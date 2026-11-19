// node --test Vault/Test/js — zero-dependency. T20: vault-webauthn.js on the real locked page, hardware-key page and
// security page (Template/vault/{locked,hwkeys,security}.php, PHP stripped), with navigator.credentials and
// KBVault.api stubbed. Checks what goes to the browser API (the challenge, each key's own PRF salt) and what is posted
// (base64url, one assertion per key), and that a key without PRF is refused before anything is posted.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { Doc, parseInto, template, flush } from './fake-dom.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const MESSAGES = {
  failed: 'Something went wrong.',
  hw_touch: 'Touch your key.',
  hw_touch_other: 'Now touch:',
  hw_prf_unsupported: 'No PRF.',
  hw_cancelled: 'Cancelled.',
  hw_unsupported: 'Unsupported.',
  unlock_failed: 'Unlock failed.',
  keys_rotated: 'Rotated.',
  confirm_hw_remove: 'Remove?',
  confirm_new_code: 'Replace?',
};
const plain = (o) => JSON.parse(JSON.stringify(o));
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');
const bytes = (u8) => Array.from(new Uint8Array(u8.buffer ?? u8, u8.byteOffset ?? 0, u8.byteLength));

// A credential as navigator.credentials returns it. prf: the PRF output bytes (null: none reported).
function credential(id, { prf = [9, 9, 9], enabled = true, kind = 'get' } = {}) {
  const buf = (a) => new Uint8Array(a).buffer;
  return {
    rawId: buf(id),
    response: kind === 'create'
      ? { clientDataJSON: buf([1]), attestationObject: buf([2]) }
      : { clientDataJSON: buf([3]), authenticatorData: buf([4]), signature: buf([5]) },
    getClientExtensionResults: () => (kind === 'create'
      ? (enabled ? { prf: { enabled: true } } : {})
      : (prf ? { prf: { results: { first: buf(prf) } } } : {})),
  };
}

function load(page, { api, create, get, confirm = () => true, extra = '' } = {}) {
  const doc = new Doc();
  const calls = [];
  const browser = [];
  parseInto(doc, doc.body, `<div id="vault-app" data-messages='${JSON.stringify(MESSAGES)}'></div>${template(page)}${extra}`);
  const window = {
    document: doc,
    btoa,
    atob,
    confirm,
    PublicKeyCredential: function () {},
    navigator: {
      credentials: {
        create: (o) => { browser.push(['create', o]); return Promise.resolve(create(o)); },
        get: (o) => { browser.push(['get', o]); return Promise.resolve(get(o)); },
      },
    },
    location: { reload: () => calls.push({ action: 'reload' }) },
    KBVault: { api: (action, body) => { calls.push({ action, body: JSON.parse(JSON.stringify(body)) }); return Promise.resolve(api(action, body)); } },
  };
  const ctx = vm.createContext({ window, Uint8Array, Promise, Math });
  const files = page === 'security' ? ['vault-webauthn.js', 'vault-security.js'] : ['vault-webauthn.js'];
  for (const f of files) vm.runInContext(readFileSync(path(`Assets/js/${f}`), 'utf8'), ctx, { filename: f });
  return { doc, calls, browser, window };
}

const K1 = { id: b64u([1, 2, 3]), label: 'Desk', prf_salt: b64u([4, 5, 6]) };
const K2 = { id: b64u([7, 7, 7]), label: 'Spare', prf_salt: b64u([8, 8, 8]) };
const challengeFor = (credentials, more = {}) => ({ ok: true, challenge: b64u([0xaa, 0xbb]), rp_id: 'kb.example', credentials, ...more });

// Spec: "The client must report prf.enabled": the key is refused here and nothing is registered.
// Kills: a create without extensions.prf; a missing prf.enabled accepted; a register POST sent anyway.
test('a key that does not report prf.enabled is refused before anything is posted', async () => {
  const { doc, calls, browser } = load('hwkeys', {
    api: (action) => (action === 'hw_challenge' ? challengeFor([], { rp_name: 'Vault', user_handle: b64u([1]), user_name: 'alice', prf_salt: b64u([6]) }) : { ok: true }),
    create: () => credential([5, 5], { kind: 'create', enabled: false }),
    get: () => credential([5, 5]),
  });
  doc.querySelector('[data-vault-hw-field="label"]').value = 'Desk';
  doc.querySelector('[data-vault-form="hwregister"]').querySelector('[data-vault-hw-field="passphrase"]').value = 'secret passphrase';
  doc.querySelector('[data-vault-action="hw-register"]').click();
  await flush(20);
  assert.deepEqual(calls.map((c) => c.action), ['hw_challenge']);
  assert.deepEqual(plain(browser[0][1].publicKey.extensions), { prf: {} });
  assert.equal(doc.querySelector('[data-vault-hw-status="register"]').textContent, 'No PRF.');
  assert.equal(doc.querySelector('[data-vault-form="hwregister"]').querySelector('[data-vault-hw-field="passphrase"]').value, '', 'the passphrase is cleared');
});

// Spec: unlock needs a fresh assertion for the server's single-use challenge, with the key's own PRF salt; the PRF
// output goes with the passphrase. Kills: eval with one salt for every key; a reused challenge; a PRF-less answer
// posted; the passphrase left in the field.
test('unlock asks for a fresh unlock challenge and evaluates each key with its own salt', async () => {
  const { doc, calls, browser } = load('locked', {
    api: (action) => (action === 'hw_challenge' ? challengeFor([K1, K2]) : { ok: true }),
    get: () => credential([1, 2, 3], { prf: [42, 43] }),
  });
  doc.querySelector('[data-vault-form="unlock"]').querySelector('input[name="passphrase"]').value = 'my vault passphrase';
  doc.querySelector('[data-vault-action="hw-unlock"]').click();
  await flush(20);
  assert.deepEqual(calls[0], { action: 'hw_challenge', body: { purpose: 'unlock' } });
  const pk = browser[0][1].publicKey;
  assert.deepEqual(bytes(pk.challenge), [0xaa, 0xbb]);
  assert.equal(pk.rpId, 'kb.example');
  assert.equal(pk.userVerification, 'preferred');
  assert.deepEqual(plain(pk.allowCredentials.map((c) => bytes(c.id))), [[1, 2, 3], [7, 7, 7]]);
  assert.deepEqual(bytes(pk.extensions.prf.evalByCredential[K1.id].first), [4, 5, 6]);
  assert.deepEqual(bytes(pk.extensions.prf.evalByCredential[K2.id].first), [8, 8, 8]);
  assert.deepEqual(calls[1], {
    action: 'hw_unlock',
    body: { passphrase: 'my vault passphrase', assertion: { credential_id: K1.id, clientDataJSON: b64u([3]), authenticatorData: b64u([4]), signature: b64u([5]), prf: b64u([42, 43]) } },
  });
  assert.equal(calls[2].action, 'reload');
  assert.equal(doc.querySelector('[data-vault-form="unlock"]').querySelector('input[name="passphrase"]').value, '');

  // No PRF output: refused, nothing posted.
  const second = load('locked', { api: (action) => (action === 'hw_challenge' ? challengeFor([K1]) : { ok: true }), get: () => credential([1, 2, 3], { prf: null }) });
  second.doc.querySelector('[data-vault-action="hw-unlock"]').click();
  await flush(20);
  assert.deepEqual(second.calls.map((c) => c.action), ['hw_challenge']);
  assert.equal(second.doc.querySelector('[data-vault-form="unlock"]').querySelector('.vault-error').textContent, 'No PRF.');
});

// Spec / R30: the second key's ceremony asks the new key for its PRF output (with the salt the server gave) and the
// first key for a fresh assertion, then posts both once. Kills: the existing key not asked; the new key evaluated
// with a stored salt; create without excludeCredentials (the same key twice).
test('adding the second key asks the new key, then the first key, and posts once', async () => {
  const { doc, calls, browser } = load('hwkeys', {
    api: (action) => (action === 'hw_challenge' ? challengeFor([K1], { rp_name: 'Vault', user_handle: b64u([1, 1]), user_name: 'alice', prf_salt: b64u([6, 6]) }) : { ok: true }),
    create: () => credential([5, 5], { kind: 'create' }),
    get: (o) => credential(bytes(o.publicKey.allowCredentials[0].id), { prf: [bytes(o.publicKey.allowCredentials[0].id)[0], 0] }),
  });
  doc.querySelector('[data-vault-hw-field="label"]').value = 'Spare';
  doc.querySelector('[data-vault-form="hwregister"]').querySelector('[data-vault-hw-field="passphrase"]').value = 'secret passphrase';
  doc.querySelector('[data-vault-action="hw-register"]').click();
  await flush(30);
  assert.deepEqual(calls.map((c) => c.action), ['hw_challenge', 'hw_challenge', 'hw_challenge', 'hw_register', 'reload']);
  assert.deepEqual(calls.slice(0, 3).map((c) => c.body.purpose), ['register', 'ceremony', 'ceremony']);
  const create = browser[0][1].publicKey;
  assert.deepEqual(plain(create.excludeCredentials.map((c) => bytes(c.id))), [[1, 2, 3]]);
  assert.equal(create.attestation, 'none');
  assert.deepEqual(plain(create.pubKeyCredParams.map((p) => p.alg)), [-8, -7]);
  assert.deepEqual(bytes(browser[1][1].publicKey.extensions.prf.evalByCredential[b64u([5, 5])].first), [6, 6], 'the new key: the server salt');
  assert.deepEqual(bytes(browser[2][1].publicKey.extensions.prf.evalByCredential[K1.id].first), [4, 5, 6], 'the first key: its own salt');
  const body = calls[3].body;
  assert.equal(body.label, 'Spare');
  assert.equal(body.passphrase, 'secret passphrase');
  assert.deepEqual(body.create, { clientDataJSON: b64u([1]), attestationObject: b64u([2]), clientExtensionResults: { prf: { enabled: true } } });
  assert.equal(body.assert.credential_id, b64u([5, 5]));
  assert.deepEqual(body.others.map((a) => a.credential_id), [K1.id]);
});

// Rotate with my keys: every key presents an assertion in turn; removal uses another key. Kills: one key only; the
// removed key asserting for itself.
test('rotate asks every key in turn; remove asks another key', async () => {
  const { doc, calls, browser } = load('hwkeys', {
    api: (action) => (action === 'hw_challenge' ? challengeFor([K1, K2]) : { ok: true, rotation: 'done' }),
    get: (o) => credential(bytes(o.publicKey.allowCredentials[0].id)),
  });
  doc.querySelector('[data-vault-form="hwrotate"]').querySelector('[data-vault-hw-field="passphrase"]').value = 'current passphrase';
  doc.querySelector('[data-vault-action="hw-rotate"]').click();
  await flush(40);
  const rotate = calls.find((c) => c.action === 'hw_rotate');
  assert.deepEqual(rotate.body.assertions.map((a) => a.credential_id), [K1.id, K2.id]);
  assert.deepEqual(plain(browser.map((b) => b[1].publicKey.allowCredentials.length)), [1, 1]);
  assert.equal(doc.querySelector('[data-vault-hw-status="rotate"]').textContent, 'Rotated.');

  // The template's key row carries its PHP placeholder id; a row with a real id is added for this check.
  const fresh = load('hwkeys', {
    api: (action) => (action === 'hw_challenge' ? challengeFor([K1, K2]) : { ok: true }),
    get: (o) => credential(bytes(o.publicKey.allowCredentials[0].id)),
    extra: `<button type="button" data-vault-hw-remove="${K1.id}">x</button>`,
  });
  fresh.doc.querySelectorAll('[data-vault-hw-remove]').pop().click();
  await flush(30);
  assert.deepEqual(plain(fresh.browser[0][1].publicKey.allowCredentials.map((c) => bytes(c.id))), [[7, 7, 7]], 'only the other key');
  assert.equal(fresh.calls.find((c) => c.action === 'hw_remove').body.credential_id, K1.id);
});

// R54: on the security page of a user with keys, a recovery code request carries a fresh assertion. Kills: the
// assertion not attached; the request sent when the key ceremony fails.
test('the recovery code request carries a fresh assertion for a key user', async () => {
  const run = async (get) => {
    const page = load('security', {
      api: (action) => (action === 'hw_challenge' ? challengeFor([K1]) : { ok: false, reason: 'failed' }),
      get,
    });
    const form = page.doc.querySelector('[data-vault-form="recovery"]');
    form.setAttribute('data-vault-hw', '1');
    form.querySelector('input[name="passphrase"]').value = 'my vault passphrase';
    form.dispatch('submit');
    await flush(20);
    return page;
  };
  const ok = await run(() => credential([1, 2, 3]));
  const sent = ok.calls.find((c) => c.action === 'recovery_code');
  assert.equal(sent.body.passphrase, 'my vault passphrase');
  assert.equal(sent.body.assertion.credential_id, K1.id);
  const cancelled = await run(() => Promise.reject(new Error('NotAllowedError')));
  assert.equal(cancelled.calls.find((c) => c.action === 'recovery_code'), undefined);
});
