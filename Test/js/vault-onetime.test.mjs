// node --test Vault/Test/js — the one-time share's browser crypto and the creator's dialog (spec: One-time shares →
// Creating a share). vault-onetime.js runs in a vm context with Node's WebCrypto and the real Argon2 worker
// (node-worker.mjs); the dialog runs on the real templates in the fake DOM. PHP made Test/fixtures/enc-vectors.json.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { webcrypto, createCipheriv } from 'node:crypto';
import vm from 'node:vm';
import { workerClass } from './node-worker.mjs';
import { loadPage, flush } from './fake-dom.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const SRC = readFileSync(path('Assets/js/vault-onetime.js'), 'utf8');
const VECTORS = JSON.parse(readFileSync(path('Test/fixtures/enc-vectors.json'), 'utf8'));
const SCRIPT_SRC = 'https://kb.test/plugins/Vault/Assets/js/vault-onetime.js?1700000000';
const ID = '00112233445566778899aabbccddeeff';
const EXP = 1795000000;
const hex = (u) => Buffer.from(u).toString('hex');
const unb64 = (s) => Buffer.from(s, 'base64');
const unb64url = (s) => Buffer.from(s, 'base64url');

// vault-onetime.js alone, as the share page loads it. randomLog records every getRandomValues length.
function load({ crypto = webcrypto, randomLog = null } = {}) {
  const { Worker, log } = workerClass();
  const c = randomLog === null ? crypto : {
    subtle: crypto.subtle,
    getRandomValues: (a) => { randomLog.push(a.length); return crypto.getRandomValues(a); },
  };
  const window = { crypto: c, Worker, URL, TextEncoder, TextDecoder, atob, btoa, document: { currentScript: { src: SCRIPT_SRC } } };
  vm.runInContext(SRC, vm.createContext({ window }), { filename: 'vault-onetime.js' });
  return { ot: window.KBVaultOnetime, log };
}

test('enc() matches PHP vector', () => {
  const { ot } = load();
  const args = (fields) => fields.map(([t, v]) => (t === 'i' ? v : String(v)));
  for (const v of [...VECTORS.share_ad, ...VECTORS.enc]) {
    assert.equal(hex(ot.enc(...args(v.fields))), v.hex);
  }
  for (const v of VECTORS.share_ad) {
    const [, , id, exp, has] = v.fields.map((f) => f[1]);
    assert.equal(hex(ot.shareAd(id, exp, has === 1)), v.hex);
  }
  // Only non-negative safe integers and strings: anything else would not match PHP's pack('J') or the AD.
  for (const bad of [-1, 1.5, 2 ** 53, NaN, null, undefined, {}, true]) {
    assert.throws(() => ot.enc(bad), /enc/);
  }
});

test('burn_hash is PHP\'s BLAKE2b-256 of the 16 raw bytes of b', async () => {
  const { ot } = load();
  assert.equal(await ot.burnHash(VECTORS.burn.b), VECTORS.burn.burn_hash);
});

test('the share key with a passphrase is PHP\'s HKDF-SHA256(k ‖ libsodium Argon2id)', async () => {
  // A ciphertext made outside the page with PHP's key decrypts in the page: the KDF, HKDF and AD all agree.
  const { ot } = load();
  const key = Buffer.from(VECTORS.key.key, 'hex');
  const iv = Buffer.alloc(12, 7);
  const ad = Buffer.from(VECTORS.share_ad[1].hex, 'hex');
  const [, , id, exp] = VECTORS.share_ad[1].fields.map((f) => f[1]);
  const cipher = createCipheriv('aes-256-gcm', key, iv).setAAD(ad);
  const ct = Buffer.concat([cipher.update('from PHP\'s key', 'utf8'), cipher.final(), cipher.getAuthTag()]);
  const fragment = Buffer.concat([Buffer.from(VECTORS.key.k, 'hex'), Buffer.alloc(16, 9)]).toString('base64url');
  const plain = await ot.decrypt({
    ciphertext: ct.toString('base64'), iv: iv.toString('base64'), salt: Buffer.from(VECTORS.argon2id.salt, 'hex').toString('base64'),
    has_passphrase: true, fragment, shareId: id, expiresAt: exp, passphrase: VECTORS.argon2id.password,
  });
  assert.equal(plain, 'from PHP\'s key');
});

test('round trip with and without passphrase', async () => {
  const { ot } = load();
  const text = 'pässwörd\twith tabs \u{1F511}\n';
  for (const passphrase of ['', 'correct-horse-battery-staple-ok']) {
    const s = await ot.encrypt({ plaintext: text, shareId: ID, expiresAt: EXP, passphrase });
    const has = passphrase !== '';
    assert.deepEqual(Object.keys(s).sort(), ['burn_hash', 'ciphertext', 'fragment', 'has_passphrase', 'iv', 'salt']);
    assert.equal(s.has_passphrase, has ? 1 : 0);
    assert.equal(unb64(s.iv).length, 12);
    assert.equal(s.salt === '' ? 0 : unb64(s.salt).length, has ? 16 : 0);
    assert.equal(unb64(s.ciphertext).length, Buffer.byteLength(text) + 16);
    // The fragment is base64url(k ‖ b): 48 bytes, no padding; burn_hash is BLAKE2b-256 of b.
    assert.match(s.fragment, /^[A-Za-z0-9_-]{64}$/);
    const kb = unb64url(s.fragment);
    assert.equal(kb.length, 48);
    assert.equal(s.burn_hash, await ot.burnHash(hex(kb.subarray(32))));
    // Without a passphrase the key is k itself.
    if (!has) {
      const key = await webcrypto.subtle.importKey('raw', kb.subarray(0, 32), 'AES-GCM', false, ['decrypt']);
      const plain = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(s.iv), additionalData: ot.shareAd(ID, EXP, false) }, key, unb64(s.ciphertext));
      assert.equal(Buffer.from(plain).toString('utf8'), text);
    }
    const out = await ot.decrypt({ ...s, has_passphrase: has, shareId: ID, expiresAt: EXP, passphrase });
    assert.equal(out, text);
  }
});

test('wrong passphrase rejects and ciphertext stays usable for retry', async () => {
  const { ot } = load();
  const s = await ot.encrypt({ plaintext: 'retry me', shareId: ID, expiresAt: EXP, passphrase: 'right one' });
  const answer = { ciphertext: s.ciphertext, iv: s.iv, salt: s.salt, has_passphrase: true, expires_at: EXP };
  const frozen = JSON.stringify(answer);
  const args = (passphrase) => ({ ...answer, fragment: s.fragment, shareId: ID, expiresAt: EXP, passphrase });
  await assert.rejects(ot.decrypt(args('wrong one')), (e) => e.code === 'decrypt_failed');
  await assert.rejects(ot.decrypt(args('')), (e) => e.code === 'passphrase_required');
  await assert.rejects(ot.decrypt(args(undefined)), (e) => e.code === 'passphrase_required');
  assert.equal(JSON.stringify(answer), frozen, 'a failed attempt leaves the answer untouched');
  assert.equal(await ot.decrypt(args('right one')), 'retry me');
  // NFC: the same passphrase typed as a decomposed é opens it too.
  const s2 = await ot.encrypt({ plaintext: 'x', shareId: ID, expiresAt: EXP, passphrase: 'café' });
  assert.equal(await ot.decrypt({ ...s2, has_passphrase: true, shareId: ID, expiresAt: EXP, passphrase: 'café' }), 'x');
});

test('changing any AD field fails decryption', async () => {
  const { ot } = load();
  const plain = await ot.encrypt({ plaintext: 'bound', shareId: ID, expiresAt: EXP, passphrase: '' });
  const withPass = await ot.encrypt({ plaintext: 'bound', shareId: ID, expiresAt: EXP, passphrase: 'pp' });
  const ok = (s, has, more = {}) => ({ ...s, has_passphrase: has, shareId: ID, expiresAt: EXP, passphrase: has ? 'pp' : '', ...more });
  assert.equal(await ot.decrypt(ok(plain, false)), 'bound');
  assert.equal(await ot.decrypt(ok(withPass, true)), 'bound');
  const cases = [
    ok(plain, false, { shareId: 'ffeeddccbbaa99887766554433221100' }),
    ok(plain, false, { shareId: ID.slice(0, 31) + 'e' }),
    ok(plain, false, { expiresAt: EXP + 1 }),
    ok(plain, false, { expiresAt: EXP - 3600 }),
    // has_passphrase is in the AD: claiming none for a passphrase share, or one for a plain share, fails.
    ok(withPass, false),
    ok({ ...plain, salt: withPass.salt }, true),
  ];
  for (const c of cases) {
    await assert.rejects(ot.decrypt(c), (e) => e.code === 'decrypt_failed', JSON.stringify({ id: c.shareId, exp: c.expiresAt, has: c.has_passphrase }));
  }
  // A tampered ciphertext or IV fails the same way; an id that isn't the link's lowercase hex is refused outright.
  const flip = (b64) => { const u = unb64(b64); u[0] ^= 1; return u.toString('base64'); };
  await assert.rejects(ot.decrypt(ok({ ...plain, ciphertext: flip(plain.ciphertext) }, false)), (e) => e.code === 'decrypt_failed');
  await assert.rejects(ot.decrypt(ok({ ...plain, iv: flip(plain.iv) }, false)), (e) => e.code === 'decrypt_failed');
  await assert.rejects(ot.decrypt(ok(plain, false, { shareId: ID.toUpperCase() })), (e) => e.code === 'bad_input');
});

test('randomness comes only from crypto.getRandomValues, fresh for every share', async () => {
  const randomLog = [];
  const { ot } = load({ randomLog });
  const a = await ot.encrypt({ plaintext: 'same', shareId: ID, expiresAt: EXP, passphrase: 'p' });
  const b = await ot.encrypt({ plaintext: 'same', shareId: ID, expiresAt: EXP, passphrase: '' });
  // k (32), b (16), iv (12) and, with a passphrase, the salt (16).
  assert.deepEqual(randomLog.slice().sort((x, y) => x - y), [12, 12, 16, 16, 16, 32, 32]);
  assert.notEqual(a.fragment, b.fragment);
  assert.notEqual(a.iv, b.iv);
  assert.doesNotMatch(SRC.replace(/^\s*(\/\/|\*|\/\*).*$/gm, ''), /Math\.random/);
});

test('encrypt refuses a payload over 64 KiB and a malformed id or expiry', async () => {
  const { ot } = load();
  const ok = await ot.encrypt({ plaintext: 'a'.repeat(65536), shareId: ID, expiresAt: EXP });
  assert.equal(unb64(ok.ciphertext).length, 65536 + 16);
  await assert.rejects(ot.encrypt({ plaintext: 'a'.repeat(65535) + 'é', shareId: ID, expiresAt: EXP }), (e) => e.code === 'payload_too_large');
  await assert.rejects(ot.encrypt({ plaintext: 'x', shareId: 'zz', expiresAt: EXP }), (e) => e.code === 'bad_input');
  await assert.rejects(ot.encrypt({ plaintext: 'x', shareId: ID, expiresAt: '1795000000' }), (e) => e.code === 'bad_input');
  await assert.rejects(ot.decrypt({ ...ok, fragment: ok.fragment.slice(1), has_passphrase: false, shareId: ID, expiresAt: EXP }), (e) => e.code === 'bad_link');
});

test('the worker is a module worker next to the script, one per job, terminated after', async () => {
  const { ot, log } = load();
  await ot.encrypt({ plaintext: 'x', shareId: ID, expiresAt: EXP, passphrase: 'p' });
  assert.deepEqual(log.started.map((s) => s.type), ['module', 'module']);
  assert.ok(log.started.every((s) => s.url === 'https://kb.test/plugins/Vault/Assets/js/argon2-worker.js'));
  assert.deepEqual(log.messages, ['argon2id', 'blake2b']);
  assert.equal(log.terminated, 2);
});

test('vault-onetime.js writes no HTML and runs no inline code', () => {
  assert.doesNotMatch(SRC, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|localStorage|sessionStorage|console\./);
});

// ---- The creator's dialog -------------------------------------------------------------------------------------

const RESERVED = { ok: true, share_id: ID, expires_at: EXP };

function creator(answers = {}) {
  const { Worker } = workerClass();
  const p = loadPage({
    crypto: webcrypto,
    onetime: { Worker, scriptSrc: SCRIPT_SRC },
    api: (action, body) => {
      if (action === 'tree') return { ok: true, groups: [{ id: 1, parent_id: null, permission: 'read', shared_by: null, name: 'G' }], shared_entries: false };
      if (action === 'list') return { ok: true, entries: [{ id: 42, title: 'DB', username: 'app', url: '', updated_at: 0 }], next_offset: null };
      const a = answers[action];
      return typeof a === 'function' ? a(body) : a || { ok: true };
    },
  });
  return p;
}

const q = (doc, sel) => doc.querySelector(sel);
async function until(fn, ms = 20000) {
  const end = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
}

test('the creator dialog reserves, encrypts in the page and sends only ciphertext and burn_hash', async () => {
  const p = creator({ share_reserve: RESERVED, share_mine: { ok: true, links: [] } });
  const { doc, calls } = p;
  await flush();
  q(doc, '[data-vault-action="onetime-new"]').click();
  await flush();
  const dialog = q(doc, '[data-vault-onetime]');
  assert.equal(dialog.hidden, false);
  q(dialog, '[data-vault-ot-text]').value = 'top secret';
  q(dialog, '[data-vault-ot-label]').value = 'for Ana';
  q(dialog, '[data-vault-ot-expiry]').value = '7d';
  q(dialog, '[data-vault-action="onetime-create"]').click();
  await until(() => !q(dialog, '[data-vault-ot-result]').hidden);
  const reserve = calls.find((c) => c.action === 'share_reserve');
  assert.deepEqual(reserve.body, { expiry: '7d' });
  const create = calls.find((c) => c.action === 'share_create').body;
  assert.deepEqual(Object.keys(create).sort(), ['burn_hash', 'ciphertext', 'has_passphrase', 'iv', 'label', 'salt', 'share_id']);
  assert.equal(create.share_id, ID);
  assert.equal(create.label, 'for Ana');
  assert.equal(String(create.has_passphrase), '0');
  // The link: the share page with the id in the query and k ‖ b only in the fragment.
  const link = new URL(q(dialog, '[data-vault-ot-link]').value);
  assert.equal(link.origin, 'https://kb.test');
  assert.equal(link.searchParams.get('controller'), 'VaultShareController');
  assert.equal(link.searchParams.get('id'), ID);
  const fragment = link.hash.slice(1);
  assert.match(fragment, /^[A-Za-z0-9_-]{64}$/);
  // Nothing the server receives holds the plaintext, k, b or the fragment.
  const kb = unb64url(fragment);
  const sent = JSON.stringify(calls.map((c) => c.body));
  for (const secret of ['top secret', fragment, hex(kb.subarray(0, 32)), hex(kb.subarray(32)), kb.subarray(32).toString('base64')]) {
    assert.ok(!sent.includes(secret), 'not sent: ' + secret);
  }
  assert.equal(create.burn_hash, await p.window.KBVaultOnetime.burnHash(hex(kb.subarray(32))));
  // The link opens what was typed.
  const out = await p.window.KBVaultOnetime.decrypt({ ...create, has_passphrase: false, fragment, shareId: ID, expiresAt: EXP });
  assert.equal(out, 'top secret');
  assert.equal(q(dialog, '[data-vault-ot-text]').value, '', 'the pasted text is cleared');
});

test('a passphrase share offers a generated 5-word passphrase and warns about weak ones', async () => {
  const words = readFileSync(path('Assets/vendor/eff_large_wordlist.txt'), 'utf8');
  const { Worker } = workerClass();
  const p = loadPage({
    crypto: webcrypto,
    wordlist: words,
    onetime: { Worker, scriptSrc: SCRIPT_SRC },
    api: (action) => (action === 'share_reserve' ? RESERVED : action === 'tree' ? { ok: true, groups: [] } : { ok: true, links: [], entries: [] }),
  });
  const { doc, calls } = p;
  await flush();
  q(doc, '[data-vault-action="onetime-new"]').click();
  const dialog = q(doc, '[data-vault-onetime]');
  const use = q(dialog, '[data-vault-ot-use-pass]');
  use.checked = true;
  use.dispatch('change');
  await until(() => q(dialog, '[data-vault-ot-pass]').value !== '');
  assert.equal(q(dialog, '[data-vault-ot-pass-row]').hidden, false);
  assert.match(q(dialog, '[data-vault-ot-pass-row]').textContent, /weak passphrase can be guessed offline/);
  const pass = q(dialog, '[data-vault-ot-pass]').value;
  assert.equal(pass.split('-').length, 5);
  q(dialog, '[data-vault-ot-text]').value = 'with pass';
  q(dialog, '[data-vault-action="onetime-create"]').click();
  await until(() => !q(dialog, '[data-vault-ot-result]').hidden);
  const create = calls.find((c) => c.action === 'share_create').body;
  assert.equal(String(create.has_passphrase), '1');
  assert.ok(!JSON.stringify(calls).includes(pass), 'the passphrase is never sent');
  const fragment = new URL(q(dialog, '[data-vault-ot-link]').value).hash.slice(1);
  const out = await p.window.KBVaultOnetime.decrypt({ ...create, has_passphrase: true, fragment, shareId: ID, expiresAt: EXP, passphrase: pass });
  assert.equal(out, 'with pass');
});

test('an entry field is shared without ever being shown, and read through vault/field', async () => {
  const entry = { id: 42, title: 'DB', username: 'app', url: '', tags: [], expires_at: null, updated_at: 0, version: 1, group_id: 1,
    permission: 'read', secrets: { password: true, notes: false, otp: false }, fields: [] };
  const p = creator({
    share_reserve: RESERVED,
    share_mine: { ok: true, links: [] },
    entry: { ok: true, entry },
    field: (body) => ({ ok: true, value: body.field === 'password' ? 'hunter2!' : '' }),
  });
  const { doc, calls } = p;
  await flush();
  // Pick the entry the way a user does: its group, then its row (vault-browser.js shows it).
  q(doc, '[data-group-id="1"]').click();
  await flush();
  doc.querySelectorAll('.vault-row')[0].click();
  await flush();
  assert.equal(q(doc, '[data-vault-detail]').getAttribute('data-vault-entry-id'), '42');
  q(doc, '[data-vault-onetime-field="password"]').click();
  await flush();
  const dialog = q(doc, '[data-vault-onetime]');
  assert.equal(q(dialog, '[data-vault-ot-text]').hidden, true, 'the field value is not put on screen');
  assert.ok(q(dialog, '[data-vault-ot-source]').textContent.includes('DB'));
  assert.equal(calls.filter((c) => c.action === 'field').length, 0, 'nothing is read before Create');
  q(dialog, '[data-vault-action="onetime-create"]').click();
  await until(() => !q(dialog, '[data-vault-ot-result]').hidden);
  assert.deepEqual(calls.find((c) => c.action === 'field').body, { id: 42, field: 'password' });
  assert.equal(q(dialog, '[data-vault-ot-text]').value, '');
  const create = calls.find((c) => c.action === 'share_create').body;
  const fragment = new URL(q(dialog, '[data-vault-ot-link]').value).hash.slice(1);
  assert.equal(await p.window.KBVaultOnetime.decrypt({ ...create, has_passphrase: false, fragment, shareId: ID, expiresAt: EXP }), 'hunter2!');
});

test('my links list labels as text and revokes by id_hash', async () => {
  const XSS = '<img src=x onerror=alert(1)>';
  const links = [
    { id_hash: 'a'.repeat(64), label: XSS, has_passphrase: true, created_at: 1, expires_at: EXP },
    { id_hash: 'b'.repeat(64), label: null, has_passphrase: false, created_at: 1, expires_at: EXP },
  ];
  const p = creator({ share_mine: { ok: true, links }, share_revoke: { ok: true } });
  const { doc, calls } = p;
  await flush();
  q(doc, '[data-vault-action="onetime-new"]').click();
  await flush();
  const list = q(doc, '[data-vault-ot-list]');
  assert.equal(list.querySelectorAll('li').length, 2);
  assert.ok(list.textContent.includes(XSS), 'the label is text');
  list.querySelectorAll('[data-vault-ot-revoke]')[1].click();
  await flush();
  assert.deepEqual(calls.filter((c) => c.action === 'share_revoke').map((c) => c.body), [{ id_hash: 'b'.repeat(64) }]);
});
