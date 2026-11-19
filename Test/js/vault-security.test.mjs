// node --test Vault/Test/js — zero-dependency. R40: the "My vault security" page (Template/vault/security.php) with
// vault-generator.js and vault-security.js in one vm context, KBVault.api stubbed. Also the enrolment form's
// generator (T13 carry). Messages come from #vault-app as on the real page.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { Doc, parseInto, template, flush, WORDLIST_URL } from './fake-dom.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const LIST = readFileSync(path('Assets/vendor/eff_large_wordlist.txt'), 'utf8');
const WORDS = new Set(LIST.split('\n').filter((l) => l !== '').map((l) => l.split('\t')[1]));
const MESSAGES = {
  failed: 'Something went wrong.',
  working: 'Working…',
  unlock_failed: 'Unlock failed.',
  passphrase_mismatch: 'Mismatch.',
  policy_forbids: 'Policy forbids.',
  passphrase_changed: 'Your passphrase is changed.',
  keys_rotated: 'Your keys are rotated.',
  rotation_pending: 'Done. Finishes at your next unlock.',
  confirm_new_code: 'Replace?',
  code_group_mismatch: 'Not group 3.',
  code_saved: 'Recovery code saved.',
};
const CODE = 'ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789-AB';

function loadSecurity({ api, confirm = () => true, page = 'security' } = {}) {
  const doc = new Doc();
  const calls = [];
  parseInto(doc, doc.body, `<div id="vault-app" data-vault-state="unlocked" data-messages='${JSON.stringify(MESSAGES)}'></div>${template(page)}`);
  const panel = doc.querySelector('[data-vault-generator]');
  if (panel) panel.setAttribute('data-wordlist', WORDLIST_URL);
  const window = {
    document: doc,
    crypto: webcrypto,
    confirm,
    setTimeout: () => 0,
    clearTimeout: () => {},
    location: { reload: () => { calls.push({ action: 'reload' }); } },
    fetch: () => Promise.resolve({ ok: true, text: () => Promise.resolve(LIST) }),
    KBVault: {
      api: (action, body) => {
        calls.push({ action, body: { ...body } });
        return Promise.resolve(api ? api(action, body) : { ok: true });
      },
    },
  };
  const ctx = vm.createContext({ window, Math });
  const files = page === 'security' ? ['vault-generator.js', 'vault-security.js'] : ['vault-generator.js'];
  for (const f of files) vm.runInContext(readFileSync(path(`Assets/js/${f}`), 'utf8'), ctx, { filename: f });
  return { doc, calls };
}

function fill(form, values) {
  for (const [name, v] of Object.entries(values)) form.querySelector(`input[name="${name}"]`).value = v;
}

const submit = (form) => form.dispatch('submit');

test('passphrase change: ROTATED and PENDING are successes, a pre-commit error is a failure', async () => {
  let answer = { ok: true, rotation: 'done', offer_recovery_code: false };
  let hold = null;
  const { doc, calls } = loadSecurity({ api: () => (hold ? hold : answer) });
  const form = doc.querySelector('[data-vault-form="passphrase"]');
  const status = form.querySelector('[data-vault-status]');
  const button = form.querySelector('button[type="submit"]');
  const offer = doc.querySelector('[data-vault-recovery-offer]');

  fill(form, { current: 'old one', passphrase: 'new one', confirm: 'new one' });
  let resolve;
  hold = new Promise((r) => { resolve = r; });
  const ev = submit(form);
  assert.equal(ev.defaultPrevented, true, 'no native submit');
  assert.equal(button.disabled, true, 'no double submit while in flight');
  submit(form);
  assert.equal(calls.filter((c) => c.action === 'passphrase').length, 1, 'one request only');
  hold = null;
  resolve(answer);
  await flush();
  assert.deepEqual(calls[0].body.current, 'old one');
  assert.deepEqual([calls[0].body.passphrase, calls[0].body.confirm], ['new one', 'new one']);
  assert.equal(status.hidden, false);
  assert.equal(status.textContent, MESSAGES.passphrase_changed);
  assert.ok(status.classList.contains('vault-ok') && !status.classList.contains('vault-bad'));
  for (const n of ['current', 'passphrase', 'confirm']) assert.equal(form.querySelector(`input[name="${n}"]`).value, '', `${n} cleared`);
  assert.equal(button.disabled, false);
  assert.equal(offer.hidden, true, 'no offer without a recovery policy');

  answer = { ok: true, rotation: 'pending', message: 'Your passphrase is changed. Re-encrypting your vault finishes at your next unlock.', offer_recovery_code: true };
  fill(form, { current: 'a', passphrase: 'b', confirm: 'b' });
  submit(form);
  await flush();
  assert.equal(status.textContent, answer.message, 'PENDING is a success with its message');
  assert.ok(status.classList.contains('vault-ok'));
  assert.equal(offer.hidden, false, 'R36: a new recovery code is offered');

  answer = { ok: false, reason: 'unlock_failed' };
  fill(form, { current: 'wrong', passphrase: 'b', confirm: 'b' });
  submit(form);
  await flush();
  assert.equal(status.textContent, MESSAGES.unlock_failed);
  assert.ok(status.classList.contains('vault-bad') && !status.classList.contains('vault-ok'));
  for (const n of ['current', 'passphrase', 'confirm']) assert.equal(form.querySelector(`input[name="${n}"]`).value, '', `${n} cleared on failure`);

  answer = { ok: false, reason: 'no-such-code' };
  submit(form);
  await flush();
  assert.equal(status.textContent, MESSAGES.failed, 'an unknown reason is the generic failure');
});

test('rotate my keys maps results the same way', async () => {
  let answer = { ok: true, rotation: 'done', offer_recovery_code: false };
  const { doc, calls } = loadSecurity({ api: () => answer });
  const form = doc.querySelector('[data-vault-form="rotate"]');
  const status = form.querySelector('[data-vault-status]');
  fill(form, { passphrase: 'mine' });
  submit(form);
  await flush();
  assert.equal(calls[0].action, 'rotate');
  assert.equal(calls[0].body.passphrase, 'mine');
  assert.equal(status.textContent, MESSAGES.keys_rotated);
  assert.equal(form.querySelector('input[name="passphrase"]').value, '');

  answer = { ok: true, rotation: 'pending', message: 'Your keys are rotated. Finishes at your next unlock.' };
  submit(form);
  await flush();
  assert.equal(status.textContent, answer.message);
  assert.ok(status.classList.contains('vault-ok'));

  answer = { ok: true, rotation: 'pending' };
  submit(form);
  await flush();
  assert.equal(status.textContent, MESSAGES.rotation_pending, 'PENDING without a message: the page default');

  answer = { ok: false, reason: 'rate_limited' };
  submit(form);
  await flush();
  assert.equal(status.textContent, MESSAGES.failed);
  assert.ok(status.classList.contains('vault-bad'));
});

test('a recovery code is shown once and cleared only after group 3 is typed back', async () => {
  let answer = { ok: true, code: CODE };
  let asked = 0;
  const { doc, calls } = loadSecurity({ api: () => answer, confirm: () => { asked++; return asked > 1; } });
  const create = doc.querySelector('[data-vault-action="recovery-create"]');
  const show = doc.querySelector('[data-vault-recovery-show]');
  const code = doc.querySelector('[data-vault-recovery-code]');
  const input = doc.querySelector('[data-vault-recovery-confirm]');
  const done = doc.querySelector('[data-vault-action="recovery-confirm"]');
  const status = doc.querySelector('[data-vault-recovery-status]');

  const form = doc.querySelector('[data-vault-form="recovery"]');
  const pass = form.querySelector('input[name="passphrase"]');
  pass.value = 'my current passphrase';
  assert.equal(submit(form).defaultPrevented, true, 'no native submit');
  await flush();
  assert.equal(calls.length, 0, 'declining the replace warning asks for nothing');
  submit(form);
  await flush();
  assert.deepEqual(calls.map((c) => c.action), ['recovery_code']);
  assert.deepEqual(calls[0].body, { passphrase: 'my current passphrase' }, 'R54: the passphrase goes with it');
  assert.equal(pass.value, '', 'and is cleared');
  assert.equal(code.textContent, CODE, 'the code, as text');
  assert.equal(show.hidden, false);
  assert.equal(create.disabled, true, 'one code at a time');

  input.value = 'EFGH';
  done.click();
  assert.equal(status.textContent, MESSAGES.code_group_mismatch, 'group 2 is not group 3');
  assert.equal(code.textContent, CODE, 'still shown');
  assert.equal(show.hidden, false);

  input.value = ' jkmn ';
  done.click();
  assert.equal(code.textContent, '', 'cleared from the page');
  assert.equal(show.hidden, true);
  assert.equal(input.value, '');
  assert.equal(status.textContent, MESSAGES.code_saved);
  assert.equal(create.disabled, false);

  answer = { ok: false, reason: 'policy_forbids' };
  submit(form);
  await flush();
  assert.equal(status.textContent, MESSAGES.policy_forbids);
  assert.equal(show.hidden, true);
  assert.equal(code.textContent, '');
});

test('the new-passphrase generator fills both fields and shows the value (security and enrolment)', async () => {
  for (const page of ['security', 'enrol']) {
    const { doc } = loadSecurity({ page });
    const button = doc.querySelector('[data-vault-action="generate"][aria-controls="vault-pgen"]');
    assert.ok(button, `${page}: a generate button for the panel`);
    assert.equal(button.getAttribute('type'), 'button', 'never submits');
    button.click();
    await flush();
    const value = doc.getElementById('vault-new-passphrase').value;
    const words = value.split('-');
    assert.equal(words.length, 6, `${page}: six words by default`);
    for (const w of words) assert.ok(WORDS.has(w), w);
    assert.equal(doc.getElementById('vault-new-confirm').value, value, `${page}: the confirmation too`);
    assert.equal(doc.querySelector('[data-vault-gen-show]').textContent, value, `${page}: shown to write down`);
    assert.match(doc.querySelector('[data-vault-gen-entropy]').textContent, /77 bits/);
    const current = doc.getElementById('vault-current');
    if (current) assert.equal(current.value, '', 'the current passphrase is left alone');
  }
});
