// node --test Vault/Test/js — zero-dependency. The owner's agents page (Template/vault/agents.php) with vault-agents.js
// in a vm context, KBVault.api stubbed. The markup below carries the attributes the template renders (agents.php's
// PHP branches pick the form per agent, which the fake DOM's PHP stripping can't); AgentVaultControllerTest checks the
// rendered template has them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { Doc, parseInto, flush } from './fake-dom.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const MESSAGES = {
  failed: 'Something went wrong.',
  working: 'Working…',
  saved: 'Saved.',
  not_found: 'Not found.',
  confirm_reenrol: 'Re-enrol?',
  key_shown: 'Copy it now.',
  key_cleared: 'Cleared.',
};
const KEY = 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde';

const PAGE = `<div id="vault-app" data-vault-state="unlocked" data-messages='${JSON.stringify(MESSAGES)}'></div>
<section data-vault-agent-key-panel hidden><p><code data-vault-agent-env></code></p><button type="button" data-vault-action="agent-key-done">I saved it</button></section>
<p data-vault-agent-status role="status" hidden></p>
<table><tbody>
<tr data-vault-agent="7"><td><form method="post" action="/enrol" data-vault-form="agent-enrol"><input type="hidden" name="csrf_token" value="t"><input type="hidden" name="agent_id" value="7"><button type="submit">Enable</button></form></td>
<td><form method="post" action="/cap" data-vault-form="agent-cap"><input type="hidden" name="agent_id" value="7"><input type="number" name="cap" value="60"><button type="submit">Save</button></form></td></tr>
<tr data-vault-agent="8"><td><form method="post" action="/reenrol" data-vault-form="agent-reenrol"><input type="hidden" name="agent_id" value="8"><button type="submit">Re-enrol</button></form></td></tr>
</tbody></table>`;

function load({ api, confirm = () => true } = {}) {
  const doc = new Doc();
  const calls = [];
  parseInto(doc, doc.body, PAGE);
  const window = {
    document: doc,
    confirm,
    KBVault: {
      api: (action, body) => {
        calls.push({ action, body: { ...body } });
        return Promise.resolve(api ? api(action, body) : { ok: true });
      },
    },
  };
  vm.runInContext(readFileSync(path('Assets/js/vault-agents.js'), 'utf8'), vm.createContext({ window }), { filename: 'vault-agents.js' });
  return { doc, calls };
}

test('enable vault access shows the key once as text, one request at a time, and "I saved it" clears it', async () => {
  let hold = null;
  const { doc, calls } = load({ api: () => hold || { ok: true, vault_key: KEY, env: 'KANBOARD_VAULT_KEY=' + KEY } });
  const form = doc.querySelector('[data-vault-form="agent-enrol"]');
  const panel = doc.querySelector('[data-vault-agent-key-panel]');
  const env = doc.querySelector('[data-vault-agent-env]');
  let release;
  hold = new Promise((r) => { release = r; });
  const ev = form.dispatch('submit');
  assert.equal(ev.defaultPrevented, true, 'no native submit');
  form.dispatch('submit');
  assert.deepEqual(calls, [{ action: 'agent_enrol', body: { agent_id: '7' } }], 'one request, the agent id only');
  hold = null;
  release({ ok: true, vault_key: KEY, env: '<b>KANBOARD_VAULT_KEY=' + KEY + '</b>' });
  await flush();
  assert.equal(panel.hidden, false);
  assert.equal(env.textContent, '<b>KANBOARD_VAULT_KEY=' + KEY + '</b>', 'written as text');
  assert.equal(doc.querySelector('[data-vault-agent-status]').textContent, 'Copy it now.');
  doc.querySelector('[data-vault-action="agent-key-done"]').click();
  assert.equal(env.textContent, '');
  assert.equal(panel.hidden, true);
  form.dispatch('submit');
  assert.equal(calls.length, 2, 'free again after the answer');
});

test('re-enrol asks first; declining sends nothing', async () => {
  let answer = false;
  const { doc, calls } = load({ confirm: () => answer, api: () => ({ ok: true, env: 'KANBOARD_VAULT_KEY=' + KEY }) });
  const form = doc.querySelector('[data-vault-form="agent-reenrol"]');
  form.dispatch('submit');
  assert.deepEqual(calls, []);
  answer = true;
  form.dispatch('submit');
  await flush();
  assert.deepEqual(calls, [{ action: 'agent_reenrol', body: { agent_id: '8' } }]);
  assert.equal(doc.querySelector('[data-vault-agent-env]').textContent, 'KANBOARD_VAULT_KEY=' + KEY);
});

test('a refusal shows its fixed message and no key; the cap form saves', async () => {
  const { doc, calls } = load({ api: (action) => (action === 'agent_cap' ? { ok: true } : { ok: false, reason: 'not_found' }) });
  doc.querySelector('[data-vault-form="agent-enrol"]').dispatch('submit');
  await flush();
  assert.equal(doc.querySelector('[data-vault-agent-key-panel]').hidden, true);
  assert.equal(doc.querySelector('[data-vault-agent-status]').textContent, 'Not found.');
  const cap = doc.querySelector('[data-vault-form="agent-cap"]');
  cap.querySelector('input[name="cap"]').value = '12';
  cap.dispatch('submit');
  await flush();
  assert.deepEqual(calls[1], { action: 'agent_cap', body: { agent_id: '7', cap: '12' } });
  assert.equal(doc.querySelector('[data-vault-agent-status]').textContent, 'Saved.');
});

test('the cap form sends one request at a time', async () => {
  let release;
  const hold = new Promise((r) => { release = r; });
  const { doc, calls } = load({ api: () => hold });
  const cap = doc.querySelector('[data-vault-form="agent-cap"]');
  cap.dispatch('submit');
  cap.dispatch('submit');
  assert.equal(calls.length, 1, 'second submit ignored while the first is in flight');
  release({ ok: true });
  await flush();
  cap.dispatch('submit');
  assert.equal(calls.length, 2, 'free again after the answer');
});

test('vault-agents.js writes no HTML', () => {
  const src = readFileSync(path('Assets/js/vault-agents.js'), 'utf8');
  for (const bad of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(']) {
    assert.equal(src.includes(bad), false, bad);
  }
});
