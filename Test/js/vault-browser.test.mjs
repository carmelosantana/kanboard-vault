// node --test Vault/Test/js — zero-dependency. Loads Assets/js/vault-browser.js into a vm context with a tiny fake DOM
// (elements record every attribute and text write; setting innerHTML or outerHTML throws), a fake clipboard and
// fake timers, as the browser would run it after vault.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { loadPage, flush } from './fake-dom.mjs';

const SRC = readFileSync(fileURLToPath(new URL('../../Assets/js/vault-browser.js', import.meta.url)), 'utf8');

// A minimal element: attributes, textContent, children, and [data-x] / [data-x="v"] selectors.
class El {
  constructor(tag, attrs = {}, children = []) {
    this.tagName = tag.toUpperCase();
    this.attrs = { ...attrs };
    this.children = children;
    this._text = '';
    this.textWrites = 0;
  }
  get textContent() { return this._text || this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this._text = String(v); this.children = []; this.textWrites++; }
  set innerHTML(v) { throw new Error('innerHTML write: ' + v); }
  get innerHTML() { throw new Error('innerHTML read'); }
  set outerHTML(v) { throw new Error('outerHTML write: ' + v); }
  insertAdjacentHTML(_, v) { throw new Error('insertAdjacentHTML: ' + v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  removeAttribute(k) { delete this.attrs[k]; }
  hasAttribute(k) { return k in this.attrs; }
  appendChild(c) { this.children.push(c); return c; }
  all() { return this.children.flatMap((c) => [c, ...c.all()]); }
  querySelectorAll(sel) {
    const m = /^\[([a-z-]+)(?:="([^"]*)")?\]$/.exec(sel);
    if (!m) throw new Error('unsupported selector ' + sel);
    return this.all().filter((e) => e.hasAttribute(m[1]) && (m[2] === undefined || e.getAttribute(m[1]) === m[2]));
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

function load({ focus = true, api } = {}) {
  const timers = [];
  const writes = [];
  const calls = [];
  const document = {
    readyState: 'complete',
    hasFocus: () => focus,
    getElementById: () => null,
    querySelector: () => null,
    addEventListener: () => {},
    createElement: (tag) => new El(tag),
  };
  const window = {
    document,
    URL,
    navigator: { clipboard: { writeText: (t) => { writes.push(t); return Promise.resolve(); } } },
    setTimeout: (fn, ms) => { timers.push({ fn, ms }); return timers.length; },
    clearTimeout: () => {},
    KBVault: {
      api: (action, body) => { calls.push({ action, body: { ...body } }); return Promise.resolve(api ? api(action, body) : { ok: true }); },
    },
  };
  vm.runInNewContext(SRC, { window, Promise, Object, Array, JSON, String, Number, Date, URL });
  return { KBVault: window.KBVault, timers, writes, calls, setFocus: (f) => { focus = f; } };
}

test('renders <img onerror> title as text', () => {
  const { KBVault } = load();
  const title = new El('h3', { 'data-field': 'title' });
  const user = new El('span', { 'data-field': 'username' });
  const node = new El('div', {}, [title, new El('p', {}, [user])]);
  const evil = '<img src=x onerror="alert(1)">';
  KBVault.render(node, { title: evil, username: '<b>bob</b>' });
  assert.equal(title.textContent, evil, 'the markup is the text');
  assert.equal(title.children.length, 0, 'no element was created');
  assert.equal(user.textContent, '<b>bob</b>');
  assert.equal(node.all().length, 3, 'the tree is unchanged');
  assert.ok(node.all().every((e) => Object.keys(e.attrs).every((k) => !k.startsWith('on'))), 'no handler attribute');
  KBVault.render(node, { title: null });
  assert.equal(title.textContent, '', 'a missing value renders empty');
});

test('safeHref rejects javascript: and data:', () => {
  const { KBVault } = load();
  for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', ' javascript:alert(1)', 'java\tscript:alert(1)',
    'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox', 'file:///etc/passwd', '//evil.example/x', '/relative',
    'evil.example', '', null, undefined, 42]) {
    assert.equal(KBVault.safeHref(bad), null, String(bad));
  }
  assert.equal(KBVault.safeHref('https://db.int/login?a=1'), 'https://db.int/login?a=1');
  assert.equal(KBVault.safeHref('HTTP://Example.test'), 'http://example.test/');
});

test('render links only http and https, and shows any other scheme as text', () => {
  const { KBVault } = load();
  const link = new El('a', { 'data-field': 'url', 'data-href': 'url' });
  const node = new El('div', {}, [link]);
  KBVault.render(node, { url: 'https://db.int' });
  assert.equal(link.getAttribute('href'), 'https://db.int/');
  assert.equal(link.getAttribute('rel'), 'noopener noreferrer');
  assert.equal(link.getAttribute('target'), '_blank');
  assert.equal(link.textContent, 'https://db.int');
  KBVault.render(node, { url: 'javascript:alert(1)' });
  assert.equal(link.getAttribute('href'), null, 'no href for another scheme');
  assert.equal(link.textContent, 'javascript:alert(1)', 'shown as plain text');
});

test('copy schedules a clear at 30000ms', async () => {
  const t = load();
  await t.KBVault.copy('s3cret');
  assert.deepEqual(t.writes, ['s3cret']);
  assert.equal(t.timers.length, 1);
  assert.equal(t.timers[0].ms, 30000);
  await t.timers[0].fn();
  assert.deepEqual(t.writes, ['s3cret', ''], 'cleared while the tab has focus');

  const away = load({ focus: false });
  await away.KBVault.copy('s3cret');
  await away.timers[0].fn();
  assert.deepEqual(away.writes, ['s3cret'], 'not touched without focus');
});

test('reveal fetches exactly one field through vault/field and masks it again', async () => {
  const t = load({ api: () => ({ ok: true, value: 'pw<i>' }) });
  const node = new El('span');
  node.textContent = '••••••••';
  await t.KBVault.reveal(7, 'password', node);
  assert.deepEqual(t.calls, [{ action: 'field', body: { id: 7, field: 'password' } }]);
  assert.equal(node.textContent, 'pw<i>');
  await t.KBVault.reveal(7, 'password', node);
  assert.equal(t.calls.length, 1, 'hiding needs no request');
  assert.equal(node.textContent, '••••••••', 'the value is gone from the DOM');
});

// The page with the real templates (fake-dom.mjs). 'tree' and 'list' answer at once; every other call is held until
// the test answers it, so it can make answers arrive late and out of order.
function heldPage() {
  const held = [];
  const page = loadPage({
    api: (action, body) => {
      if (action === 'tree') {
        return { ok: true, groups: [{ id: 1, parent_id: null, permission: 'owner', shared_by: null, name: 'G' }], shared_entries: false };
      }
      if (action === 'list') {
        return { ok: true, entries: [10, 11].map((id) => ({ id, title: 'T' + id, username: 'u', url: '', updated_at: 0 })), next_offset: null };
      }
      return new Promise((resolve) => held.push({ action, body, resolve }));
    },
  });
  const take = (action, id) => {
    const i = held.findIndex((h) => h.action === action && (id === undefined || h.body.id === id));
    assert.notEqual(i, -1, `a pending ${action} ${id ?? ''}`);
    return held.splice(i, 1)[0];
  };
  const entry = (id) => ({ ok: true, entry: { id, title: 'T' + id, username: 'u', url: '', tags: [], expires_at: null, updated_at: 0,
    version: 1, group_id: 1, permission: 'owner', secrets: { password: true, notes: false, otp: false }, fields: [] } });
  return { ...page, held, take, entry };
}

test('a slow reveal or entry load never renders under another entry', async () => {
  const { doc, take, entry, held } = heldPage();
  await flush();
  doc.querySelector('[data-group-id="1"]').click();
  await flush();
  const rows = () => doc.querySelectorAll('.vault-row');
  const detail = doc.querySelector('[data-vault-detail]');
  const title = detail.querySelector('[data-field="title"]');
  const pw = detail.querySelector('[data-vault-value="password"]');

  // Entry loads answered out of order: the last one clicked wins.
  rows()[0].click();
  rows()[1].click();
  take('entry', 11).resolve(entry(11));
  await flush();
  take('entry', 10).resolve(entry(10));
  await flush();
  assert.equal(title.textContent, 'T11', 'the late answer for T10 is dropped');

  // A reveal of T11's password that answers after T10 is shown is dropped.
  detail.querySelector('[data-vault-reveal="password"]').click();
  rows()[0].click();
  take('entry', 10).resolve(entry(10));
  await flush();
  take('field', 11).resolve({ ok: true, value: 'pw-of-T11' });
  await flush();
  assert.equal(title.textContent, 'T10');
  assert.equal(pw.textContent, '••••••••', "T11's password never shows under T10");
  assert.equal(pw.getAttribute('data-revealed'), null);

  // A reveal that answers while its entry is still shown lands.
  detail.querySelector('[data-vault-reveal="password"]').click();
  take('field', 10).resolve({ ok: true, value: 'pw-of-T10' });
  await flush();
  assert.equal(pw.textContent, 'pw-of-T10');

  // Leaving the group while an entry loads: the detail stays closed.
  rows()[1].click();
  doc.querySelector('[data-group-id="1"]').click();
  await flush();
  take('entry', 11).resolve(entry(11));
  await flush();
  assert.equal(detail.hidden, true, 'no entry shown after the list changed');
  assert.equal(pw.textContent, '••••••••');
  assert.equal(held.length, 0);
});

test('save sends one request at a time and re-enables after the answer', async () => {
  const { doc, take, entry, calls } = heldPage();
  await flush();
  doc.querySelector('[data-group-id="1"]').click();
  await flush();
  doc.querySelector('[data-vault-action="new-entry"]').click();
  await flush();
  const form = doc.querySelector('[data-vault-form="edit"]');
  const submit = form.querySelector('button[type="submit"]');
  assert.equal(form.hidden, false);
  form.elements.title.value = 'New';
  const saves = () => calls.filter((c) => c.action === 'save').length;

  assert.equal(form.dispatch('submit').defaultPrevented, true);
  form.dispatch('submit');
  assert.equal(saves(), 1, 'a double submit sends one create');
  assert.equal(submit.disabled, true, 'disabled while in flight');

  take('save').resolve({ ok: false, reason: 'failed' });
  await flush();
  assert.equal(submit.disabled, false, 'enabled again after a refusal');
  form.dispatch('submit');
  assert.equal(saves(), 2, 'and a retry goes out');

  take('save').resolve({ ok: true, id: 12, version: 1 });
  await flush();
  take('entry', 12).resolve(entry(12));
  await flush();
  assert.equal(submit.disabled, false, 'enabled again after a success');
  assert.equal(form.hidden, true);
});

// T24 (found in the browser E2E): opening the editor fetched every secret at once, and on SQLite Kanboard core's
// session write (SessionHandler::write reads, then updates, in one deferred transaction) fails with "database is
// locked" when another request of the same session wrote in between, so one of the parallel answers came back broken
// and the editor said "Something went wrong". The editor fetches one field at a time. Kills: Promise.all over the
// fields again, or filling the editor before every field arrived.
test('the editor fetches the secrets one at a time, then fills', async () => {
  const { doc, take, entry, held } = heldPage();
  await flush();
  doc.querySelector('[data-group-id="1"]').click();
  await flush();
  doc.querySelectorAll('.vault-row')[0].click();
  const e = entry(10);
  e.entry.secrets = { password: true, notes: true, otp: false };
  e.entry.fields = [{ name: 'api key', protected: true }];
  take('entry', 10).resolve(e);
  await flush();
  doc.querySelector('[data-vault-action="edit"]').click();
  await flush();
  const form = doc.querySelector('[data-vault-form="edit"]');
  const answers = [['password', 'pw-10'], ['notes', 'notes-10'], ['field:api key', 'key-10']];
  for (const [field, value] of answers) {
    const pending = held.filter((h) => h.action === 'field');
    assert.equal(pending.length, 1, `one field request in flight (${pending.map((h) => h.body.field).join(', ')})`);
    assert.equal(pending[0].body.field, field);
    assert.equal(form.hidden, true, 'the editor waits for every field');
    take('field', 10).resolve({ ok: true, value });
    await flush();
  }
  assert.equal(held.filter((h) => h.action === 'field').length, 0);
  assert.equal(form.hidden, false);
  assert.equal(form.elements.password.value, 'pw-10');
  assert.equal(form.elements.notes.value, 'notes-10');
});

// Final review M4 (A9/R70): a custom field's value input is built here, not in a template, so PassphraseInputsTest
// can't see it. Like every passphrase or password input it carries autocomplete="off" and the password-manager ignore
// hints, protected or not (the lock toggles it to a password input in place). Kills: a hint dropped.
test('custom field value inputs refuse password-manager saving', async () => {
  const { doc, take, entry } = heldPage();
  await flush();
  doc.querySelector('[data-group-id="1"]').click();
  await flush();
  doc.querySelectorAll('.vault-row')[0].click();
  const e = entry(10);
  e.entry.secrets = { password: false, notes: false, otp: false };
  e.entry.fields = [{ name: 'api key', protected: true }, { name: 'region', protected: false, value: 'eu' }];
  take('entry', 10).resolve(e);
  await flush();
  doc.querySelector('[data-vault-action="edit"]').click();
  await flush();
  take('field', 10).resolve({ ok: true, value: 'key-10' });
  await flush();
  take('field', 10).resolve({ ok: true, value: 'eu' });
  await flush();
  const inputs = doc.querySelectorAll('.vault-field-value');
  assert.equal(inputs.length, 2);
  assert.equal(inputs[0].type, 'password');
  for (const i of inputs) {
    assert.equal(i.getAttribute('autocomplete'), 'off');
    assert.equal(i.hasAttribute('data-1p-ignore'), true);
    assert.equal(i.getAttribute('data-lpignore'), 'true');
    assert.equal(i.hasAttribute('data-bwignore'), true);
  }
});

// T24: after a save the list and the saved entry were reloaded at once (the same SQLite session-write race). Kills:
// loading both in parallel again, or dropping the entry reload.
test('after a save, the list reloads first, then the entry', async () => {
  const held = [];
  let lists = 0;
  const { doc } = loadPage({
    api: (action, body) => {
      if (action === 'tree') {
        return { ok: true, groups: [{ id: 1, parent_id: null, permission: 'owner', shared_by: null, name: 'G' }], shared_entries: false };
      }
      if (action === 'list' && lists++ === 0) {
        return { ok: true, entries: [], next_offset: null };
      }
      return new Promise((resolve) => held.push({ action, body, resolve }));
    },
  });
  const take = (action) => held.splice(held.findIndex((h) => h.action === action), 1)[0];
  await flush();
  doc.querySelector('[data-group-id="1"]').click();
  await flush();
  doc.querySelector('[data-vault-action="new-entry"]').click();
  await flush();
  const form = doc.querySelector('[data-vault-form="edit"]');
  form.elements.title.value = 'New';
  form.dispatch('submit');
  take('save').resolve({ ok: true, id: 12, version: 1 });
  await flush();
  assert.deepEqual(held.map((h) => h.action), ['list'], 'only the list reload is in flight');
  take('list').resolve({ ok: true, entries: [{ id: 12, title: 'New', username: '', url: '', updated_at: 0 }], next_offset: null });
  await flush();
  assert.deepEqual(held.map((h) => [h.action, h.body.id]), [['entry', 12]], 'then the saved entry');
});

// Task 12 fix: the owner's at-risk warning links to vault?entry=<id>. The unlocked browser opens that entry through
// vault/entry, the same path a click takes; anything but a positive decimal id is ignored (no request, no error).
test('?entry=<id> opens that entry; any other value is ignored', async () => {
  const base = 'https://kb.test/?controller=VaultController&action=index&plugin=Vault';
  const entry = { id: 42, title: 'Deep', username: 'u', url: '', tags: [], expires_at: null, updated_at: 0, version: 1,
    group_id: 1, permission: 'owner', secrets: { password: true, notes: false, otp: false }, fields: [] };
  const api = (action) => (action === 'tree' ? { ok: true, groups: [], shared_entries: false }
    : action === 'entry' ? { ok: true, entry } : { ok: true });
  const p = loadPage({ api, href: base + '&entry=42' });
  await flush();
  assert.deepEqual(p.calls.filter((c) => c.action === 'entry').map((c) => c.body), [{ id: 42 }]);
  const detail = p.doc.querySelector('[data-vault-detail]');
  assert.equal(detail.hidden, false, 'the entry view is open');
  assert.equal(detail.querySelector('[data-field="title"]').textContent, 'Deep');
  assert.equal(detail.getAttribute('data-vault-entry-id'), '42');

  for (const bad of ['0', '-3', '4x', 'x', '1e3', '0x10', ' 5', '5.0', '', '12345678901234567', '%2F1']) {
    const q = loadPage({ api, href: base + '&entry=' + bad });
    await flush();
    assert.equal(q.calls.filter((c) => c.action === 'entry').length, 0, `entry=${bad} is ignored`);
    assert.equal(q.doc.querySelector('[data-vault-detail]').hidden, true, `entry=${bad}: nothing opens`);
  }
  const none = loadPage({ api, href: base });
  await flush();
  assert.equal(none.calls.filter((c) => c.action === 'entry').length, 0, 'no parameter, no request');
});
