// node --test Vault/Test/js — zero-dependency. Loads Assets/js/vault-browser.js into a vm context with a tiny fake DOM
// (elements record every attribute and text write; setting innerHTML or outerHTML throws), a fake clipboard and
// fake timers, as the browser would run it after vault.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

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
