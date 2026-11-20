// node --test Vault/Test/js — the public one-time share page (spec: One-time shares → Opening a share), run on the
// real Template/share/show.php in the fake DOM with vault-onetime.js, vault-reveal.js, Node's WebCrypto and the real
// Argon2 worker. fetch, history and the clipboard are spies.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import vm from 'node:vm';
import { Doc, parseInto, flush } from './fake-dom.mjs';
import { workerClass } from './node-worker.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const SRC = readFileSync(path('Assets/js/vault-reveal.js'), 'utf8');
const TEMPLATE = readFileSync(path('Template/share/show.php'), 'utf8');
const ID = '00112233445566778899aabbccddeeff';
const EXP = 1795000000;
const REVEAL_URL = '/?controller=VaultShareController&action=reveal&plugin=Vault';

function stripPhp(src) {
  return src
    .replace(/<\?=\s*t\('((?:[^'\\]|\\.)*)'\)\s*\?>/g, (_, s) => s.replace(/\\'/g, "'"))
    .replace(/<\?=[\s\S]*?\?>/g, 'X')
    .replace(/<\?php[\s\S]*?\?>/g, '')
    .replace(/<!DOCTYPE html>/i, '');
}

// A share made by the real page code, and the server's reveal answer for it.
async function makeShare(plaintext, passphrase = '') {
  const { Worker } = workerClass();
  const window = { crypto: webcrypto, Worker, URL, TextEncoder, TextDecoder, atob, btoa, document: { currentScript: { src: 'https://kb.test/plugins/Vault/Assets/js/vault-onetime.js' } } };
  vm.runInContext(readFileSync(path('Assets/js/vault-onetime.js'), 'utf8'), vm.createContext({ window }));
  const s = await window.KBVaultOnetime.encrypt({ plaintext, shareId: ID, expiresAt: EXP, passphrase });
  return {
    fragment: s.fragment,
    burnHash: s.burn_hash,
    answer: { ok: true, ciphertext: s.ciphertext, iv: s.iv, salt: s.salt, has_passphrase: s.has_passphrase === 1, expires_at: EXP },
  };
}

// The page at ?…&id=<id>#<hash>. reveal(body) answers each POST (default: the given answer once, then not_available).
function sharePage({ id = ID, hash = '', https = '1', reveal, worker } = {}) {
  const doc = new Doc();
  parseInto(doc, doc.body, stripPhp(TEMPLATE));
  const root = doc.getElementById('vault-reveal');
  root.setAttribute('data-reveal-url', REVEAL_URL);
  root.setAttribute('data-csrf', 'csrf-token');
  root.setAttribute('data-vault-https', https);
  const posts = [];
  const history = [];
  const copied = [];
  const search = '?controller=VaultShareController&action=show&plugin=Vault' + (id === null ? '' : '&id=' + id);
  const location = { pathname: '/', search, hash: hash ? '#' + hash : '', href: 'https://kb.test/' + search + (hash ? '#' + hash : '') };
  const { Worker: RealWorker } = workerClass();
  const Worker = worker === undefined ? RealWorker : worker;
  const window = {
    document: doc,
    location,
    crypto: webcrypto,
    Worker,
    URL,
    URLSearchParams,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    setTimeout: () => 0,
    clearTimeout: () => {},
    navigator: { clipboard: { writeText: (t) => { copied.push(t); return Promise.resolve(); } } },
    history: {
      replaceState: (state, title, url) => {
        history.push(url);
        location.hash = '';
        location.href = 'https://kb.test' + url;
      },
    },
    fetch: (url, init) => {
      const body = Object.fromEntries(new URLSearchParams(init.body));
      posts.push({ url, init, body });
      const [status, data] = reveal ? reveal(body, posts.length) : [404, { ok: false, reason: 'not_available' }];
      return Promise.resolve({ status, ok: status === 200, json: () => Promise.resolve(data) });
    },
  };
  const ctx = vm.createContext({ window });
  doc.currentScript = { src: 'https://kb.test/plugins/Vault/Assets/js/vault-onetime.js?1' };
  vm.runInContext(readFileSync(path('Assets/js/vault-onetime.js'), 'utf8'), ctx, { filename: 'vault-onetime.js' });
  doc.currentScript = null;
  vm.runInContext(SRC, ctx, { filename: 'vault-reveal.js' });
  const q = (sel) => doc.querySelector(sel);
  return {
    doc, window, posts, history, copied, location,
    button: q('[data-vault-reveal-button]'),
    pass: q('[data-vault-reveal-passphrase]'),
    status: q('[data-vault-reveal-status]'),
    result: q('[data-vault-reveal-result]'),
    secret: q('[data-vault-reveal-secret]'),
    copy: q('[data-vault-reveal-copy]'),
  };
}

async function until(fn, ms = 20000) {
  const end = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
}

const once = (answer) => (body, n) => (n === 1 ? [200, answer] : [404, { ok: false, reason: 'not_available' }]);

test('the fragment is read once and wiped from the address bar, and nothing is posted on load', async () => {
  const s = await makeShare('hello');
  const p = sharePage({ hash: s.fragment, reveal: once(s.answer) });
  await flush();
  assert.deepEqual(p.history, ['/?controller=VaultShareController&action=show&plugin=Vault&id=' + ID]);
  assert.equal(p.location.hash, '');
  assert.ok(!p.location.href.includes(s.fragment));
  assert.equal(p.posts.length, 0, 'opening the page reveals nothing');
  assert.equal(p.button.disabled, false);
});

test('Reveal posts only id, b and the CSRF token, never k, and shows the secret as text', async () => {
  const XSS = '<img src=x onerror=alert(1)>';
  const s = await makeShare(XSS);
  const p = sharePage({ hash: s.fragment, reveal: once(s.answer) });
  await flush();
  const ev = p.button.dispatch('click');
  assert.equal(ev.defaultPrevented, true);
  await until(() => !p.result.hidden);
  assert.equal(p.posts.length, 1);
  const post = p.posts[0];
  assert.equal(post.url, REVEAL_URL);
  assert.equal(post.init.method, 'POST');
  assert.equal(post.init.credentials, 'same-origin');
  assert.equal(post.init.cache, 'no-store');
  assert.deepEqual(Object.keys(post.body).sort(), ['b', 'csrf_token', 'id']);
  assert.equal(post.body.id, ID);
  assert.equal(post.body.csrf_token, 'csrf-token');
  const kb = Buffer.from(s.fragment, 'base64url');
  assert.equal(post.body.b, kb.subarray(32).toString('hex'));
  const wire = JSON.stringify(p.posts.map((x) => [x.url, x.init.body]));
  assert.ok(!wire.includes(s.fragment) && !wire.includes(kb.subarray(0, 32).toString('hex')) && !wire.includes(kb.subarray(0, 32).toString('base64')), 'k never leaves the page');
  assert.ok(!post.url.includes(ID), 'the id goes in the body, not a query');
  assert.equal(p.secret.value, XSS);
  p.copy.click();
  await flush();
  assert.deepEqual(p.copied, [XSS]);
});

test('Enter in the passphrase field reveals, with preventDefault', async () => {
  const s = await makeShare('by enter', 'open sesame');
  const p = sharePage({ hash: s.fragment, reveal: once(s.answer) });
  await flush();
  p.pass.value = 'open sesame';
  const other = p.pass.dispatch('keydown', { key: 'a' });
  assert.equal(other.defaultPrevented, false);
  assert.equal(p.posts.length, 0);
  const ev = p.pass.dispatch('keydown', { key: 'Enter' });
  assert.equal(ev.defaultPrevented, true);
  await until(() => !p.result.hidden);
  assert.equal(p.secret.value, 'by enter');
  assert.equal(p.pass.value, '', 'the passphrase field is cleared');
});

test('a wrong passphrase keeps the ciphertext in memory for a retry without a second reveal', async () => {
  const s = await makeShare('second try', 'right');
  const p = sharePage({ hash: s.fragment, reveal: once(s.answer) });
  await flush();
  p.pass.value = 'wrong';
  p.button.click();
  await until(() => p.posts.length === 1 && !p.status.hidden && !p.button.disabled);
  assert.equal(p.result.hidden, true);
  assert.match(p.status.textContent, /passphrase/i);
  p.pass.value = 'right';
  p.button.click();
  await until(() => !p.result.hidden);
  assert.equal(p.posts.length, 1, 'the link was revealed once; the retry decrypts the kept ciphertext');
  assert.equal(p.secret.value, 'second try');
});

test('a passphrase share revealed without one asks for it, without a second reveal', async () => {
  const s = await makeShare('needs it', 'pp');
  const p = sharePage({ hash: s.fragment, reveal: once(s.answer) });
  await flush();
  p.button.click();
  await until(() => p.posts.length === 1 && !p.status.hidden && !p.button.disabled);
  assert.match(p.status.textContent, /passphrase/i);
  p.pass.value = 'pp';
  p.button.click();
  await until(() => !p.result.hidden);
  assert.equal(p.posts.length, 1);
  assert.equal(p.secret.value, 'needs it');
});

// Final review M3: Reveal burns the link, so a browser that can't run the module worker (Argon2 for a passphrase
// share) must find out before the POST, not after. A missing Worker, one whose constructor throws, and one that fails
// to load (a browser without module workers loads the script classic and errors) all leave the link unburned: no POST,
// "unsupported", Reveal off. Kills: the probe dropped or moved after the POST.
test('a browser without a working module worker is told so before anything is posted', async () => {
  const s = await makeShare('hello', 'pass phrase');
  class Throws { constructor() { throw new Error('module workers unsupported'); } }
  class Fails {
    constructor() { setTimeout(() => this.onerror && this.onerror({}), 0); }
    postMessage() {}
    terminate() {}
  }
  for (const worker of [null, Throws, Fails]) {
    const p = sharePage({ hash: s.fragment, reveal: once(s.answer), worker });
    await flush();
    p.pass.value = 'pass phrase';
    p.button.dispatch('click');
    await until(() => !p.status.hidden && p.button.disabled && p.status.textContent !== '');
    await flush();
    assert.equal(p.posts.length, 0, 'nothing posted: the link is not burned (' + (worker && worker.name) + ')');
    assert.match(p.status.textContent, /could not run the decryption/);
    assert.equal(p.button.disabled, true);
  }
});

test('a burned, revoked or unknown link shows not available, and Reveal stays off', async () => {
  const s = await makeShare('gone');
  const p = sharePage({ hash: s.fragment });
  await flush();
  p.button.click();
  await until(() => !p.status.hidden && p.posts.length === 1);
  await flush();
  assert.match(p.status.textContent, /not available|no longer/i);
  assert.equal(p.button.disabled, true);
  p.button.click();
  await flush();
  assert.equal(p.posts.length, 1);
});

test('an incomplete link or a page without HTTPS posts nothing', async () => {
  const s = await makeShare('x');
  for (const opts of [{ hash: '' }, { hash: s.fragment.slice(0, 40) }, { hash: s.fragment, id: 'nothex' }, { hash: s.fragment, id: null }, { hash: s.fragment, https: '0' }]) {
    const p = sharePage({ ...opts, reveal: once(s.answer) });
    await flush();
    assert.equal(p.button.disabled, true, JSON.stringify(opts));
    p.button.click();
    p.pass.dispatch('keydown', { key: 'Enter' });
    await flush();
    assert.equal(p.posts.length, 0, JSON.stringify(opts));
  }
});

test('vault-reveal.js writes no HTML and keeps nothing in storage or the console', () => {
  assert.doesNotMatch(SRC, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|localStorage|sessionStorage|indexedDB|console\.|\.submit\(/);
});

test('the share page loads vault-onetime.js, then vault-reveal.js, and carries its messages as attributes', () => {
  const a = TEMPLATE.indexOf("Assets/js/vault-onetime.js");
  const b = TEMPLATE.indexOf("Assets/js/vault-reveal.js");
  assert.ok(a > 0 && b > a);
  assert.doesNotMatch(TEMPLATE, /<script>|<script [^>]*>[^<]/, 'no inline script');
});
