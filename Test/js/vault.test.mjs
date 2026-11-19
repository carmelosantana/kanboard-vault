// node --test Vault/Test/js — zero-dependency. Loads Assets/js/vault.js into a vm context with a fake window,
// document and fetch, as the browser would run it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const SRC = readFileSync(fileURLToPath(new URL('../../Assets/js/vault.js', import.meta.url)), 'utf8');
const TOKEN = 'a'.repeat(64);
// Objects made inside the vm context have its prototypes; compare their JSON shape.
const plain = (o) => JSON.parse(JSON.stringify(o));

function load({ state = 'locked', idleMs = 0, respond } = {}) {
  const calls = [];
  const timers = [];
  const listeners = {};
  let reloads = 0;
  const attrs = {
    'data-csrf': TOKEN,
    'data-endpoints': JSON.stringify({ unlock: '/vault/unlock', lock: '/vault/lock', enrol: '/vault/enrol' }),
    'data-messages': JSON.stringify({ failed: 'Something went wrong.' }),
    'data-idle-ms': String(idleMs),
    'data-vault-state': state,
  };
  const app = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
  const document = {
    readyState: 'complete',
    getElementById: (id) => (id === 'vault-app' ? app : null),
    querySelector: () => null,
    addEventListener: (ev, fn) => { (listeners[ev] ||= []).push(fn); },
  };
  const window = {
    document,
    URLSearchParams,
    JSON,
    location: { reload: () => { reloads++; } },
    setTimeout: (fn, ms) => { timers.push({ fn, ms, live: true }); return timers.length; },
    clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].live = false; },
    fetch: (url, opts) => {
      calls.push({ url, opts });
      return Promise.resolve(respond ? respond(url, opts) : { json: () => Promise.resolve({ ok: true }) });
    },
  };
  vm.runInNewContext(SRC, { window, Promise, Object, Array, JSON, String, parseInt });
  return { KBVault: window.KBVault, calls, timers, listeners, reloads: () => reloads };
}

test('api() sends csrf_token', async () => {
  const { KBVault, calls } = load();
  const res = await KBVault.api('unlock', { passphrase: 'pw words here', csrf_token: 'forged' });
  assert.deepEqual(plain(res), { ok: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/vault/unlock');
  assert.equal(calls[0].opts.method, 'POST');
  assert.equal(calls[0].opts.credentials, 'same-origin');
  const body = new URLSearchParams(calls[0].opts.body);
  assert.deepEqual(body.getAll('csrf_token'), [TOKEN], 'the page token, once, never the body\'s');
  assert.equal(body.get('passphrase'), 'pw words here');
});

test('api() refuses an unknown action without a request', async () => {
  const { KBVault, calls } = load();
  assert.deepEqual(plain(await KBVault.api('toString', {})), { ok: false, reason: 'failed' });
  assert.deepEqual(plain(await KBVault.api('nope', {})), { ok: false, reason: 'failed' });
  assert.equal(calls.length, 0);
});

test('api() turns a non-JSON answer or a network error into a generic failure', async () => {
  const html = load({ respond: () => ({ json: () => Promise.reject(new SyntaxError('html')) }) });
  assert.deepEqual(plain(await html.KBVault.api('lock', {})), { ok: false, reason: 'failed' });
  const rate = load({ respond: () => ({ json: () => Promise.resolve({ ok: false, reason: 'rate_limited' }) }) });
  assert.deepEqual(plain(await rate.KBVault.api('unlock', {})), { ok: false, reason: 'rate_limited' });
});

test('lockOnIdle posts lock after ms of inactivity and activity restarts the timer', async () => {
  const { KBVault, calls, timers, listeners, reloads } = load();
  KBVault.lockOnIdle(900000);
  assert.equal(timers.length, 1);
  assert.equal(timers[0].ms, 900000);
  listeners.keydown[0]();
  assert.equal(timers[0].live, false, 'activity cancels the old timer');
  const live = timers.filter((t) => t.live);
  assert.equal(live.length, 1);
  await live[0].fn();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/vault/lock');
  assert.equal(new URLSearchParams(calls[0].opts.body).get('csrf_token'), TOKEN);
  assert.equal(reloads(), 1, 'the page reloads into the locked view');
});

test('the unlocked shell arms the idle lock from data-idle-ms; the locked page does not', () => {
  assert.equal(load({ state: 'unlocked', idleMs: 600000 }).timers[0].ms, 600000);
  assert.equal(load({ state: 'locked', idleMs: 600000 }).timers.length, 0);
});
