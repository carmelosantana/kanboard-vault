// node --test Vault/Test/js — the Argon2 module worker and the vendored @noble/hashes 2.4.0 (spec: KeePassXC →
// Libraries; One-time shares → Creating a share). The worker runs as a module worker would, through
// module-worker-harness.mjs under --experimental-vm-modules; the KAT runs the vendored file itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const HARNESS = fileURLToPath(new URL('./module-worker-harness.mjs', import.meta.url));
const VECTORS = JSON.parse(readFileSync(path('Test/fixtures/enc-vectors.json'), 'utf8'));
const hex = (u) => Buffer.from(u).toString('hex');
const utf8hex = (s) => Buffer.from(s, 'utf8').toString('hex');

function worker(messages) {
  const out = execFileSync(process.execPath, ['--experimental-vm-modules', '--no-warnings', HARNESS, JSON.stringify(messages)], {
    encoding: 'utf8',
    timeout: 120000,
  });
  return JSON.parse(out.trim().split('\n').pop());
}

test('noble files load as-is in a module worker', () => {
  const a = VECTORS.argon2id;
  const r = worker([
    { id: 1, type: 'argon2id', password: { hex: utf8hex(a.password) }, salt: { hex: a.salt }, t: a.t, m: a.m, p: a.p, dkLen: a.dkLen },
    { id: 2, type: 'blake2b', data: { hex: VECTORS.burn.b }, dkLen: 32 },
  ]);
  // A worker realm: no Node loader or globals were there to lean on.
  assert.deepEqual(r.globals, ['undefined', 'undefined', 'undefined']);
  // The share's Argon2id (t=3, m=64 MiB, p=1) equals libsodium's, and BLAKE2b-256 equals ShareModel::burnHash.
  assert.deepEqual(r.replies, [{ id: 1, hash: a.hash }, { id: 2, hash: VECTORS.burn.burn_hash }]);
  // Exactly the vendored files were loaded, unmodified (their sha256 is pinned in VENDOR.md).
  assert.deepEqual(r.loaded.sort(), [
    'Assets/js/argon2-worker.js',
    'Assets/vendor/noble-hashes/_blake.js',
    'Assets/vendor/noble-hashes/_md.js',
    'Assets/vendor/noble-hashes/_u64.js',
    'Assets/vendor/noble-hashes/argon2.js',
    'Assets/vendor/noble-hashes/blake2.js',
    'Assets/vendor/noble-hashes/utils.js',
  ]);
});

test('vendored noble files match the sha256 pinned in VENDOR.md', () => {
  const md = readFileSync(path('Assets/vendor/VENDOR.md'), 'utf8');
  const files = readdirSync(path('Assets/vendor/noble-hashes')).sort();
  assert.deepEqual(files, ['LICENSE', '_blake.js', '_md.js', '_u64.js', 'argon2.js', 'blake2.js', 'utils.js']);
  for (const f of files) {
    const sum = createHash('sha256').update(readFileSync(path('Assets/vendor/noble-hashes/' + f))).digest('hex');
    assert.match(md, new RegExp('`noble-hashes/' + f.replace('.', '\\.') + '` \\| `' + sum + '`'), f + ' is pinned with its sha256');
  }
});

test('argon2id KAT from RFC 9106', async () => {
  // RFC 9106 §5.3 (Argon2id) and §5.1 (Argon2d): password 32×0x01, salt 16×0x02, secret 8×0x03, associated data
  // 12×0x04, t=3, m=32 KiB, p=4, a 32-byte tag.
  const { argon2id, argon2d } = await import(new URL('../../Assets/vendor/noble-hashes/argon2.js', import.meta.url));
  const opts = { t: 3, m: 32, p: 4, dkLen: 32, key: new Uint8Array(8).fill(3), personalization: new Uint8Array(12).fill(4) };
  const pw = new Uint8Array(32).fill(1);
  const salt = new Uint8Array(16).fill(2);
  assert.equal(hex(argon2id(pw, salt, opts)), '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  assert.equal(hex(argon2d(pw, salt, opts)), '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb');
});

test('the worker runs argon2d and answers each request by its id', () => {
  const r = worker([
    { id: 'x', type: 'argon2d', password: { hex: '01'.repeat(32) }, salt: { hex: '02'.repeat(16) }, t: 3, m: 32, p: 4, dkLen: 32 },
    { id: 'y', type: 'argon2id', password: { hex: '01'.repeat(32) }, salt: { hex: '02'.repeat(16) }, t: 3, m: 32, p: 4, dkLen: 32 },
  ]);
  assert.equal(r.replies.length, 2);
  assert.equal(r.replies[0].id, 'x');
  assert.equal(r.replies[1].id, 'y');
  // Without the RFC's secret and AD the tags differ from the KAT, but argon2d and argon2id must differ from each other.
  assert.match(r.replies[0].hash, /^[0-9a-f]{64}$/);
  assert.notEqual(r.replies[0].hash, r.replies[1].hash);
});

test('the worker refuses out-of-range parameters with a fixed error', () => {
  const base = { type: 'argon2id', password: { hex: '00' }, salt: { hex: '00'.repeat(16) }, t: 1, m: 64, p: 1, dkLen: 32 };
  const r = worker([
    { ...base, id: 1, m: 1024 * 1024 + 1 },
    { ...base, id: 2, t: 101 },
    { ...base, id: 3, p: 9, m: 1024 },
    { ...base, id: 4, salt: { hex: '00'.repeat(7) } },
    { ...base, id: 5, type: 'argon2i' },
    { ...base, id: 6, type: 'constructor' },
    { ...base, id: 7, dkLen: 8 },
    { ...base, id: 8, password: 'not bytes' },
    { id: 9, type: 'blake2b', data: { hex: '00' }, dkLen: 65 },
  ]);
  assert.deepEqual(r.replies.map((x) => [x.id, x.error]), [
    [1, 'bad_params'], [2, 'bad_params'], [3, 'bad_params'], [4, 'bad_params'], [5, 'bad_type'], [6, 'bad_type'],
    [7, 'bad_params'], [8, 'bad_params'], [9, 'bad_params'],
  ]);
});

test('argon2-worker.js has no eval, no WebAssembly and only relative imports', () => {
  const src = readFileSync(path('Assets/js/argon2-worker.js'), 'utf8').replace(/^\s*\/\/.*$/gm, '');
  assert.doesNotMatch(src, /eval\(|new Function|WebAssembly|importScripts|fetch\(/);
  for (const m of src.matchAll(/^import .* from '([^']+)';$/gm)) assert.match(m[1], /^\.\.\/vendor\/noble-hashes\/[a-z0-9_]+\.js$/);
});
