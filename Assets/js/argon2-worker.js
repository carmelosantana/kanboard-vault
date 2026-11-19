// Vault's Argon2 module worker (spec: KeePassXC → Libraries / Where the code runs). Started as
// new Worker(url, {type: 'module'}); it imports the vendored, byte-identical @noble/hashes 2.4.0 ESM files as they are
// (Assets/vendor/VENDOR.md), so there is no build step, no WebAssembly and no eval, and Kanboard's CSP is unchanged.
// The file is .js, not .mjs: Kanboard's own nginx image has no MIME type for .mjs and serves it as
// application/octet-stream, which a browser refuses for a module script.
//
// Messages in:
//   {id, type: 'argon2id' | 'argon2d', password, salt, t, m, p, dkLen}  password and salt are Uint8Array; m in KiB
//   {id, type: 'blake2b', data, dkLen}                                  BLAKE2b with a dkLen-byte digest, no key
// Replies: {id, hash} (a Uint8Array, transferred) or {id, error} (a fixed message, never an input).
//
// Limits (spec: KeePassXC import pre-checks): m ≤ 1 GiB, t ≤ 100, p ≤ 8, so a hostile header can't make the worker
// allocate without bound; 16 ≤ dkLen ≤ 64; a salt of at least 8 bytes. The password copy received here is zeroed
// after use. Runs one job at a time, in arrival order.
import { argon2idAsync, argon2dAsync } from '../vendor/noble-hashes/argon2.js';
import { blake2b } from '../vendor/noble-hashes/blake2.js';

const MAX_M = 1024 * 1024; // KiB: 1 GiB
const MAX_T = 100;
const MAX_P = 8;
const ARGON2 = { argon2id: argon2idAsync, argon2d: argon2dAsync };

const int = (v, lo, hi) => Number.isSafeInteger(v) && v >= lo && v <= hi;
const bytes = (v) => v instanceof Uint8Array;

async function run(msg) {
  if (msg.type === 'blake2b') {
    if (!bytes(msg.data) || !int(msg.dkLen, 16, 64)) {
      throw new Error('bad_params');
    }
    return blake2b(msg.data, { dkLen: msg.dkLen });
  }
  const fn = Object.prototype.hasOwnProperty.call(ARGON2, msg.type) ? ARGON2[msg.type] : null;
  if (fn === null) {
    throw new Error('bad_type');
  }
  const { password, salt, t, m, p, dkLen } = msg;
  if (!bytes(password) || !bytes(salt) || salt.length < 8 || !int(t, 1, MAX_T) || !int(p, 1, MAX_P)
    || !int(m, 8 * p, MAX_M) || !int(dkLen, 16, 64)) {
    throw new Error('bad_params');
  }
  try {
    return await fn(password, salt, { t, m, p, dkLen, maxmem: MAX_M * 1024 });
  } finally {
    password.fill(0);
  }
}

let queue = Promise.resolve();

self.addEventListener('message', (event) => {
  const msg = event.data && typeof event.data === 'object' ? event.data : {};
  const id = msg.id;
  queue = queue.then(() => run(msg).then(
    (hash) => self.postMessage({ id, hash }, [hash.buffer]),
    (e) => self.postMessage({ id, error: e && /^bad_/.test(e.message) ? e.message : 'failed' })
  ));
});
