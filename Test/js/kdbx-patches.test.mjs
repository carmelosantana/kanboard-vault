// node --test Vault/Test/js — the vendored kdbxweb 2.1.1, its three local patches, and vault-kdbx.js, which runs it
// on the page with Argon2 in the module worker (spec: KeePassXC import and export → Libraries, Where the code runs,
// Local patches). kdbxweb and vault-kdbx.js run in kdbx-page.mjs's page-like realm with the real worker
// (node-worker.mjs). The fixtures come from Test/fixtures/kdbx/make-fixtures.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash, randomBytes, webcrypto } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { loadKdbxPage } from './kdbx-page.mjs';
import { applyPatch } from './unified-diff.mjs';
import { PASSWORD, WRONG_PASSWORD, WHITESPACE_ENTRY, FILES } from '../fixtures/kdbx/fixtures.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const fixture = (name) => new Uint8Array(readFileSync(path('Test/fixtures/kdbx/' + name)));
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (e) => {
    assert.equal(e && e.code, code, 'error code (message: ' + (e && e.message) + ')');
    return true;
  });
}

function fieldsOf(db) {
  const entry = db.getDefaultGroup().entries[0];
  return Object.fromEntries([...entry.fields].map(([k, v]) => [k, typeof v === 'string' ? v : v.getText()]));
}

async function until(cond, ms = 5000) {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error('timed out waiting');
    await sleep(5);
  }
}

// --- Patch 1 -------------------------------------------------------------------------------------------------------

test('final HMAC block is verified', async () => {
  const { vault } = loadKdbxPage({ vault: true });
  // The fixture differs from whitespace.kdbx in one bit of the final, empty block's HMAC; upstream accepted it.
  const good = fixture(FILES.whitespace);
  const bad = fixture(FILES.tamperedFinalBlock);
  assert.equal(bad.length, good.length);
  assert.deepEqual([...bad.keys()].filter((i) => bad[i] !== good[i]), [good.length - 36]);
  await rejectsWith(vault.load(bad, PASSWORD), 'file_corrupt');
  assert.equal(fieldsOf(await vault.load(good, PASSWORD)).Title, 'Whitespace');

  // The attack the check closes: a block stream cut after a full block, then a forged empty final block. Upstream
  // returned the first block as if it were the whole file.
  const { kdbxweb } = loadKdbxPage();
  const H = kdbxweb.HmacBlockTransform;
  const key = webcrypto.getRandomValues(new Uint8Array(64)).buffer;
  const plain = new Uint8Array(randomBytes(1024 * 1024 + 10));
  const stream = new Uint8Array(await H.encrypt(plain.buffer.slice(0), key.slice(0)));
  assert.deepEqual(new Uint8Array(await H.decrypt(stream.buffer.slice(0), key.slice(0))), plain);
  const firstBlockEnd = 32 + 4 + 1024 * 1024;
  const forged = new Uint8Array(firstBlockEnd + 36);
  forged.set(stream.subarray(0, firstBlockEnd));
  await assert.rejects(H.decrypt(forged.buffer, key.slice(0)), (e) => e.code === 'FileCorrupt' && /invalid hash block/.test(e.message));
});

// --- Patch 2 -------------------------------------------------------------------------------------------------------

test('tabs and whitespace preserved', async () => {
  const { vault, kdbxweb } = loadKdbxPage({ vault: true });
  // KDBX 4 (unprotected values are XML text, where upstream deleted every tab) and KDBX 3.1.
  for (const name of [FILES.whitespace, FILES.kdbx3]) {
    assert.deepEqual(fieldsOf(await vault.load(fixture(name), PASSWORD)), WHITESPACE_ENTRY, name);
  }
  // The filter still removes the control characters XML 1.0 forbids; tab, LF and CR are allowed.
  const doc = kdbxweb.XmlUtils.parse('<r><v>\t a\x00b\x0bc\x1fd \t</v></r>');
  assert.equal(doc.documentElement.firstChild.textContent, '\t abcd \t');
});

// --- Patch 3 -------------------------------------------------------------------------------------------------------

// A page whose WebCrypto records every SHA digest, and a spy on Uint8Array.prototype.fill(0) (kdbxweb's zeroBuffer).
function spiedPage({ failEncrypt = false } = {}) {
  const digests = [];
  const subtle = webcrypto.subtle;
  const crypto = {
    getRandomValues: (a) => webcrypto.getRandomValues(a),
    subtle: new Proxy(subtle, {
      get(target, prop) {
        if (prop === 'digest') {
          return async (alg, data) => {
            const out = await subtle.digest(alg, data);
            const input = data instanceof ArrayBuffer ? data : data.buffer;
            digests.push({ alg: typeof alg === 'string' ? alg : alg.name, inLen: data.byteLength, input, out });
            return out;
          };
        }
        if (prop === 'encrypt' && failEncrypt) {
          return () => Promise.reject(new Error('encrypt failed'));
        }
        const v = target[prop];
        return typeof v === 'function' ? v.bind(target) : v;
      },
    }),
  };
  return { ...loadKdbxPage({ vault: true, crypto }), digests };
}

function spyFill() {
  const zeroed = new Set();
  const fill = Uint8Array.prototype.fill;
  Uint8Array.prototype.fill = function (v, ...rest) {
    if (v === 0) zeroed.add(this.buffer);
    return fill.call(this, v, ...rest);
  };
  return { zeroed, restore: () => { Uint8Array.prototype.fill = fill; } };
}

// The key material among the recorded digests, by algorithm and input length: SHA-256 of 32 bytes is the credential
// hash (and KDBX 3's key hash), SHA-256 of 64 is KDBX 4's cipher key (its input is master seed ‖ derived key) and
// KDBX 3's master key, SHA-512 of 65 is KDBX 4's HMAC key, SHA-512 of 72 the header and per-block HMAC keys. Not
// counted: the header hash, the password's own hash and the inner stream key (SHA-512 of the inner header's 64-byte
// key, which kdbxweb keeps for protected values and patch 03 does not cover).
const KEY_DIGESTS = ['SHA-256/32', 'SHA-256/64', 'SHA-512/65', 'SHA-512/72'];
function assertKeysZeroed(digests, zeroed, expectLens) {
  const keys = digests.filter((d) => KEY_DIGESTS.includes(d.alg + '/' + d.inLen));
  assert.deepEqual([...new Set(keys.map((d) => d.inLen))].sort(), expectLens.slice().sort(), 'the key digests the load made');
  for (const d of keys) {
    const what = `${d.alg} of ${d.inLen} bytes`;
    assert.ok(zeroed.has(d.out), what + ': fill(0) on the output');
    assert.ok(new Uint8Array(d.out).every((b) => b === 0), what + ': output is zero');
    if (d.inLen === 64) {
      assert.ok(new Uint8Array(d.input).every((b) => b === 0), what + ': input is zero');
    }
  }
}

test('keys zeroed on failed load', async () => {
  const spy = spyFill();
  try {
    // KDBX 4, wrong password: refused at the header HMAC, with the cipher, HMAC and header keys made.
    let p = spiedPage();
    await rejectsWith(p.vault.load(fixture(FILES.whitespace), WRONG_PASSWORD), 'invalid_key');
    assertKeysZeroed(p.digests, spy.zeroed, [32, 64, 65, 72]);

    // KDBX 4, right password, tampered final block: refused in the block stream, after every key was made.
    p = spiedPage();
    await rejectsWith(p.vault.load(fixture(FILES.tamperedFinalBlock), PASSWORD), 'file_corrupt');
    assertKeysZeroed(p.digests, spy.zeroed, [32, 64, 65, 72]);

    // KDBX 3.1, wrong password: refused when AES-CBC decryption fails, with the master key made.
    p = spiedPage();
    await rejectsWith(p.vault.load(fixture(FILES.kdbx3), WRONG_PASSWORD), 'invalid_key');
    assertKeysZeroed(p.digests, spy.zeroed, [32, 64]);

    // The KDF itself fails (a header past the caps): the credential hash it was given is zeroed.
    p = spiedPage();
    await rejectsWith(p.vault.load(fixture(FILES.hostileM), PASSWORD), 'kdf_limits');
    assertKeysZeroed(p.digests, spy.zeroed, [32]);

    // KDBX 3.1 whose AES-KDF fails (WebCrypto refuses): the credential hash it was given is zeroed.
    p = spiedPage({ failEncrypt: true });
    await rejectsWith(p.vault.load(fixture(FILES.kdbx3), PASSWORD), 'load_failed');
    assertKeysZeroed(p.digests, spy.zeroed, [32]);

    // A derived key of the wrong length is refused and zeroed.
    const { kdbxweb } = loadKdbxPage();
    const short = new Uint8Array(16).fill(7);
    kdbxweb.CryptoEngine.setArgon2Impl(() => Promise.resolve(short));
    const creds = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(PASSWORD));
    await assert.rejects(kdbxweb.Kdbx.load(fixture(FILES.whitespace).buffer, creds), (e) => e.code === 'Unsupported');
    assert.ok(short.every((b) => b === 0), 'the short derived key is zeroed');

    // And a load that succeeds leaves no key behind either (upstream kept the header and block HMAC keys).
    p = spiedPage();
    await p.vault.load(fixture(FILES.whitespace), PASSWORD);
    assertKeysZeroed(p.digests, spy.zeroed, [32, 64, 65, 72]);
  } finally {
    spy.restore();
  }
});

// --- The vendored file ---------------------------------------------------------------------------------------------

// --- Patch 4 (Task 22, T21 M5) ----------------------------------------------------------------------------------------

test('inflated size is capped', async () => {
  // kdbxweb's gunzip runs on the page, where cancel() can't stop it. Patch 04 gives each load an inflate budget
  // (KdbxFormat.inflateLimit, 256 MiB): a gzip stream whose declared size would go past it is refused before it is
  // inflated (vault-kdbx.js: too_large), and one that inflates past its declared size stops at once (FileCorrupt).
  const { kdbxweb, vault } = loadKdbxPage({ vault: true });
  assert.equal(kdbxweb.KdbxFormat.inflateLimit, 256 * 1024 * 1024);
  kdbxweb.KdbxFormat.inflateLimit = 100;
  await rejectsWith(vault.load(fixture(FILES.whitespace), PASSWORD), 'too_large');
  await rejectsWith(vault.load(fixture(FILES.kdbx3), PASSWORD), 'too_large');
  // The budget is per load, and the limit is read at each load.
  kdbxweb.KdbxFormat.inflateLimit = 256 * 1024 * 1024;
  assert.equal(fieldsOf(await vault.load(fixture(FILES.whitespace), PASSWORD)).Title, 'Whitespace');
  assert.equal(fieldsOf(await vault.load(fixture(FILES.kdbx3), PASSWORD)).Title, 'Whitespace');

  // A KDBX 3 compressed binary goes through the same gunzip. 1 MiB of zeros, declared as 1 KiB: refused while
  // inflating, not after (the 1 KiB buffer is not silently overrun).
  const bomb = new Uint8Array(gzipSync(Buffer.alloc(1024 * 1024)));
  const lie = bomb.slice();
  new DataView(lie.buffer).setUint32(lie.length - 4, 1024, true);
  const node = (b) => kdbxweb.XmlUtils.parse('<Binary Compressed="True">' + Buffer.from(b).toString('base64') + '</Binary>').documentElement;
  assert.throws(() => kdbxweb.XmlUtils.getProtectedBinary(node(lie)), (e) => e.code === 'FileCorrupt');
  assert.equal(kdbxweb.XmlUtils.getProtectedBinary(node(bomb)).byteLength, 1024 * 1024);
  // Declared past what is left of the budget: refused before a buffer is allocated.
  const huge = bomb.slice();
  new DataView(huge.buffer).setUint32(huge.length - 4, 0xffffffff, true);
  assert.throws(() => kdbxweb.XmlUtils.getProtectedBinary(node(huge)), (e) => e.code === 'InflateLimit');

  // The budget is shared by everything one load inflates: two 1 MiB binaries don't fit in 1.5 MiB.
  kdbxweb.KdbxFormat.inflateLimit = 1.5 * 1024 * 1024;
  await vault.load(fixture(FILES.whitespace), PASSWORD);
  assert.equal(kdbxweb.XmlUtils.getProtectedBinary(node(bomb)).byteLength, 1024 * 1024);
  assert.throws(() => kdbxweb.XmlUtils.getProtectedBinary(node(bomb)), (e) => e.code === 'InflateLimit');
  kdbxweb.KdbxFormat.inflateLimit = 256 * 1024 * 1024;
  await vault.load(fixture(FILES.whitespace), PASSWORD);

  // Hand-made single deflate blocks (fixed Huffman), so no block boundary helps: a literal, then a million copies of
  // 258 bytes (258 MB) declared as 1 KiB stops at the first copy past the buffer, at once; and literals alone past
  // the declared size are refused at the end of the stream instead of cut off silently.
  const copies = gzipFixed((w) => {
    w.literal(0);
    for (let i = 0; i < 1000000; i++) w.copy258();
  }, 1024);
  const t0 = Date.now();
  assert.throws(() => kdbxweb.XmlUtils.getProtectedBinary(node(copies)), (e) => e.code === 'FileCorrupt');
  assert.ok(Date.now() - t0 < 150, 'refused within ' + (Date.now() - t0) + ' ms');
  const literals = gzipFixed((w) => {
    for (let i = 0; i < 2000; i++) w.literal(0x61);
  }, 1024);
  assert.throws(() => kdbxweb.XmlUtils.getProtectedBinary(node(literals)), (e) => e.code === 'FileCorrupt');
  assert.equal(kdbxweb.XmlUtils.getProtectedBinary(node(gzipFixed((w) => w.literal(0x61), 1))).byteLength, 1);
});

// A gzip stream with one final fixed-Huffman deflate block written by fill(w), whose trailer declares `size` bytes
// (CRC left 0: fflate's gunzipSync doesn't check it). RFC 1951 3.2.6: literals 0–143 are 8-bit codes from 0x30,
// length 258 is code 285 (8 bits, 0xc5) with no extra bits, distance 1 is code 0 (5 bits), end of block is 7 zero bits.
function gzipFixed(fill, size) {
  const out = [];
  let acc = 0;
  let n = 0;
  const bits = (v, k) => {
    for (let i = 0; i < k; i++) {
      acc |= ((v >> i) & 1) << n;
      if (++n === 8) { out.push(acc); acc = 0; n = 0; }
    }
  };
  const huff = (code, k) => {
    for (let i = k - 1; i >= 0; i--) bits((code >> i) & 1, 1);
  };
  bits(1, 1); // BFINAL
  bits(1, 2); // BTYPE 01: fixed Huffman
  fill({ literal: (b) => huff(0x30 + b, 8), copy258: () => { huff(0xc5, 8); huff(0, 5); } });
  huff(0, 7);
  if (n > 0) out.push(acc);
  const trailer = new Uint8Array(8);
  new DataView(trailer.buffer).setUint32(4, size, true);
  return Uint8Array.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, ...out, ...trailer]);
}

test('an empty password is tried as no password, then as an empty one', async () => {
  // KeePassXC's rule: an empty password field opens a key-file-only database, and a database whose password is
  // literally empty on a retry (Task 21 concern 4).
  const { kdbxweb, vault } = loadKdbxPage({ vault: true });
  const { Kdbx, Credentials, ProtectedValue } = kdbxweb;
  const keyFile = fixture(FILES.keyfileKey);
  const make = async (pv, kf) => {
    const db = Kdbx.create(new Credentials(pv, kf), 'Empty password');
    db.setVersion(3);
    db.header.keyEncryptionRounds = 1000;
    db.createEntry(db.getDefaultGroup()).fields.set('Title', pv ? 'Empty' : 'Key only');
    return new Uint8Array(await db.save());
  };
  const emptyPw = await make(ProtectedValue.fromString(''), null);
  const emptyPwKey = await make(ProtectedValue.fromString(''), keyFile);
  const keyOnly = await make(null, keyFile);
  assert.equal(fieldsOf(await vault.load(emptyPw, '')).Title, 'Empty');
  assert.equal(fieldsOf(await vault.load(emptyPwKey, '', keyFile)).Title, 'Empty');
  assert.equal(fieldsOf(await vault.load(keyOnly, '', keyFile)).Title, 'Key only');
  // A raw 32-byte key file, which kdbxweb XORs in place: the retry gets fresh bytes.
  const raw = new Uint8Array(randomBytes(32));
  assert.equal(fieldsOf(await vault.load(await make(ProtectedValue.fromString(''), raw.slice()), '', raw)).Title, 'Empty');
  // A wrong key is still wrong after the retry, and a non-empty password is never retried.
  await rejectsWith(vault.load(keyOnly, ''), 'invalid_key');
  await rejectsWith(vault.load(emptyPw, 'x'), 'invalid_key');
});

test('vendored file sha256 matches VENDOR.md after patches', () => {
  const md = readFileSync(path('Assets/vendor/VENDOR.md'), 'utf8');
  const pinned = (label) => {
    const m = new RegExp('\\| `kdbxweb/' + label.replace(/[.()]/g, '\\$&') + '` \\| `([0-9a-f]{64})` \\|').exec(md);
    assert.ok(m, label + ' is pinned in VENDOR.md');
    return m[1];
  };
  const vendored = readFileSync(path('Assets/vendor/kdbxweb/kdbxweb.js'), 'utf8');
  assert.equal(sha256(vendored), pinned('kdbxweb.js (patched)'));
  assert.equal(sha256(readFileSync(path('Assets/vendor/kdbxweb/LICENSE'))), pinned('LICENSE'));

  // The patches, in order, are exactly the files in patches/ and each is listed in VENDOR.md.
  const patches = readdirSync(path('Assets/vendor/kdbxweb/patches')).sort();
  assert.deepEqual(patches, ['01-verify-final-hmac-block.patch', '02-preserve-tabs.patch', '03-zero-keys-on-failure.patch', '04-cap-inflated-size.patch']);
  for (const f of patches) assert.ok(md.includes('`kdbxweb/patches/' + f + '`'), f + ' is recorded in VENDOR.md');
  const texts = patches.map((f) => readFileSync(path('Assets/vendor/kdbxweb/patches/' + f), 'utf8'));

  // Un-applying them, last first, gives the upstream bytes (the npm tarball's sha256, pinned in VENDOR.md) ...
  const upstream = texts.slice().reverse().reduce((t, patch) => applyPatch(t, patch, { reverse: true }), vendored);
  assert.equal(sha256(upstream), pinned('kdbxweb.js (upstream)'));
  // ... and applying them to those bytes, in order, gives the vendored file back byte for byte.
  assert.equal(texts.reduce((t, patch) => applyPatch(t, patch), upstream), vendored);
});

test('the vendored kdbxweb has no eval or WebAssembly, and its one Function is the unreachable global fallback', () => {
  const src = readFileSync(path('Assets/vendor/kdbxweb/kdbxweb.js'), 'utf8');
  assert.doesNotMatch(src, /\beval\(|WebAssembly|importScripts|XMLHttpRequest|\bfetch\(/);
  // webpack's runtime reaches new Function only when globalThis is not an object, which no supported browser has.
  assert.deepEqual([...src.matchAll(/new Function|Function\(/g)].length, 1);
  assert.match(src, /if \(typeof globalThis === 'object'\) return globalThis;\n.*\n.*return this \|\| new Function\('return this'\)\(\);/);
});

// --- vault-kdbx.js -------------------------------------------------------------------------------------------------

test('load opens KDBX 4 and 3.1 files through the Argon2 module worker, with a key file too', async () => {
  const { vault, log } = loadKdbxPage({ vault: true, workerLog: { started: [], messages: [], terminated: 0, replies: [] } });
  assert.equal(fieldsOf(await vault.load(fixture(FILES.whitespace), PASSWORD)).Title, 'Whitespace');
  // The worker's answer is copied out and the copy it sent is zeroed (kdbxweb zeroes the page's copy).
  assert.equal(log.replies.length, 1);
  assert.equal(log.replies[0].hash.length, 32);
  assert.ok(log.replies[0].hash.every((b) => b === 0));
  // Each Argon2 job runs in a fresh module worker next to vault-kdbx.js, which is terminated after its answer.
  assert.deepEqual(log.started, [{ url: 'https://kb.test/plugins/Vault/Assets/js/argon2-worker.js', type: 'module' }]);
  assert.deepEqual(log.messages, ['argon2id']);
  assert.equal(log.terminated, 1);

  // An ArrayBuffer works as well as a Uint8Array, and so does a view into a larger buffer (only its own bytes are
  // read); the caller's bytes are left as they were.
  const kf = fixture(FILES.keyfile);
  const before = kf.slice();
  const db = await vault.load(kf.buffer, PASSWORD, fixture(FILES.keyfileKey));
  assert.equal(fieldsOf(db).UserName, 'key user');
  assert.deepEqual(kf, before);
  assert.deepEqual(log.messages, ['argon2id', 'argon2d']);
  const padded = new Uint8Array(kf.length + 16);
  padded.set(kf, 8);
  assert.equal(fieldsOf(await vault.load(padded.subarray(8, 8 + kf.length), PASSWORD, fixture(FILES.keyfileKey))).Title, 'Keyed');
  await rejectsWith(vault.load(fixture(FILES.keyfile), PASSWORD), 'invalid_key');
  // The header's Argon2 version reaches the worker (0x10 gives a different key from 0x13).
  assert.equal(fieldsOf(await vault.load(fixture(FILES.argon2v10), PASSWORD)).Title, 'Version 0x10');
  await rejectsWith(vault.load(fixture(FILES.whitespace), WRONG_PASSWORD), 'invalid_key');

  // KDBX 3.1 uses AES-KDF, so no worker is started.
  const n = log.started.length;
  assert.equal(fieldsOf(await vault.load(fixture(FILES.kdbx3), PASSWORD)).Title, 'Whitespace');
  assert.equal(log.started.length, n);

  await rejectsWith(vault.load(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]), PASSWORD), 'not_kdbx');
  await rejectsWith(vault.load('not bytes', PASSWORD), 'bad_input');
  await rejectsWith(vault.load(fixture(FILES.whitespace), null), 'bad_input');
  await rejectsWith(vault.load(fixture(FILES.whitespace), PASSWORD, 'not bytes'), 'bad_input');
});

test('the worker refuses KDF parameters past the import caps, so a hostile header cannot hang the page', async () => {
  // No pre-check runs here: vault-kdbx.js hands the header's values to the worker, which refuses them at once.
  const { vault, log } = loadKdbxPage({ vault: true });
  vault.argon2TimeoutMs = 20000;
  for (const name of [FILES.hostileM, FILES.hostileT, FILES.hostileP]) {
    const t0 = Date.now();
    await rejectsWith(vault.load(fixture(name), PASSWORD), 'kdf_limits');
    assert.ok(Date.now() - t0 < 5000, name + ' was refused quickly');
  }
  assert.equal(log.started.length, 3);
  assert.equal(log.terminated, 3);
});

test('cancel() terminates the worker and rejects the load', async () => {
  const { vault, log } = loadKdbxPage({ vault: true });
  const pending = vault.load(fixture(FILES.slow), PASSWORD);
  await until(() => log.messages.length === 1);
  assert.equal(log.terminated, 0);
  const t0 = Date.now();
  vault.cancel();
  await rejectsWith(pending, 'cancelled');
  // At once: the job is stopped, not waited for (it would run for many seconds).
  assert.ok(Date.now() - t0 < 1000, 'cancelled within a second');
  assert.equal(log.terminated, 1);

  // Cancelled before the KDF starts: no worker is started at all.
  const early = vault.load(fixture(FILES.slow), PASSWORD);
  vault.cancel();
  await rejectsWith(early, 'cancelled');
  await sleep(50);
  assert.equal(log.started.length, 1);

  // Cancelled after the KDF (KDBX 3.1 has none in the worker): the load still rejects, whether it would have
  // succeeded or failed.
  const late = vault.load(fixture(FILES.kdbx3), PASSWORD);
  vault.cancel();
  await rejectsWith(late, 'cancelled');
  const lateWrong = vault.load(fixture(FILES.kdbx3), WRONG_PASSWORD);
  vault.cancel();
  await rejectsWith(lateWrong, 'cancelled');

  // A cancel with nothing running is harmless, and the next load works.
  vault.cancel();
  assert.equal(fieldsOf(await vault.load(fixture(FILES.whitespace), PASSWORD)).Title, 'Whitespace');
});

test('a load waits for the one before it', async () => {
  const { vault } = loadKdbxPage({ vault: true });
  const first = vault.load(fixture(FILES.slow), PASSWORD);
  await rejectsWith(vault.load(fixture(FILES.whitespace), PASSWORD), 'busy');
  vault.cancel();
  await rejectsWith(first, 'cancelled');
});

test('an Argon2 job past the time limit is stopped and its worker terminated', async () => {
  const { vault, log } = loadKdbxPage({ vault: true });
  assert.equal(vault.argon2TimeoutMs, 120000);
  vault.argon2TimeoutMs = 300;
  const t0 = Date.now();
  await rejectsWith(vault.load(fixture(FILES.slow), PASSWORD), 'timeout');
  assert.ok(Date.now() - t0 < 5000);
  assert.equal(log.started.length, 1);
  assert.equal(log.terminated, 1);
});

test('vault-kdbx.js has no eval, inline HTML, storage or logging', () => {
  const src = readFileSync(path('Assets/js/vault-kdbx.js'), 'utf8').replace(/^\s*(\/\/|\*|\/\*).*$/gm, '');
  assert.doesNotMatch(src, /eval\(|new Function|WebAssembly|innerHTML|outerHTML|insertAdjacentHTML|localStorage|sessionStorage|indexedDB|console\.|importScripts|fetch\(/);
});
