// node --test Vault/Test/js — KBVaultKdbxHeader.check, the import pre-check (spec: KeePassXC import and export →
// Import, step 1). It reads the outer KDBX header itself, before kdbxweb sees the file, and refuses a file that is too
// big, asks for too much KDF work, uses Twofish, or whose framing is broken (T21 M4/M5). One test per reason code,
// each against its own crafted file (Test/fixtures/kdbx/make-headers.mjs) or one crafted here from a real fixture.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { FILES, KPXC, CRAFTED } from '../fixtures/kdbx/fixtures.mjs';
import { field, withKdfParam, withKdfDict, concat, u32, u64, ascii } from '../fixtures/kdbx/craft.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const fixture = (name) => new Uint8Array(readFileSync(path('Test/fixtures/kdbx/' + name)));

// The script runs as the page runs it: a classic script whose global object is window.
function loadHeader() {
  const ctx = vm.createContext({ TextDecoder, Uint8Array, DataView, ArrayBuffer });
  vm.runInContext('var window = globalThis;', ctx);
  vm.runInContext(readFileSync(path('Assets/js/vault-kdbx-header.js'), 'utf8'), ctx, { filename: 'vault-kdbx-header.js' });
  return vm.runInContext('window.KBVaultKdbxHeader', ctx);
}
const H = loadHeader();
const reason = (bytes) => {
  const r = H.check(bytes);
  assert.equal(r.ok, false, 'refused');
  return r.reason;
};
const ok = (bytes) => {
  const r = H.check(bytes);
  assert.equal(r.ok, true, 'accepted (got ' + r.reason + ')');
  return { ...r };
};

const MiB = 1024 * 1024;
const ARGON2D_UUID = Uint8Array.from([0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c]);

test('too_large: a file over 50 MB is refused before it is parsed', () => {
  // A real header followed by padding: 50 MiB exactly is not too large (its framing is then what fails), one more
  // byte is.
  const ws = fixture(FILES.whitespace);
  const big = new Uint8Array(50 * MiB + 1);
  big.set(ws);
  assert.equal(reason(big), 'too_large');
  assert.equal(reason(big.subarray(0, 50 * MiB)), 'file_corrupt');
  // Size first: even bytes that aren't KDBX at all.
  assert.equal(reason(new Uint8Array(50 * MiB + 1)), 'too_large');
  assert.equal(H.MAX_FILE_BYTES, 50 * MiB);
});

test('argon_mem: Argon2 memory over 1 GiB is refused', () => {
  assert.equal(reason(fixture(FILES.hostileM)), 'argon_mem'); // M = 2 GiB
  const ws = fixture(FILES.whitespace);
  assert.equal(reason(withKdfParam(ws, 'M', 1024 * MiB + 1024)), 'argon_mem');
  assert.equal(ok(withKdfParam(ws, 'M', 1024 * MiB)).kdf, 'argon2id');
  // Past 2^32 (the high word counts).
  assert.equal(reason(withKdfParam(ws, 'M', 2 ** 40)), 'argon_mem');
});

test('argon_iter: more than 100 Argon2 iterations is refused', () => {
  assert.equal(reason(fixture(FILES.hostileT)), 'argon_iter'); // I = 1,000,000
  const ws = fixture(FILES.whitespace);
  assert.equal(reason(withKdfParam(ws, 'I', 101)), 'argon_iter');
  ok(withKdfParam(ws, 'I', 100));
});

test('argon_lanes: more than 8 Argon2 lanes is refused', () => {
  assert.equal(reason(fixture(FILES.hostileP)), 'argon_lanes'); // P = 9
  const ws = fixture(FILES.whitespace);
  ok(withKdfParam(ws, 'P', 8));
  assert.equal(reason(withKdfParam(ws, 'P', 0xffffffff)), 'argon_lanes');
});

test('aes_rounds: more than 10^8 AES-KDF rounds is refused, in KDBX 3.1 and 4', () => {
  assert.equal(reason(fixture(CRAFTED.aesRounds3)), 'aes_rounds'); // TransformRounds = 100,000,001
  assert.equal(reason(fixture(CRAFTED.aesRounds4)), 'aes_rounds'); // R = 100,000,001
  // At the cap it passes.
  const v3 = fixture(CRAFTED.aesRounds3).slice();
  const tr = field(v3, 6);
  new DataView(v3.buffer).setUint32(tr.at, 1e8, true);
  assert.deepEqual(ok(v3), { ok: true, version: '3.1', kdf: 'aes', cipher: 'aes' });
  assert.deepEqual(ok(withKdfParam(fixture(CRAFTED.aesRounds4), 'R', 1e8)), { ok: true, version: '4.0', kdf: 'aes', cipher: 'aes' });
  // The high word counts too.
  new DataView(v3.buffer).setUint32(tr.at + 4, 1, true);
  assert.equal(reason(v3), 'aes_rounds');
});

test('twofish: a Twofish database is refused by name', () => {
  assert.equal(reason(fixture(CRAFTED.twofish)), 'twofish');
});

test('yubikey_cr: a challenge-response file has an ordinary header, so the check passes it to the open step', () => {
  // KeePassXC marks nothing in the file (its 2.7.12 binaries hold no such marker; the challenge is the KDF salt).
  // The open step tells the user about the YubiKey when the key is wrong (vault-import.test.mjs).
  assert.deepEqual(ok(fixture(CRAFTED.challengeResponse)), { ok: true, version: '4.0', kdf: 'argon2d', cipher: 'aes' });
  assert.equal(H.REASONS.includes('yubikey_cr'), true);
});

test('file_corrupt: a cut-off file, bytes after the final block, or a header that runs off the end', () => {
  assert.equal(reason(fixture(CRAFTED.truncated)), 'file_corrupt');
  assert.equal(reason(fixture(CRAFTED.trailing)), 'file_corrupt');
  const ws = fixture(FILES.whitespace);
  assert.equal(reason(concat([ws, Uint8Array.of(0)])), 'file_corrupt');
  assert.equal(reason(ws.subarray(0, ws.length - 1)), 'file_corrupt');
  assert.equal(reason(ws.subarray(0, 40)), 'file_corrupt');
  // KDBX 3.1: the encrypted payload must be whole AES blocks.
  const v3 = fixture(FILES.kdbx3);
  assert.equal(reason(v3.subarray(0, v3.length - 1)), 'file_corrupt');
  assert.equal(reason(v3.subarray(0, field(v3, 0).at + 4)), 'file_corrupt');
  // A header field kdbxweb doesn't know (it would throw on it).
  const unknown = ws.slice();
  unknown[field(unknown, 7).at - 5] = 13;
  assert.equal(reason(unknown), 'file_corrupt');
  // A KDF parameter with the wrong length for its type.
  assert.equal(reason(withKdfDict(ws, [[0x42, ascii('$UUID'), ARGON2D_UUID], [0x05, ascii('M'), u32(1024)]])), 'file_corrupt');
});

test('a KDF parameter given twice, or under a key that decodes to the same name, cannot hide a hostile value', () => {
  // kdbxweb keeps the last value of a key, and decodes keys as UTF-8 with the BOM dropped; every value is checked.
  const ws = fixture(FILES.whitespace);
  const base = [[0x42, ascii('$UUID'), ARGON2D_UUID], [0x05, ascii('I'), u64(2)], [0x04, ascii('P'), u32(1)], [0x04, ascii('V'), u32(0x13)], [0x42, ascii('S'), new Uint8Array(32)]];
  ok(withKdfDict(ws, [...base, [0x05, ascii('M'), u64(MiB)]]));
  assert.equal(reason(withKdfDict(ws, [...base, [0x05, ascii('M'), u64(MiB)], [0x05, ascii('M'), u64(4096 * MiB)]])), 'argon_mem');
  assert.equal(reason(withKdfDict(ws, [...base, [0x05, ascii('M'), u64(4096 * MiB)], [0x05, ascii('M'), u64(MiB)]])), 'argon_mem');
  const bomM = concat([Uint8Array.of(0xef, 0xbb, 0xbf), ascii('M')]);
  assert.equal(reason(withKdfDict(ws, [...base, [0x05, ascii('M'), u64(MiB)], [0x05, bomM, u64(4096 * MiB)]])), 'argon_mem');
  // Any integer type counts (kdbxweb reads them all as numbers).
  assert.equal(reason(withKdfDict(ws, [...base, [0x04, ascii('M'), u32(0xfffffc00)]])), 'argon_mem');
  assert.equal(reason(withKdfDict(ws, [...base, [0x0d, ascii('M'), u64(4096 * MiB)]])), 'argon_mem');
  // A header field given twice: kdbxweb keeps the last one, so every one is checked.
  const twice = withKdfParam(ws, 'I', 1000);
  const f = field(twice, 11);
  const again = concat([twice.subarray(0, f.at - 5), ws.subarray(field(ws, 11).at - 5, field(ws, 11).at + field(ws, 11).size), twice.subarray(f.at - 5)]);
  assert.equal(reason(again), 'argon_iter');
});

test('not_kdbx and unsupported: other files, KeePass 1 and unknown versions, KDFs, ciphers and compression', () => {
  assert.equal(reason(ascii('hello, this is not a database at all')), 'not_kdbx');
  assert.equal(reason(new Uint8Array(4)), 'not_kdbx');
  assert.equal(reason('not bytes'), 'not_kdbx');
  const ws = fixture(FILES.whitespace);
  const kdb = ws.slice();
  new DataView(kdb.buffer).setUint32(4, 0xb54bfb65, true);
  assert.equal(reason(kdb), 'unsupported');
  for (const [minor, major] of [[0, 5], [2, 4], [2, 3], [0, 2]]) {
    const v = ws.slice();
    new DataView(v.buffer).setUint16(8, minor, true);
    new DataView(v.buffer).setUint16(10, major, true);
    assert.equal(reason(v), 'unsupported', major + '.' + minor);
  }
  const cipher = ws.slice();
  cipher[field(cipher, 2).at] ^= 0xff;
  assert.equal(reason(cipher), 'unsupported');
  const kdf = withKdfDict(ws, [[0x42, ascii('$UUID'), new Uint8Array(16)], [0x05, ascii('M'), u64(MiB)]]);
  assert.equal(reason(kdf), 'unsupported');
  const gz = ws.slice();
  new DataView(gz.buffer).setUint32(field(gz, 3).at, 2, true);
  assert.equal(reason(gz), 'unsupported');
});

test('real files pass, with their version, KDF and cipher', () => {
  for (const c of Object.values(KPXC)) {
    assert.deepEqual(ok(fixture(c.file)), { ok: true, version: c.version, kdf: c.kdf, cipher: c.cipher }, c.file);
  }
  assert.deepEqual(ok(fixture(FILES.whitespace)), { ok: true, version: '4.0', kdf: 'argon2id', cipher: 'chacha20' });
  assert.deepEqual(ok(fixture(FILES.kdbx3)), { ok: true, version: '3.1', kdf: 'aes', cipher: 'aes' });
  assert.deepEqual(ok(fixture(FILES.argon2v10).buffer), { ok: true, version: '4.0', kdf: 'argon2d', cipher: 'aes' });
  // In-cap but slow is the open step's job (timeout and Cancel), not the check's.
  ok(fixture(FILES.slow));
});

test('vault-kdbx-header.js has no eval, inline HTML, storage or logging', () => {
  const src = readFileSync(path('Assets/js/vault-kdbx-header.js'), 'utf8').replace(/^\s*(\/\/|\*|\/\*).*$/gm, '');
  assert.doesNotMatch(src, /eval\(|new Function|WebAssembly|innerHTML|outerHTML|insertAdjacentHTML|localStorage|sessionStorage|indexedDB|console\.|fetch\(/);
});
