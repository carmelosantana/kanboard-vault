// Writes the KDBX fixtures listed in fixtures.mjs into this folder, with the vendored kdbxweb in the page-like realm
// of Test/js/kdbx-page.mjs (no GUI, nothing installed). Argon2 here is the vendored @noble/hashes, called directly.
// The files are committed; re-running makes new salts and keys, so the bytes change but the contents do not.
// Run from the repo root: node Vault/Test/fixtures/kdbx/make-fixtures.mjs
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadKdbxPage } from '../../js/kdbx-page.mjs';
import { argon2d, argon2id } from '../../../Assets/vendor/noble-hashes/argon2.js';
import { PASSWORD, WHITESPACE_ENTRY, PROTECTED_FIELDS, FILES } from './fixtures.mjs';

const out = (name) => fileURLToPath(new URL('./' + name, import.meta.url));
const { kdbxweb } = loadKdbxPage();
const { Kdbx, Credentials, ProtectedValue, Consts, KdbxUuid, VarDictionary, Int64, CryptoEngine } = kdbxweb;

const realArgon2 = (password, salt, memory, iterations, length, parallelism, type, version) => {
  const fn = type === CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d;
  return Promise.resolve(fn(new Uint8Array(password), new Uint8Array(salt), { m: memory, t: iterations, p: parallelism, dkLen: length, version }));
};
// For the hostile headers only: a stand-in so writing them does not run the hostile KDF.
const standInArgon2 = (password, salt, memory, iterations, length) => Promise.resolve(new Uint8Array(length).fill(0x5a));

function creds(keyFile = null) {
  return new Credentials(ProtectedValue.fromString(PASSWORD), keyFile);
}

function addEntry(db, fields) {
  const entry = db.createEntry(db.getDefaultGroup());
  for (const [k, v] of Object.entries(fields)) {
    entry.fields.set(k, PROTECTED_FIELDS.includes(k) ? ProtectedValue.fromString(v) : v);
  }
}

function argonDb(kdf, cipher, { m = 1024 * 1024, t = 2, p = 1 } = {}, keyFile = null) {
  const db = Kdbx.create(creds(keyFile), 'Vault fixture');
  db.setVersion(4);
  db.setKdf(kdf);
  db.header.dataCipherUuid = new KdbxUuid(cipher);
  const params = db.header.kdfParameters;
  params.set('M', VarDictionary.ValueType.UInt64, Int64.from(m));
  params.set('I', VarDictionary.ValueType.UInt64, Int64.from(t));
  params.set('P', VarDictionary.ValueType.UInt32, p);
  return db;
}

async function save(db, name) {
  const bytes = new Uint8Array(await db.save());
  writeFileSync(out(name), bytes);
  return bytes;
}

CryptoEngine.setArgon2Impl(realArgon2);

const ws = argonDb(Consts.KdfId.Argon2id, Consts.CipherId.ChaCha20);
addEntry(ws, WHITESPACE_ENTRY);
const wsBytes = await save(ws, FILES.whitespace);

// The final block of the HMAC block stream is its last 36 bytes: HMAC (32) then a zero uint32 length.
const tail = wsBytes.subarray(wsBytes.length - 4);
if (tail.some((b) => b !== 0)) throw new Error('the file does not end with an empty final block');
const tampered = wsBytes.slice();
tampered[tampered.length - 36] ^= 0x01;
writeFileSync(out(FILES.tamperedFinalBlock), tampered);

const v3 = Kdbx.create(creds(), 'Vault fixture');
v3.setVersion(3);
v3.header.keyEncryptionRounds = 1000;
addEntry(v3, WHITESPACE_ENTRY);
await save(v3, FILES.kdbx3);

const keyFile = await Credentials.createRandomKeyFile(2);
writeFileSync(out(FILES.keyfileKey), keyFile);
const kf = argonDb(Consts.KdfId.Argon2d, Consts.CipherId.Aes, {}, keyFile);
addEntry(kf, { Title: 'Keyed', UserName: 'key user' });
await save(kf, FILES.keyfile);

const v10 = argonDb(Consts.KdfId.Argon2d, Consts.CipherId.Aes);
v10.header.kdfParameters.set('V', VarDictionary.ValueType.UInt32, 0x10);
addEntry(v10, { Title: 'Version 0x10' });
await save(v10, FILES.argon2v10);

CryptoEngine.setArgon2Impl(standInArgon2);
for (const [name, params] of [
  [FILES.hostileM, { m: 2 * 1024 * 1024 * 1024 }],
  [FILES.hostileT, { t: 1000000 }],
  [FILES.hostileP, { p: 9 }],
  [FILES.slow, { m: 64 * 1024 * 1024, t: 100 }],
]) {
  const db = argonDb(Consts.KdfId.Argon2d, Consts.CipherId.Aes, params);
  addEntry(db, { Title: 'Hostile' });
  await save(db, name);
}
console.log('wrote', Object.values(FILES).join(', '));
