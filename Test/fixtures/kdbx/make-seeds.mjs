// Step 1 of make-fixtures.sh, run on the host by node (nothing installed): writes into the folder given as the only
// argument
//   entries.xml        a KeePass 2 XML file holding KPXC_ENTRIES, for `keepassxc-cli import`;
//   seed-kdbx3.kdbx    an empty KDBX 3.1 database (AES-KDF, AES-256);
//   seed-argon2d.kdbx  an empty KDBX 4.0 database (Argon2d, AES-256);
//   seed-chacha.kdbx   an empty KDBX 4.0 database (Argon2id, ChaCha20).
// keepassxc-cli has no switch for the format, KDF or cipher, so make-fixtures.sh merges its import into these seeds
// and KeePassXC writes the result with the seed's header settings. The seeds come from the vendored kdbxweb in the
// page-like realm of Test/js/kdbx-page.mjs; they hold no entries and no recycle bin.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadKdbxPage } from '../../js/kdbx-page.mjs';
import { argon2d, argon2id } from '../../../Assets/vendor/noble-hashes/argon2.js';
import { PASSWORD, KPXC_ENTRIES } from './fixtures.mjs';
import { keepassXml } from './keepass-xml.mjs';

const dir = process.argv[2];
if (!dir) throw new Error('usage: node make-seeds.mjs <folder>');
mkdirSync(dir, { recursive: true });

const { kdbxweb } = loadKdbxPage();
const { Kdbx, Credentials, ProtectedValue, Consts, KdbxUuid, VarDictionary, Int64, CryptoEngine } = kdbxweb;
CryptoEngine.setArgon2Impl((password, salt, memory, iterations, length, parallelism, type, version) => {
  const fn = type === CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d;
  return Promise.resolve(fn(new Uint8Array(password), new Uint8Array(salt), { m: memory, t: iterations, p: parallelism, dkLen: length, version }));
});

function emptyDb() {
  const db = Kdbx.create(new Credentials(ProtectedValue.fromString(PASSWORD)), 'Vault import fixture');
  const root = db.getDefaultGroup();
  root.groups.length = 0; // no recycle bin
  db.meta.recycleBinEnabled = false;
  db.meta.recycleBinUuid = undefined;
  return db;
}

async function save(db, name) {
  writeFileSync(join(dir, name), new Uint8Array(await db.save()));
}

const v3 = emptyDb();
v3.setVersion(3);
v3.header.keyEncryptionRounds = 1000;
await save(v3, 'seed-kdbx3.kdbx');

const ad = emptyDb();
ad.setVersion(4);
ad.setKdf(Consts.KdfId.Argon2d);
ad.header.kdfParameters.set('M', VarDictionary.ValueType.UInt64, Int64.from(1024 * 1024));
ad.header.kdfParameters.set('I', VarDictionary.ValueType.UInt64, Int64.from(2));
ad.header.kdfParameters.set('P', VarDictionary.ValueType.UInt32, 1);
await save(ad, 'seed-argon2d.kdbx');

const cc = emptyDb();
cc.setVersion(4);
cc.setKdf(Consts.KdfId.Argon2id);
cc.header.dataCipherUuid = new KdbxUuid(Consts.CipherId.ChaCha20);
cc.header.kdfParameters.set('M', VarDictionary.ValueType.UInt64, Int64.from(1024 * 1024));
cc.header.kdfParameters.set('I', VarDictionary.ValueType.UInt64, Int64.from(2));
cc.header.kdfParameters.set('P', VarDictionary.ValueType.UInt32, 1);
await save(cc, 'seed-chacha.kdbx');

// --- entries.xml ---------------------------------------------------------------------------------------------------
writeFileSync(join(dir, 'entries.xml'), keepassXml('Vault import fixture', KPXC_ENTRIES, 'vault-kpxc:'));
console.log('wrote seeds and entries.xml to', dir);
