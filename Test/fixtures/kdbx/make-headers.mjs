// Writes the crafted files listed in fixtures.mjs (CRAFTED), one per kdbx-header reason that needs a file. Run by
// make-fixtures.sh after the KeePassXC fixtures exist; run on its own with: node Vault/Test/fixtures/kdbx/make-headers.mjs
// Each hostile header is a valid file with one header value overwritten in place. The header hash no longer matches,
// which doesn't matter: Vault's pre-check refuses the file before kdbxweb reads it.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { loadKdbxPage } from '../../js/kdbx-page.mjs';
import { argon2d } from '../../../Assets/vendor/noble-hashes/argon2.js';
import { PASSWORD, FILES, KPXC, CRAFTED, CR_SECRET_HEX } from './fixtures.mjs';
import { field, dictValue, setUint64 } from './craft.mjs';

const file = (name) => fileURLToPath(new URL('./' + name, import.meta.url));
const read = (name) => new Uint8Array(readFileSync(file(name)));
const write = (name, bytes) => writeFileSync(file(name), bytes);

const OVER_ROUNDS = 100000001;

// KDBX 3.1: TransformRounds (field 6) past 10^8.
const v3 = read(KPXC.kdbx3.file).slice();
setUint64(v3, field(v3, 6).at, OVER_ROUNDS);
write(CRAFTED.aesRounds3, v3);

// KDBX 4.0 with AES-KDF: R past 10^8. kdbxweb writes the file (1000 rounds), then R is overwritten.
const { kdbxweb } = loadKdbxPage();
const { Kdbx, Credentials, ProtectedValue, Consts, VarDictionary, Int64, CryptoEngine } = kdbxweb;
CryptoEngine.setArgon2Impl((password, salt, memory, iterations, length, parallelism, type, version) =>
  Promise.resolve(argon2d(new Uint8Array(password), new Uint8Array(salt), { m: memory, t: iterations, p: parallelism, dkLen: length, version })));
const aes4 = Kdbx.create(new Credentials(ProtectedValue.fromString(PASSWORD)), 'Vault fixture');
aes4.setVersion(4);
aes4.setKdf(Consts.KdfId.Aes);
aes4.header.kdfParameters.set('R', VarDictionary.ValueType.UInt64, Int64.from(1000));
const a4 = new Uint8Array(await aes4.save());
const r = dictValue(a4, field(a4, 11).at, 'R');
setUint64(a4, r.at, OVER_ROUNDS);
write(CRAFTED.aesRounds4, a4);

// KDBX 4.0 whose cipher (field 2) is Twofish (UUID ad68f29f-576f-4bb9-a36a-d47af965346c).
const tf = read(FILES.whitespace).slice();
tf.set([0xad, 0x68, 0xf2, 0x9f, 0x57, 0x6f, 0x4b, 0xb9, 0xa3, 0x6a, 0xd4, 0x7a, 0xf9, 0x65, 0x34, 0x6c], field(tf, 2).at);
write(CRAFTED.twofish, tf);

// Broken framing: cut inside the HMAC block stream, and 100 bytes after the final block.
const ws = read(FILES.whitespace);
write(CRAFTED.truncated, ws.slice(0, ws.length - 50));
const tr = new Uint8Array(ws.length + 100);
tr.set(ws);
tr.fill(0x41, ws.length);
write(CRAFTED.trailing, tr);

// A challenge-response database, in KeePassXC's scheme (the HMAC-SHA1 response to the KDF salt is part of the
// key), with a simulated YubiKey. Its header is an ordinary KDBX 4 header.
const secret = Buffer.from(CR_SECRET_HEX, 'hex');
const respond = (challenge) => Promise.resolve(new Uint8Array(createHmac('sha1', secret).update(new Uint8Array(challenge)).digest()));
const cr = Kdbx.create(new Credentials(ProtectedValue.fromString(PASSWORD), null, respond), 'Vault fixture');
cr.setVersion(4);
cr.setKdf(Consts.KdfId.Argon2d);
cr.header.kdfParameters.set('M', VarDictionary.ValueType.UInt64, Int64.from(1024 * 1024));
cr.header.kdfParameters.set('I', VarDictionary.ValueType.UInt64, Int64.from(2));
const e = cr.createEntry(cr.getDefaultGroup());
e.fields.set('Title', 'Needs the YubiKey');
write(CRAFTED.challengeResponse, new Uint8Array(await cr.save()));

console.log('wrote', Object.values(CRAFTED).join(', '));
