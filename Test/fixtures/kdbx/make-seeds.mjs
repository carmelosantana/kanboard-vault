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
import { createHash } from 'node:crypto';
import { loadKdbxPage } from '../../js/kdbx-page.mjs';
import { argon2d, argon2id } from '../../../Assets/vendor/noble-hashes/argon2.js';
import { PASSWORD, KPXC_ENTRIES } from './fixtures.mjs';

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
// Fixed UUIDs, so the XML (and what the import holds) is the same on every run.
const uuid = (label) => createHash('sha256').update('vault-kpxc:' + label).digest().subarray(0, 16).toString('base64');
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const TIME = '2026-11-19T00:00:00Z';

function times(expires) {
  return '<Times><CreationTime>' + TIME + '</CreationTime><LastModificationTime>' + TIME + '</LastModificationTime>'
    + '<LastAccessTime>' + TIME + '</LastAccessTime><ExpiryTime>' + (expires || TIME) + '</ExpiryTime>'
    + '<Expires>' + (expires ? 'True' : 'False') + '</Expires><UsageCount>0</UsageCount>'
    + '<LocationChanged>' + TIME + '</LocationChanged></Times>';
}

function strings(fields, protect) {
  return Object.entries(fields).map(([k, v]) => '<String><Key>' + esc(k) + '</Key><Value'
    + (protect.includes(k) ? ' ProtectInMemory="True"' : '') + '>' + esc(v) + '</Value></String>').join('');
}

const binaries = [];
function entryXml(e, label) {
  let x = '<Entry><UUID>' + uuid('entry:' + label) + '</UUID><IconID>0</IconID><Tags>' + esc(e.tags.join(';')) + '</Tags>'
    + times(e.expires) + strings(e.fields, e.protect);
  for (const [name, text] of Object.entries(e.attachments || {})) {
    binaries.push(Buffer.from(text, 'utf8').toString('base64'));
    x += '<Binary><Key>' + esc(name) + '</Key><Value Ref="' + (binaries.length - 1) + '"/></Binary>';
  }
  if (e.history && e.history.length) {
    x += '<History>' + e.history.map((h, i) => '<Entry><UUID>' + uuid('entry:' + label) + '</UUID><IconID>0</IconID>'
      + times() + strings(h, ['Password']) + '</Entry>').join('') + '</History>';
  }
  return x + '</Entry>';
}

// The group tree: a group is keyed by its path, plus `group` for siblings of the same name.
const tree = { name: 'Vault import fixture', key: 'root', entries: [], groups: [] };
KPXC_ENTRIES.forEach((e, i) => {
  let node = tree;
  e.path.forEach((name, depth) => {
    const key = node.key + '/' + name + (depth === e.path.length - 1 && e.group !== undefined ? '#' + e.group : '');
    let child = node.groups.find((g) => g.key === key);
    if (!child) {
      child = { name, key, entries: [], groups: [] };
      node.groups.push(child);
    }
    node = child;
  });
  node.entries.push(entryXml(e, String(i)));
});

function groupXml(g) {
  return '<Group><UUID>' + uuid('group:' + g.key) + '</UUID><Name>' + esc(g.name) + '</Name><Notes></Notes><IconID>48</IconID>'
    + times() + '<IsExpanded>True</IsExpanded>' + g.entries.join('') + g.groups.map(groupXml).join('') + '</Group>';
}

const xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<KeePassFile><Meta><Generator>Vault fixture</Generator>'
  + '<DatabaseName>Vault import fixture</DatabaseName><RecycleBinEnabled>False</RecycleBinEnabled>'
  + '<Binaries>' + binaries.map((b, i) => '<Binary ID="' + i + '" Compressed="False">' + b + '</Binary>').join('') + '</Binaries>'
  + '</Meta><Root>' + groupXml(tree) + '<DeletedObjects/></Root></KeePassFile>\n';
writeFileSync(join(dir, 'entries.xml'), xml);
console.log('wrote seeds and entries.xml to', dir);
