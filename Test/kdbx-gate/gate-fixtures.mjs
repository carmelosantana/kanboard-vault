// The export gate's fixtures and what both readers must find in the export (spec: KeePassXC import and export →
// CI gate). Used by run.sh in two steps, and imported by gate.mjs:
//   node gate-fixtures.mjs sources <dir>   writes the KeePass XML sources and the empty KDBX 4.0 seed that
//                                          keepassxc-cli turns into the gate's databases (run.sh, in the container);
//   node gate-fixtures.mjs craft <dir>     writes the broken files from the KeePassXC-written gate-unicode.kdbx:
//                                          truncated, one data block's HMAC flipped, and a hostile KDF header.
// The content: Unicode, tabs and whitespace (fixtures.mjs's KPXC_ENTRIES, with an attachment and history the import
// drops), 10,000 generated entries, and one entry made in Vault itself (EDGE: emoji with a ZWJ sequence, 64 KiB+ notes with tabs, CR LF and emoji, name
// collisions, a TOTP seed).
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { KPXC_ENTRIES, KPXC_EXPECTED, PASSWORD } from '../fixtures/kdbx/fixtures.mjs';
import { keepassXml } from '../fixtures/kdbx/keepass-xml.mjs';
import { withKdfParam, field } from '../fixtures/kdbx/craft.mjs';

export { PASSWORD };
export const FILES = {
  unicode: 'gate-unicode.kdbx', // KDBX 4.0, Argon2id + ChaCha20 (KPXC_ENTRIES), written by KeePassXC
  bulk: 'gate-10000.kdbx', // 10,000 entries, keepassxc-cli import's defaults (KDBX 3.1, AES-KDF)
  truncated: 'gate-truncated.kdbx', // gate-unicode.kdbx cut in the middle of its block stream
  badHmac: 'gate-bad-hmac.kdbx', // gate-unicode.kdbx with one byte of its first data block's HMAC flipped
  hostileKdf: 'gate-hostile-kdf.kdbx', // gate-unicode.kdbx whose Argon2 memory is 2 GiB
};
export const BULK_COUNT = 10000;
// The import groups are renamed to these before the export, so every entry has a unique path for keepassxc-cli show.
export const ROOTS = { unicode: 'Unicode and tabs', bulk: 'Bulk' };
export const EDGE_ROOT = 'Made in Vault';
// Emoji, including the ZWJ sequence 👩‍💻 (woman, ZWJ, laptop): astral code points, so surrogate pairs in JS and in
// PHP's json_encode.
const EMOJI_TITLE = '🔑 Keys 👩\u200d💻';
const EMOJI_PASSWORD = 'edge\tpässword 🔑👩\u200d💻 ';
// Long notes: over 64 KiB of UTF-8 (several HMAC blocks' worth of protected value), lines ending CR LF, with tabs and
// emoji throughout.
const LONG_NOTES = (() => {
  let s = '';
  for (let i = 0; Buffer.byteLength(s, 'utf8') < 66 * 1024; i++) {
    s += `line ${String(i).padStart(5, '0')}\tnotes ✓ 🔑\tand 👩\u200d💻 then 🏳️\u200d🌈 tab\tend\r\n`;
  }
  return s + 'last line 🏁';
})();

// One entry made in Vault (vault/save), with what the export must turn it into.
export const EDGE_PAYLOAD = {
  title: EMOJI_TITLE, username: '\tedge user ', password: EMOJI_PASSWORD, url: 'https://edge.example.test/',
  notes: LONG_NOTES, tags: ['edge', 'gate'], expires_at: 1924992000, otp: 'otpauth://totp/Edge?secret=GEZDGNBVGY3TQOJQ',
  fields: [
    { name: 'Title', value: 'a custom field named Title', protected: false },
    { name: 'otp', value: 'otpauth://totp/Field?secret=MFRGGZDFMZTWQ2LK', protected: false },
    { name: 'Secret ✓', value: '\tsecret value ', protected: true },
  ],
};
const EDGE_EXPECTED = {
  path: [EDGE_ROOT],
  fields: {
    Title: [EMOJI_TITLE, false], UserName: ['\tedge user ', false], Password: [EMOJI_PASSWORD, true], URL: ['https://edge.example.test/', false],
    Notes: [LONG_NOTES, true], 'Title (2)': ['a custom field named Title', false],
    otp: ['otpauth://totp/Field?secret=MFRGGZDFMZTWQ2LK', true], 'Secret ✓': ['\tsecret value ', true],
    'otp (2)': ['otpauth://totp/Edge?secret=GEZDGNBVGY3TQOJQ', true],
  },
  tags: ['edge', 'gate'],
  expires: '2031-01-01T00:00:00Z',
};

const STANDARD = ['Title', 'UserName', 'Password', 'URL', 'Notes'];
const pad = (i) => String(i).padStart(5, '0');
const digest = (s) => createHash('sha256').update(s).digest('base64url').slice(0, 16);

// The 10,000 entries, KPXC_ENTRIES-shaped: ten groups, every third entry one level deeper; tabs, spaces and Unicode in
// values; protected and plain custom fields, tags and expiry on some.
export function bulkEntries() {
  const out = [];
  for (let i = 0; i < BULK_COUNT; i++) {
    const fields = {
      Title: 'Entry ' + pad(i),
      UserName: 'user ' + i + '\t✓',
      Password: 'pw-' + digest('bulk:' + i) + ' ',
      URL: 'https://site' + i + '.example.test/',
      Notes: i % 4 === 0 ? 'note ' + i + '\n\tindented ' : '',
    };
    const protect = ['Password'];
    if (i % 7 === 0) {
      fields['Secret field'] = 's ' + i + '\t';
      protect.push('Secret field');
    }
    if (i % 11 === 0) fields['Plain field'] = 'p ' + i + ' ü';
    out.push({
      path: i % 3 === 0 ? ['Bulk group ' + (i % 10), 'Nested'] : ['Bulk group ' + (i % 10)],
      fields,
      protect,
      tags: i % 5 === 0 ? ['bulk', 't' + (i % 3)] : [],
      ...(i % 13 === 0 ? { expires: '2031-02-03T04:05:06Z' } : {}),
    });
  }
  return out;
}

// What a reader must find for a KeePass source entry after import and export: the same strings (standard ones always
// present), otp protected (the import's rule), attachments and history gone; `path` is its Vault group path.
function roundTrip(e, root, path) {
  const fields = {};
  for (const k of STANDARD) fields[k] = [e.fields[k] ?? '', k === 'Password'];
  for (const [k, v] of Object.entries(e.fields)) {
    if (!STANDARD.includes(k)) fields[k] = [v, e.protect.includes(k) || k === 'otp'];
  }
  return { path: [root, ...path], fields, tags: e.tags, expires: e.expires ?? null };
}

// expected.json for verify.py: every group path (below the export's root group) and every entry.
export function expected() {
  const entries = [];
  for (const e of KPXC_ENTRIES) {
    const vault = KPXC_EXPECTED.find((x) => x.payload.title === e.fields.Title);
    entries.push(roundTrip(e, ROOTS.unicode, vault.path));
  }
  for (const e of bulkEntries()) entries.push(roundTrip(e, ROOTS.bulk, e.path));
  entries.push(EDGE_EXPECTED);
  const groups = new Set();
  for (const e of entries) {
    for (let i = 1; i <= e.path.length; i++) groups.add(JSON.stringify(e.path.slice(0, i)));
  }
  return { groups: [...groups].map((g) => JSON.parse(g)), entries };
}

function sources(dir) {
  mkdirSync(dir, { recursive: true });
  // The empty KDBX 4.0 Argon2id + ChaCha20 seed, from T22's make-seeds.mjs (it also writes T22's entries.xml).
  const seeds = spawnSync(process.execPath, [fileURLToPath(new URL('../fixtures/kdbx/make-seeds.mjs', import.meta.url)), dir], { stdio: 'inherit' });
  if (seeds.status !== 0) throw new Error('make-seeds.mjs failed');
  writeFileSync(join(dir, 'unicode.xml'), keepassXml('Vault export gate', KPXC_ENTRIES, 'vault-gate-unicode:'));
  writeFileSync(join(dir, 'bulk.xml'), keepassXml('Vault export gate', bulkEntries(), 'vault-gate-bulk:'));
}

function craft(dir) {
  const read = (name) => new Uint8Array(readFileSync(join(dir, name)));
  const good = read(FILES.unicode);
  writeFileSync(join(dir, FILES.truncated), good.slice(0, Math.floor(good.length / 2)));
  // KDBX 4: header, its SHA-256 and HMAC (64 bytes), then the blocks; the first block starts with its 32-byte HMAC.
  const end = field(good, 0);
  const bad = good.slice();
  bad[end.at + end.size + 64 + 5] ^= 0x01;
  writeFileSync(join(dir, FILES.badHmac), bad);
  writeFileSync(join(dir, FILES.hostileKdf), withKdfParam(good, 'M', 2 * 1024 * 1024 * 1024));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [step, dir] = process.argv.slice(2);
  if (step === 'sources' && dir) sources(dir);
  else if (step === 'craft' && dir) craft(dir);
  else {
    console.error('usage: node gate-fixtures.mjs sources|craft <dir>');
    process.exit(2);
  }
}
