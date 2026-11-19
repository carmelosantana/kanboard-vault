// node --test Vault/Test/js — vault-export.js, the export page (spec: KeePassXC import and export → Export): the
// KDBX 4.0 file it builds (Argon2id, ChaCha20), field for field, read back with kdbxweb in kdbx-page.mjs's realm with
// the real Argon2 worker; cancel and worker failures (T21 M6); and the page's DOM wiring against the real template in
// fake-dom.mjs (fresh re-auth, download, clearing). The CI gate (Test/kdbx-gate/run.sh) reads the same files with
// keepassxc-cli and pykeepass.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadKdbxPage } from './kdbx-page.mjs';
import { Doc, parseInto, template, flush } from './fake-dom.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const plain = (v) => JSON.parse(JSON.stringify(v));
const PASSWORD = 'export\tpässword ✓ ';
const FAST = { memory: 1024 * 1024, iterations: 2, parallelism: 1 };

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (e) => {
    assert.equal(e && e.code, code, 'error code (message: ' + (e && e.message) + ')');
    return true;
  });
}

// A full entry as vault/export answers it (EntryPayload's canonical keys, plus group_id).
function entry(groupId, over = {}) {
  return { group_id: groupId, title: '', username: '', password: '', url: '', notes: '', tags: [], expires_at: null, otp: '', fields: [], ...over };
}

// The answer of vault/export: nesting, same-named siblings, a child whose id is lower than its parent's, a shared
// group and an entry shared on its own (group_id null).
const DATA = () => ({
  ok: true,
  groups: [
    { id: 10, parent_id: null, name: 'Mail ✓', shared: false },
    { id: 11, parent_id: 10, name: 'Sub', shared: false },
    { id: 12, parent_id: null, name: 'Dup', shared: false },
    { id: 13, parent_id: null, name: 'Dup', shared: false },
    { id: 5, parent_id: 13, name: 'Child', shared: false },
    { id: 20, parent_id: null, name: 'Ops', shared: true },
  ],
  entries: [
    entry(10, {
      title: 'Mail', username: '\tmail user ', password: 'Mail\tpass word ', url: 'https://mail.example.test/login',
      notes: 'line one\n\tline two  ', tags: ['mail', 'work'], expires_at: 1893553445,
      otp: 'otpauth://totp/Example:mail?secret=JBSWY3DPEHPK3PXP&issuer=Example',
      fields: [{ name: 'Plain custom', value: 'plain\tvalue ', protected: false }, { name: 'Secret custom', value: ' secret value\t', protected: true }],
    }),
    entry(11, { title: 'Ünïcødé ✓ host', username: 'root', password: 'pässwörd ✓ 🔑 Keys 👩‍💻' }),
    entry(12, { title: 'In the first Dup' }),
    entry(13, { title: 'In the second Dup' }),
    entry(5, { title: 'In the child' }),
    entry(20, { title: 'Shared in a group', password: 'shared pw' }),
    entry(null, { title: 'Shared alone', username: 'ana' }),
  ],
  skipped: 0,
});

// Everything a KDBX reader sees: each group by path, each entry by path with its strings ([value, protected]), tags
// and expiry.
function readBack(kdbxweb, db) {
  const groups = [];
  const entries = [];
  const walk = (g, path) => {
    for (const e of g.entries) {
      const fields = {};
      for (const [k, v] of e.fields) fields[k] = v instanceof kdbxweb.ProtectedValue ? [v.getText(), true] : [v, false];
      entries.push({ path, fields, tags: e.tags.slice(), expires: e.times.expires ? e.times.expiryTime.getTime() : null });
    }
    for (const sub of g.groups) {
      groups.push([...path, sub.name]);
      walk(sub, [...path, sub.name]);
    }
  };
  walk(db.getDefaultGroup(), []);
  return { groups, entries };
}

// kdbxweb reads an empty protected value back as a plain empty string.
const STANDARD = (over = {}) => ({ Title: ['', false], UserName: ['', false], Password: ['', false], URL: ['', false], Notes: ['', false], ...over });

test('build writes KDBX 4.0 with Argon2id and ChaCha20, which Vault can import again', async () => {
  const { exporter, vault, kdbxweb, win } = loadKdbxPage({ importer: true, exporter: true });
  assert.deepEqual(plain(exporter.KDF), { memory: 64 * 1024 * 1024, iterations: 8, parallelism: 2 });
  const bytes = await exporter.build(DATA(), PASSWORD);
  assert.ok(bytes instanceof win.Uint8Array);
  const h = new DataView(bytes.buffer, bytes.byteOffset, 12);
  assert.deepEqual([h.getUint32(0, true), h.getUint32(4, true), h.getUint16(8, true), h.getUint16(10, true)], [0x9aa2d903, 0xb54bfb67, 0, 4], 'KDBX signature, version 4.0');
  assert.deepEqual(plain(win.KBVaultKdbxHeader.check(bytes)), { ok: true, version: '4.0', kdf: 'argon2id', cipher: 'chacha20' });
  const db = await vault.load(bytes, PASSWORD);
  const kdf = db.header.kdfParameters;
  assert.equal(kdbxweb.ByteUtils.bytesToBase64(kdf.get('$UUID')), kdbxweb.Consts.KdfId.Argon2id);
  assert.equal(db.header.dataCipherUuid.toString(), kdbxweb.Consts.CipherId.ChaCha20);
  assert.deepEqual([kdf.get('M').value, kdf.get('I').value, kdf.get('P')], [64 * 1024 * 1024, 8, 2]);
  assert.equal(db.header.compression, kdbxweb.Consts.CompressionAlgorithm.GZip);
  assert.equal(db.meta.recycleBinEnabled, false, 'no recycle bin group');
  await rejectsWith(vault.load(bytes, PASSWORD + 'x'), 'invalid_key');
});

test('every field and group survives the round trip', async () => {
  const { exporter, vault, kdbxweb } = loadKdbxPage({ exporter: true });
  Object.assign(exporter.KDF, FAST);
  exporter.sharedGroupName = 'Shared with me';
  const db = await vault.load(await exporter.build(DATA(), PASSWORD), PASSWORD);
  assert.equal(db.getDefaultGroup().name, 'Vault export');
  const got = plain(readBack(kdbxweb, db));
  assert.deepEqual(got.groups, [['Mail ✓'], ['Mail ✓', 'Sub'], ['Dup'], ['Dup'], ['Dup', 'Child'], ['Shared with me'], ['Shared with me', 'Ops']]);
  assert.deepEqual(got.entries, [
    { path: ['Mail ✓'], tags: ['mail', 'work'], expires: 1893553445000, fields: STANDARD({
      Title: ['Mail', false], UserName: ['\tmail user ', false], Password: ['Mail\tpass word ', true], URL: ['https://mail.example.test/login', false],
      Notes: ['line one\n\tline two  ', false], 'Plain custom': ['plain\tvalue ', false], 'Secret custom': [' secret value\t', true],
      otp: ['otpauth://totp/Example:mail?secret=JBSWY3DPEHPK3PXP&issuer=Example', true],
    }) },
    { path: ['Mail ✓', 'Sub'], tags: [], expires: null, fields: STANDARD({ Title: ['Ünïcødé ✓ host', false], UserName: ['root', false], Password: ['pässwörd ✓ 🔑 Keys 👩‍💻', true] }) },
    { path: ['Dup'], tags: [], expires: null, fields: STANDARD({ Title: ['In the first Dup', false] }) },
    { path: ['Dup'], tags: [], expires: null, fields: STANDARD({ Title: ['In the second Dup', false] }) },
    { path: ['Dup', 'Child'], tags: [], expires: null, fields: STANDARD({ Title: ['In the child', false] }) },
    { path: ['Shared with me'], tags: [], expires: null, fields: STANDARD({ Title: ['Shared alone', false], UserName: ['ana', false] }) },
    { path: ['Shared with me', 'Ops'], tags: [], expires: null, fields: STANDARD({ Title: ['Shared in a group', false], Password: ['shared pw', true] }) },
  ]);
  // The second Dup holds the child: same-named siblings stay apart.
  assert.equal(db.getDefaultGroup().groups[2].groups.length, 1);
  // Tags are written as KeePassXC writes them, joined by ';' (pykeepass doesn't trim the space kdbxweb's ', ' adds).
  const raw = await kdbxweb.Kdbx.load((await exporter.build(DATA(), PASSWORD)).buffer, new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(PASSWORD)), { preserveXml: true });
  assert.deepEqual([...kdbxweb.XmlUtils.serialize(raw.xml).matchAll(/<Tags>([^<]*)<\/Tags>/g)].map((m) => m[1]).filter(Boolean), ['mail;work']);

  // Without shared items there is no Shared with me group.
  const own = DATA();
  own.groups = own.groups.filter((g) => !g.shared);
  own.entries = own.entries.filter((e) => e.group_id !== null && e.group_id !== 20);
  const ownDb = await vault.load(await exporter.build(own, PASSWORD), PASSWORD);
  assert.ok(!readBack(kdbxweb, ownDb).groups.some((p) => p[0] === 'Shared with me'));
});

test('name collisions and characters XML cannot carry keep every value', async () => {
  const { exporter, vault, kdbxweb } = loadKdbxPage({ exporter: true });
  Object.assign(exporter.KDF, FAST);
  const data = {
    groups: [{ id: 1, parent_id: null, name: 'G\u0001roup\r', shared: false }],
    entries: [entry(1, {
      title: 'Edge', username: 'x\u0001y', url: 'https://e.test/\uFFFE', notes: 'line\r\nnext', otp: 'payload otp', tags: ['t\u0003', 'ok'],
      fields: [
        { name: 'Title', value: 'a custom Title', protected: false },
        { name: 'otp', value: 'field otp', protected: false },
        { name: 'Title (2)', value: 'taken', protected: false },
        { name: 'N\u0002', value: 'v', protected: false },
        { name: 'Password', value: 'second password', protected: true },
      ],
    })],
  };
  const db = await vault.load(await exporter.build(data, PASSWORD), PASSWORD);
  const got = plain(readBack(kdbxweb, db));
  assert.deepEqual(got.groups, [['G\uFFFDroup\uFFFD']], 'a name keeps its place; what XML cannot carry becomes U+FFFD');
  assert.deepEqual(got.entries[0].tags, ['t\uFFFD', 'ok']);
  // Values XML text can't carry exactly (a control character, CR) are written protected, so their bytes survive;
  // U+FFFE, which no XML can carry, becomes U+FFFD.
  assert.deepEqual(got.entries[0].fields, {
    Title: ['Edge', false], UserName: ['x\u0001y', true], Password: ['', false], URL: ['https://e.test/\uFFFD', false], Notes: ['line\r\nnext', true],
    'Title (3)': ['a custom Title', false], otp: ['field otp', true], 'Title (2)': ['taken', false], 'N\uFFFD': ['v', false],
    'Password (2)': ['second password', true], 'otp (2)': ['payload otp', true],
  });
});

test('cancel stops the export and terminates its Argon2 worker', async () => {
  const { exporter, log } = loadKdbxPage({ exporter: true });
  Object.assign(exporter.KDF, { memory: 256 * 1024 * 1024, iterations: 50, parallelism: 1 });
  const building = exporter.build(DATA(), PASSWORD);
  for (let i = 0; i < 500 && log.started.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
  assert.equal(log.started.length, 1, 'the Argon2 worker started');
  const t0 = Date.now();
  exporter.cancel();
  await rejectsWith(building, 'cancelled');
  assert.ok(Date.now() - t0 < 1000, 'cancel is prompt');
  assert.equal(log.terminated, 1);
  // Cancel before the KDF starts: no worker at all.
  const { exporter: ex2, log: log2 } = loadKdbxPage({ exporter: true });
  const early = ex2.build(DATA(), PASSWORD);
  ex2.cancel();
  await rejectsWith(early, 'cancelled');
  assert.equal(log2.started.length, 0);
});

test('a worker message that cannot be read fails the job (onmessageerror) and the worker is terminated', async () => {
  const made = [];
  class BadMessageWorker {
    constructor() { this.terminated = false; made.push(this); }
    postMessage() { setTimeout(() => this.onmessageerror && this.onmessageerror({ data: null }), 1); }
    terminate() { this.terminated = true; }
  }
  const { exporter } = loadKdbxPage({ exporter: true, worker: BadMessageWorker });
  Object.assign(exporter.KDF, FAST);
  await rejectsWith(exporter.build(DATA(), PASSWORD), 'worker_failed');
  assert.equal(made.length, 1);
  assert.equal(made[0].terminated, true);
});

test('build refuses what it cannot write', async () => {
  const { exporter } = loadKdbxPage({ exporter: true });
  await rejectsWith(exporter.build(DATA(), ''), 'bad_input');
  await rejectsWith(exporter.build({ groups: [], entries: 'x' }, PASSWORD), 'bad_input');
  await rejectsWith(exporter.build({ groups: [{ id: 1, parent_id: 2, name: 'a', shared: false }, { id: 2, parent_id: 1, name: 'b', shared: false }], entries: [] }, PASSWORD), 'bad_input');
});

// ---- The page ----------------------------------------------------------------------------------------------------

const MESSAGES = {
  failed: 'F', unlock_failed: 'Unlock failed.', passphrase_mismatch: 'Mismatch.', export_password_required: 'Choose a password.',
  export_checking: 'Checking', export_building: 'Building', export_done: 'Done', export_skipped: '{count} skipped.',
  export_cancelled: 'Cancelled.', shared_entries: 'Shared with me',
};

function loadExportPage(answers, { hw = false } = {}) {
  const page = loadKdbxPage({ vault: true });
  const { win } = page;
  const doc = new Doc();
  parseInto(doc, doc.body, '<div id="vault-app" data-messages="{}"></div>' + template('export'));
  doc.getElementById('vault-app').setAttribute('data-messages', JSON.stringify(MESSAGES));
  const form = doc.querySelector('[data-vault-export-form]');
  if (hw) form.setAttribute('data-vault-hw', '1'); else form.removeAttribute('data-vault-hw');
  const calls = [];
  const stored = [];
  const blobs = [];
  const urls = { made: [], revoked: [] };
  const anchors = [];
  const sent = [];
  win.KBVault = { api: (action, body) => { calls.push([action, plain(body)]); const a = answers.shift(); sent.push(a); return a instanceof Error ? Promise.reject(a) : Promise.resolve(a); } };
  win.KBVaultWebAuthn = { assertion: (purpose) => { calls.push(['assertion', purpose]); return Promise.resolve('{"assertion":"wire"}'); } };
  win.localStorage = { setItem: (k) => stored.push(k) };
  win.sessionStorage = win.localStorage;
  win.Blob = class { constructor(parts, opts) { this.bytes = new Uint8Array(parts[0]); this.type = opts && opts.type; this.parts = parts; blobs.push(this); } };
  win.URL.createObjectURL = (b) => { urls.made.push(b); return 'blob:vault/' + urls.made.length; };
  win.URL.revokeObjectURL = (u) => urls.revoked.push(u);
  const create = doc.createElement.bind(doc);
  doc.createElement = (tag) => { const el = create(tag); if (tag === 'a') anchors.push(el); return el; };
  win.document = doc;
  page.run = () => {
    page.win.eval(readFileSync(path('Assets/js/vault-export.js'), 'utf8'));
    Object.assign(page.win.KBVaultExport.KDF, FAST);
  };
  return { ...page, doc, calls, stored, blobs, urls, anchors, sent };
}

async function settle(cond) {
  for (let i = 0; i < 2000 && !cond(); i++) await new Promise((r) => setTimeout(r, 5));
}

const fill = (q, { passphrase = 'my vault passphrase', password = PASSWORD, confirm = password, shared = false } = {}) => {
  q('[data-vault-export-passphrase]').value = passphrase;
  q('[data-vault-export-password]').value = password;
  q('[data-vault-export-confirm]').value = confirm;
  q('[data-vault-export-shared]').checked = shared;
  q('[data-vault-export-form]').dispatch('submit', { preventDefault() {} });
};

test('the page re-proves the passphrase, builds and downloads the file, then clears everything', async () => {
  const p = loadExportPage([DATA()]);
  p.run();
  const q = (s) => p.doc.querySelector(s);
  // No input has a name and the form no action, so a native submit carries nothing.
  assert.equal(q('[data-vault-export]').querySelectorAll('input[name]').length, 0);
  assert.equal(q('[data-vault-export-form]').getAttribute('action'), null);
  assert.equal(q('[data-vault-export-passphrase]').getAttribute('autocomplete'), 'current-password');
  // The T13 generator is offered for the export password.
  assert.ok(q('[data-vault-generator]'), 'the generator');
  assert.equal(q('[data-vault-generator]').getAttribute('data-vault-gen-target'), q('[data-vault-export-password]').id);
  assert.equal(q('[data-vault-generator]').getAttribute('data-vault-gen-confirm'), q('[data-vault-export-confirm]').id);

  fill(q, { shared: true });
  await settle(() => p.urls.revoked.length > 0 || q('[data-vault-export-status]').classList.contains('vault-bad'));
  assert.equal(q('[data-vault-export-status]').textContent, 'Done', q('[data-vault-export-status]').textContent);
  assert.deepEqual(p.calls, [['export', { passphrase: 'my vault passphrase', include_shared: '1' }]]);
  // One download: a .kdbx Blob through an <a download>, the object URL revoked afterwards.
  assert.equal(p.blobs.length, 1);
  assert.equal(p.anchors.length, 1);
  assert.match(p.anchors[0].getAttribute('download'), /^vault-export-\d{4}-\d{2}-\d{2}\.kdbx$/);
  assert.equal(p.anchors[0].getAttribute('href'), 'blob:vault/1');
  assert.equal(p.anchors[0].parentNode, null, 'the link is removed again');
  assert.deepEqual(p.urls.revoked, ['blob:vault/1']);
  const db = await p.vault.load(p.blobs[0].bytes, PASSWORD);
  assert.equal(readBack(p.kdbxweb, db).entries.length, 7, 'the file opens with the export password');
  // The page's own copy of the file and of the decrypted answer are cleared; no input keeps a secret.
  assert.ok(new Uint8Array(p.blobs[0].parts[0]).every((b) => b === 0), 'the file bytes handed to the Blob are zeroed');
  assert.equal(p.sent[0].entries.length, 0, 'the decrypted entries are dropped');
  assert.equal(p.sent[0].groups.length, 0);
  for (const s of ['passphrase', 'password', 'confirm']) assert.equal(q('[data-vault-export-' + s + ']').value, '', s + ' cleared');
  assert.equal(q('[data-vault-export-report]').querySelector('[data-field="entries"]').textContent, '7');
  assert.deepEqual(p.stored, []);
  assert.equal(q('[data-vault-export-submit]').disabled, false);
});

test('Cancel while the server is still answering drops the answer: no file is built or downloaded', async () => {
  let release;
  const pending = new Promise((r) => { release = r; });
  const p = loadExportPage([pending]);
  p.run();
  const q = (s) => p.doc.querySelector(s);
  const status = q('[data-vault-export-status]');
  fill(q);
  await flush();
  assert.equal(status.textContent, 'Checking');
  assert.equal(q('[data-vault-export-cancel]').hidden, false, 'Cancel is offered while the server answers');
  q('[data-vault-export-cancel]').click();
  const answer = DATA();
  release(answer);
  await settle(() => status.classList.contains('vault-bad') || p.blobs.length > 0);
  await flush();
  assert.equal(status.textContent, 'Cancelled.');
  assert.equal(p.blobs.length, 0, 'no Blob');
  assert.equal(p.anchors.length, 0, 'no download link');
  assert.equal(answer.entries.length, 0, 'the decrypted answer is dropped');
  assert.equal(q('[data-vault-export-submit]').disabled, false);
  assert.equal(q('[data-vault-export-cancel]').hidden, true);

  // The next export is not cancelled by the earlier click.
  const p2 = loadExportPage([DATA()]);
  p2.run();
  const q2 = (s) => p2.doc.querySelector(s);
  q2('[data-vault-export-cancel]').click();
  fill(q2);
  await settle(() => p2.urls.revoked.length > 0 || q2('[data-vault-export-status]').classList.contains('vault-bad'));
  assert.equal(q2('[data-vault-export-status]').textContent, 'Done');
});

test('the page asks a hardware key for a fresh assertion when the user has one', async () => {
  const p = loadExportPage([DATA()], { hw: true });
  p.run();
  const q = (s) => p.doc.querySelector(s);
  fill(q);
  await settle(() => p.urls.revoked.length > 0 || q('[data-vault-export-status]').classList.contains('vault-bad'));
  assert.deepEqual(p.calls, [['assertion', 'ceremony'], ['export', { passphrase: 'my vault passphrase', include_shared: '0', assertion: '{"assertion":"wire"}' }]]);
});

test('the page refuses empty or mismatched export passwords before sending anything, and shows a refusal', async () => {
  const p = loadExportPage([{ ok: false, reason: 'unlock_failed' }]);
  p.run();
  const q = (s) => p.doc.querySelector(s);
  const status = q('[data-vault-export-status]');
  fill(q, { password: '', confirm: '' });
  await flush();
  assert.equal(status.textContent, 'Choose a password.');
  fill(q, { password: 'one', confirm: 'two' });
  await flush();
  assert.equal(status.textContent, 'Mismatch.');
  assert.deepEqual(p.calls, [], 'nothing was sent');
  for (const s of ['passphrase', 'password', 'confirm']) assert.equal(q('[data-vault-export-' + s + ']').value, '', s + ' cleared');

  fill(q);
  await settle(() => status.classList.contains('vault-bad') && p.calls.length === 1);
  await flush();
  assert.equal(status.textContent, 'Unlock failed.');
  assert.equal(p.blobs.length, 0, 'nothing built');
  assert.equal(q('[data-vault-export-passphrase]').value, '');
});

test('the page reports entries the server could not decrypt', async () => {
  const data = DATA();
  data.skipped = 2;
  const p = loadExportPage([data]);
  p.run();
  const q = (s) => p.doc.querySelector(s);
  fill(q);
  await settle(() => p.urls.revoked.length > 0 || q('[data-vault-export-status]').classList.contains('vault-bad'));
  assert.equal(q('[data-vault-export-status]').textContent, 'Done 2 skipped.');
});

test('vault-export.js has no eval, inline HTML, storage or logging', () => {
  const src = readFileSync(path('Assets/js/vault-export.js'), 'utf8').replace(/^\s*(\/\/|\*|\/\*).*$/gm, '');
  assert.doesNotMatch(src, /eval\(|new Function|WebAssembly|innerHTML|outerHTML|insertAdjacentHTML|localStorage|sessionStorage|indexedDB|console\.|fetch\(|location/);
});
