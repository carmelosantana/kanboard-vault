// node --test Vault/Test/js — vault-import.js, the import page's logic (spec: KeePassXC import and export → Import):
// pre-check, open, mapping, the refusals before upload, batching and the upload protocol. The real KeePassXC fixtures
// (Test/fixtures/kdbx/make-fixtures.sh) go through the real page scripts in kdbx-page.mjs's realm; the page's DOM
// wiring runs against the real template in fake-dom.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadKdbxPage } from './kdbx-page.mjs';
import { Doc, parseInto, template, flush } from './fake-dom.mjs';
import { mapAll } from '../fixtures/kdbx/make-mapped.mjs';
import { PASSWORD, WRONG_PASSWORD, FILES, KPXC, KPXC_EXPECTED, KPXC_SKIPPED_ATTACHMENTS, MAPPED, CRAFTED } from '../fixtures/kdbx/fixtures.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const fixture = (name) => new Uint8Array(readFileSync(path('Test/fixtures/kdbx/' + name)));
const plain = (v) => JSON.parse(JSON.stringify(v));
const flat = (batches) => batches.flatMap((b) => b.entries.map((payload) => ({ path: b.group_path, payload })));

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (e) => {
    assert.equal(e && e.code, code, 'error code (message: ' + (e && e.message) + ')');
    return true;
  });
}

test('mapping field for field: the four KeePassXC fixtures map to the same Vault entries', async () => {
  // KDBX 3.1 AES-KDF, 4.0 Argon2d + AES, 4.0 Argon2id + ChaCha20, and a password plus key file: title, username,
  // password, URL, notes, tags, expiry and custom fields with their protection; otp becomes a protected field;
  // the attachment is counted and skipped; history is dropped; same-named sibling groups stay apart.
  const { importer } = loadKdbxPage({ importer: true });
  for (const [name, c] of Object.entries(KPXC)) {
    const p = await importer.open(fixture(c.file), PASSWORD, c.keyFile ? fixture(c.keyFile) : null);
    assert.deepEqual(plain(flat(p.batches)), KPXC_EXPECTED, name);
    assert.equal(p.total, KPXC_EXPECTED.length, name);
    assert.equal(p.skippedAttachments, KPXC_SKIPPED_ATTACHMENTS, name);
    assert.equal(p.groups, 4, name + ': Servers, Servers/Linux, Dup, Dup (2)');
  }
  // ImportControllerTest posts kpxc-mapped.json; it must be what the page builds today.
  assert.deepEqual(await mapAll(), JSON.parse(readFileSync(path('Test/fixtures/kdbx/' + MAPPED), 'utf8')));
});

// Final review M2: KeePassXC keeps deleted entries in its Recycle Bin group (db.meta.recycleBinUuid). Importing it
// brought deleted credentials back into a store the user shares from. The bin and everything below it is skipped and
// counted (its entries), as export already leaves the bin out. Kills: the bin imported; a group merely named
// "Recycle Bin" skipped; the count missing from the report.
test('the KeePass Recycle Bin is skipped and its entries counted', async () => {
  const { importer, kdbxweb } = loadKdbxPage({ importer: true });
  const db = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('x')), 'Bin test');
  const root = db.getDefaultGroup();
  const keep = db.createEntry(root);
  keep.fields.set('Title', 'Kept');
  const decoy = db.createGroup(root, 'Recycle Bin');
  db.createEntry(decoy).fields.set('Title', 'In a group only named like the bin');
  db.meta.recycleBinEnabled = true;
  db.createRecycleBin();
  const bin = db.getGroup(db.meta.recycleBinUuid);
  assert.ok(bin, 'the database has a recycle bin');
  db.createEntry(bin).fields.set('Title', 'Deleted one');
  db.createEntry(db.createGroup(bin, 'Deleted group')).fields.set('Title', 'Deleted two');
  const p = importer.prepare(db);
  const titles = flat(p.batches).map((e) => e.payload.title).sort();
  assert.deepEqual(plain(titles), ['In a group only named like the bin', 'Kept']);
  assert.equal(p.total, 2);
  assert.equal(p.groups, 1, 'the decoy only; the bin and its child are not made');
  assert.equal(p.skippedRecycled, 2);
});

test('the pre-check refuses before kdbxweb or the worker runs', async () => {
  const { importer, log } = loadKdbxPage({ importer: true });
  await rejectsWith(importer.open(fixture(CRAFTED.twofish), PASSWORD), 'twofish');
  await rejectsWith(importer.open(fixture(FILES.hostileM), PASSWORD), 'argon_mem');
  await rejectsWith(importer.open(fixture(CRAFTED.aesRounds3), PASSWORD), 'aes_rounds');
  await rejectsWith(importer.open(fixture(CRAFTED.trailing), PASSWORD), 'file_corrupt');
  assert.equal(log.started.length, 0, 'no Argon2 worker was started');
});

test('yubikey_cr: a challenge-response file opened without its YubiKey says what to do', async () => {
  const { importer } = loadKdbxPage({ importer: true });
  await rejectsWith(importer.open(fixture(CRAFTED.challengeResponse), PASSWORD), 'invalid_key');
  assert.deepEqual(plain(importer.messageKeys('invalid_key')), ['import_invalid_key', 'import_yubikey_cr']);
  assert.deepEqual(plain(importer.messageKeys('twofish')), ['import_twofish']);
});

test('the file and key-file bytes are zeroed when the open ends, either way', async () => {
  const { importer } = loadKdbxPage({ importer: true });
  const c = KPXC.keyfile;
  const bytes = fixture(c.file);
  const key = fixture(c.keyFile);
  await importer.open(bytes, PASSWORD, key);
  assert.ok(bytes.every((b) => b === 0), 'file bytes zeroed');
  assert.ok(key.every((b) => b === 0), 'key bytes zeroed');
  const bytes2 = fixture(c.file);
  const key2 = fixture(c.keyFile);
  await rejectsWith(importer.open(bytes2, WRONG_PASSWORD, key2), 'invalid_key');
  assert.ok(bytes2.every((b) => b === 0) && key2.every((b) => b === 0), 'zeroed on failure too');
});

test('over 20 000 entries, or an entry over 256 KB, is refused before anything is sent', async () => {
  const { importer, kdbxweb } = loadKdbxPage({ importer: true });
  assert.deepEqual(plain(importer.LIMITS), { entries: 20000, entryBytes: 262144, batchEntries: 100, batchBytes: 2097152 });
  const db = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('x')), 'Big');
  const root = db.getDefaultGroup();
  root.groups.length = 0;
  for (let i = 0; i < 20000; i++) db.createEntry(root).fields.set('Title', 'e' + i);
  assert.equal(importer.prepare(db).total, 20000);
  db.createEntry(root).fields.set('Title', 'one too many');
  assert.throws(() => importer.prepare(db), (e) => e.code === 'import_limit');

  const one = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString('x')), 'One');
  one.getDefaultGroup().groups.length = 0;
  const e = one.createEntry(one.getDefaultGroup());
  // The payload JSON with empty values is this long; fill notes to exactly 262 144 bytes, then one more.
  const empty = JSON.stringify({ title: '', username: '', password: '', url: '', notes: '', tags: [], expires_at: null, otp: '', fields: [] }).length;
  e.fields.set('Notes', 'n'.repeat(262144 - empty));
  assert.equal(importer.prepare(one).total, 1);
  e.fields.set('Notes', 'n'.repeat(262144 - empty + 1));
  assert.throws(() => importer.prepare(one), (x) => x.code === 'import_limit');
  // Multi-byte characters count as their UTF-8 bytes.
  e.fields.set('Notes', 'é'.repeat((262144 - empty) / 2 + 1));
  assert.throws(() => importer.prepare(one), (x) => x.code === 'import_limit');
});

test('batches: at most 100 entries and about 2 MiB each, tree order, and an empty group still gets one', () => {
  const { importer } = loadKdbxPage({ importer: true });
  const p = (title, notes = '') => ({ title, username: '', password: '', url: '', notes, tags: [], expires_at: null, otp: '', fields: [] });
  const entries = [];
  for (let i = 0; i < 250; i++) entries.push({ path: ['A'], payload: p('a' + i) });
  entries.push({ path: [], payload: p('root') });
  const big = 'x'.repeat(600 * 1024);
  for (let i = 0; i < 5; i++) entries.push({ path: ['B'], payload: p('b' + i, big) });
  const out = plain(importer.batches({ groups: [[], ['A'], ['B'], ['Empty']], entries }));
  assert.deepEqual(out.map((b) => [b.group_path.join('/'), b.entries.length]), [['', 1], ['A', 100], ['A', 100], ['A', 50], ['B', 3], ['B', 2], ['Empty', 0]]);
  assert.deepEqual(out[1].entries[0].title, 'a0');
  assert.deepEqual(out[3].entries[49].title, 'a249');
});

test('upload: start, then each batch in order; it stops at a refusal or a cancel and says how many were stored', async () => {
  const { importer } = loadKdbxPage({ importer: true });
  const prepared = () => ({ total: 3, batches: [{ group_path: [], entries: [{ title: 'a' }, { title: 'b' }] }, { group_path: ['G'], entries: [{ title: 'c' }] }] });
  const calls = [];
  const api = (answers) => (action, body) => {
    calls.push([action, plain(body)]);
    return Promise.resolve(answers.shift());
  };
  const seen = [];
  const r = await importer.upload(prepared(), api([{ ok: true, import_id: 7 }, { ok: true, created: 2 }, { ok: true, created: 1 }]), (n) => seen.push(n));
  assert.deepEqual(plain(r), { created: 3 });
  assert.deepEqual(seen, [2, 3]);
  assert.deepEqual(calls, [
    ['import_start', { total: 3 }],
    ['import_batch', { import_id: 7, group_path: [], entries: [{ title: 'a' }, { title: 'b' }] }],
    ['import_batch', { import_id: 7, group_path: ['G'], entries: [{ title: 'c' }] }],
  ]);

  calls.length = 0;
  await assert.rejects(importer.upload(prepared(), api([{ ok: false, reason: 'import_limit' }])), (e) => e.code === 'import_limit' && e.created === 0);
  assert.equal(calls.length, 1);
  await assert.rejects(importer.upload(prepared(), api([{ ok: true, import_id: 7 }, { ok: true, created: 2 }, { ok: false, reason: 'payload_too_large' }])), (e) => e.code === 'payload_too_large' && e.created === 2);
  await assert.rejects(importer.upload(prepared(), api([{ ok: true, import_id: 7 }, { ok: false }])), (e) => e.code === 'failed');

  // Cancel between batches: nothing more is sent.
  calls.length = 0;
  const slow = (action, body) => {
    calls.push(action);
    if (action === 'import_batch') importer.cancel();
    return Promise.resolve(action === 'import_start' ? { ok: true, import_id: 1 } : { ok: true, created: 2 });
  };
  await assert.rejects(importer.upload(prepared(), slow), (e) => e.code === 'cancelled' && e.created === 2);
  assert.deepEqual(calls, ['import_start', 'import_batch']);
});

// --- The page ------------------------------------------------------------------------------------------------------

function loadImportPage(answers) {
  const page = loadKdbxPage({ importer: false, vault: true });
  const { win } = page;
  const doc = new Doc();
  parseInto(doc, doc.body, '<div id="vault-app" data-messages="{}"></div>' + template('import'));
  doc.getElementById('vault-app').setAttribute('data-messages', JSON.stringify({
    failed: 'F', import_opening: 'Opening', import_uploading: 'Uploading', import_done: 'Done', import_invalid_key: 'Wrong key.',
    import_yubikey_cr: 'YubiKey?', import_twofish: 'Twofish!', import_partial: '{count} stored.',
  }));
  const calls = [];
  const stored = [];
  win.KBVault = { api: (action, body) => { calls.push([action, plain(body)]); return Promise.resolve(answers.shift()); } };
  win.localStorage = { setItem: (k) => stored.push(k) };
  win.sessionStorage = win.localStorage;
  win.document = doc;
  page.run = () => {
    const vm = page.win;
    vm.eval(readFileSync(path('Assets/js/vault-kdbx-header.js'), 'utf8'));
    vm.eval(readFileSync(path('Assets/js/vault-import.js'), 'utf8'));
  };
  return { ...page, doc, calls, stored };
}

function setFile(input, bytes) {
  input.files = bytes ? [{ arrayBuffer: () => Promise.resolve(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)) }] : [];
  input.value = bytes ? 'C:\\fakepath\\private.kdbx' : '';
}

async function settle(cond) {
  for (let i = 0; i < 2000 && !cond(); i++) await new Promise((r) => setTimeout(r, 5));
}

test('the page imports, reports, and clears the password and files; nothing goes to storage or a URL', async () => {
  const p = loadImportPage([{ ok: true, import_id: 3 }, ...Array(5).fill({ ok: true, created: 1 })]);
  p.run();
  const q = (s) => p.doc.querySelector(s);
  // No input has a name, so a native submit (no JS) carries nothing.
  assert.equal(q('[data-vault-import]').querySelectorAll('input[name]').length, 0);
  assert.equal(q('[data-vault-import]').querySelectorAll('input').length, 3);
  setFile(q('[data-vault-import-file]'), fixture(KPXC.argon2id.file));
  q('[data-vault-import-password]').value = PASSWORD;
  q('[data-vault-import-form]').dispatch('submit', { preventDefault() {} });
  await settle(() => !q('[data-vault-import-report]').hidden || q('[data-vault-import-status]').classList.contains('vault-bad'));
  assert.equal(q('[data-vault-import-status]').textContent, 'Done');
  assert.equal(q('[data-vault-import-report]').querySelector('[data-field="created"]').textContent, '5');
  assert.equal(q('[data-vault-import-report]').querySelector('[data-field="groups"]').textContent, '4');
  assert.equal(q('[data-vault-import-report]').querySelector('[data-field="skipped_attachments"]').textContent, '1');
  assert.equal(q('[data-vault-import-report]').querySelector('[data-field="skipped_recycled"]').textContent, '0');
  assert.equal(q('[data-vault-import-password]').value, '');
  assert.equal(q('[data-vault-import-file]').value, '');
  assert.equal(p.calls[0][0], 'import_start');
  assert.equal(p.calls.length, 6);
  // The file name never leaves the page.
  assert.ok(!JSON.stringify(p.calls).includes('private'));
  assert.deepEqual(p.stored, []);
  assert.equal(q('[data-vault-import-submit]').disabled, false);
});

test('the page shows the explicit message for a refused file, and the YubiKey hint for a wrong key', async () => {
  const p = loadImportPage([]);
  p.run();
  const q = (s) => p.doc.querySelector(s);
  const status = q('[data-vault-import-status]');
  const submitWith = async (bytes, pw) => {
    status.classList.remove('vault-bad');
    setFile(q('[data-vault-import-file]'), bytes);
    q('[data-vault-import-password]').value = pw;
    q('[data-vault-import-form]').dispatch('submit', { preventDefault() {} });
    await settle(() => status.classList.contains('vault-bad'));
    await flush();
  };
  await submitWith(fixture(CRAFTED.twofish), PASSWORD);
  assert.equal(status.textContent, 'Twofish!');
  await submitWith(fixture(CRAFTED.challengeResponse), PASSWORD);
  assert.equal(status.textContent, 'Wrong key. YubiKey?');
  assert.equal(q('[data-vault-import-password]').value, '');
  assert.equal(p.calls.length, 0, 'nothing was sent');
});

test('vault-import.js has no eval, inline HTML, storage or logging', () => {
  const src = readFileSync(path('Assets/js/vault-import.js'), 'utf8').replace(/^\s*(\/\/|\*|\/\*).*$/gm, '');
  assert.doesNotMatch(src, /eval\(|new Function|WebAssembly|innerHTML|outerHTML|insertAdjacentHTML|localStorage|sessionStorage|indexedDB|console\.|fetch\(|location/);
});
