// The export gate's browser half (spec: KeePassXC import and export → CI gate, steps 2–4; R68). Zero dependencies
// (Node 22: built-in WebSocket, fetch and child_process). Drives headless Chrome over raw CDP against the throwaway
// Kanboard container run.sh starts (never the :8081 dev stack), through Vault's real pages: Kanboard's CSP, the real
// DOMParser, kdbxweb, the Argon2 module worker, vault-import.js and vault-export.js.
//
//   a new user enrols a vault → imports the gate's KeePassXC files through the import page (Unicode and tabs, read
//   back field for field; 10,000 entries) → the truncated, bad-HMAC and hostile-KDF files are refused with their
//   message and send nothing → the import groups are renamed and one entry is made in Vault → the export page
//   re-proves the passphrase, builds the KDBX 4.0 file and downloads it → no request carries the export password,
//   the export answer is no-store, nothing lands in browser storage, there is no CSP violation, and the export is
//   audited once with the right count.
// It leaves export.kdbx, export-password and expected.json in GATE_WORK for verify.py.
//
// Env: KB_URL (http://localhost:<port>, required), KB_CONTAINER (the throwaway container, required; never kb-suite),
// GATE_WORK (run.sh's work folder, with the gate fixtures), CHROME (default /usr/bin/google-chrome).
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, readdirSync, copyFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { FILES, PASSWORD, ROOTS, EDGE_ROOT, EDGE_PAYLOAD, BULK_COUNT, bulkEntries, expected } from './gate-fixtures.mjs';
import { KPXC_EXPECTED } from '../fixtures/kdbx/fixtures.mjs';

const BASE = process.env.KB_URL || '';
const CONTAINER = process.env.KB_CONTAINER || '';
const WORK = process.env.GATE_WORK || '';
const CHROME = process.env.CHROME || '/usr/bin/google-chrome';
// This script creates users and reads the database: refuse anything but a throwaway local container.
if (!/^http:\/\/localhost:\d+$/.test(BASE) || !CONTAINER || CONTAINER === 'kb-suite' || new URL(BASE).port === '8081' || !WORK) {
  console.error('refusing: KB_URL must be http://localhost:<port> (not 8081), KB_CONTAINER a throwaway container (not kb-suite), GATE_WORK set');
  process.exit(2);
}
const USER = 'vault-kdbx-gate';
const LOGIN = randomBytes(12).toString('base64url');
const PASSPHRASE = 'gate ' + randomBytes(12).toString('base64url') + ' passphrase';
const EXPORT_PASSWORD = 'export ' + randomBytes(12).toString('base64url') + '\tü ';
const page = (controller, action) => `${BASE}/?controller=${controller}&action=${action}&plugin=Vault`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── The container's database (PDO as nginx; the query and its parameters go in on stdin) ──────────────────────────
const PHP = `$in = json_decode(stream_get_contents(STDIN), true);
$p = new PDO('sqlite:/var/www/app/data/db.sqlite');
$p->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$p->exec('PRAGMA foreign_keys = ON');
if (isset($in['hash'])) { $in['params'][] = password_hash($in['hash'], PASSWORD_BCRYPT); }
$s = $p->prepare($in['sql']);
$s->execute($in['params']);
echo json_encode($s->columnCount() ? $s->fetchAll(PDO::FETCH_ASSOC) : []);`;
function sql(query, params = [], hash) {
  const r = spawnSync('docker', ['exec', '-i', '-u', 'nginx', CONTAINER, 'php', '-r', PHP], { input: JSON.stringify({ sql: query, params, ...(hash ? { hash } : {}) }), encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`sql failed: ${r.stderr || r.stdout}`);
  return JSON.parse(r.stdout || '[]');
}
const userId = () => Number(sql('SELECT id FROM users WHERE username = ?', [USER])[0]?.id ?? 0);

let failures = 0;
function check(ok, what) {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${what}`);
  if (!ok) failures++;
}

const profile = mkdtempSync(join(tmpdir(), 'vault-kdbx-gate-'));
const downloads = join(profile, 'downloads');
mkdirSync(downloads);
let chrome = null;
let ws = null;

try {
  // Kanboard migrates on its first request.
  let up = false;
  for (let i = 0; i < 120 && !up; i++) {
    try { up = (await fetch(`${BASE}/?controller=AuthController&action=login`)).status === 200; } catch {}
    if (!up) await sleep(500);
  }
  check(up, `the throwaway Kanboard answers at ${BASE}`);
  sql("INSERT INTO users (username, name, role, is_active, password) VALUES (?, 'Vault KDBX gate', 'app-user', 1, ?)", [USER], LOGIN);
  const uid = userId();
  check(uid > 0, 'gate user created by PDO in the throwaway container');

  chrome = spawn(CHROME, [
    '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check', '--disable-gpu',
    '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-default-apps',
    '--disable-extensions', '--disable-domain-reliability', '--disable-client-side-phishing-detection', '--no-pings',
    '--metrics-recording-only', '--disable-features=OptimizationHints,MediaRouter,Translate,AutofillServerCommunication',
    'about:blank',
  ], { stdio: 'ignore' });
  const portFile = join(profile, 'DevToolsActivePort');
  for (let i = 0; i < 100 && !existsSync(portFile); i++) await sleep(100);
  const [port, wsPath] = readFileSync(portFile, 'utf8').trim().split('\n');
  ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let nextId = 1;
  const pending = new Map();
  const requests = [];
  const responses = [];
  const problems = [];
  let download = null;
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve: ok, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(`${msg.error.message} ${msg.error.data || ''}`)) : ok(msg.result);
    } else if (msg.method === 'Network.requestWillBeSent') {
      requests.push({ url: msg.params.request.url, body: msg.params.request.postData || '' });
    } else if (msg.method === 'Network.responseReceived') {
      responses.push({ url: msg.params.response.url, headers: msg.params.response.headers });
    } else if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
      problems.push(msg.params.entry.text);
    } else if (msg.method === 'Runtime.exceptionThrown') {
      problems.push(JSON.stringify(msg.params.exceptionDetails).slice(0, 300));
    } else if (msg.method === 'Browser.downloadWillBegin') {
      download = { name: msg.params.suggestedFilename, state: 'started' };
    } else if (msg.method === 'Browser.downloadProgress' && download) {
      download.state = msg.params.state;
    }
  };
  const send = (method, params = {}, sessionId) => new Promise((ok, reject) => {
    const id = nextId++;
    pending.set(id, { resolve: ok, reject });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  await send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads, eventsEnabled: true });
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  const s = (m, p) => send(m, p, sessionId);
  for (const d of ['Page', 'Runtime', 'Log', 'Network', 'DOM']) await s(d + '.enable');

  const evaluate = async (expression) => {
    const r = await s('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails).slice(0, 400));
    return r.result.value;
  };
  const waitFor = async (expression, what, ms = 60000) => {
    for (let t = 0; t < ms; t += 200) {
      try { if (await evaluate(expression)) return; } catch {}
      await sleep(200);
    }
    throw new Error(`timed out waiting for ${what} (at ${await evaluate("location.href + ' ' + document.title").catch(() => '?')})`);
  };
  const go = async (url) => {
    await s('Page.navigate', { url });
    await waitFor(`document.readyState === 'complete' && location.href === ${JSON.stringify(url)}`, `load ${url}`);
  };
  const api = async (action, body) => {
    const r = await evaluate(`window.KBVault.api(${JSON.stringify(action)}, ${JSON.stringify(body)})`);
    if (!r || r.ok !== true) throw new Error(`${action}: ${JSON.stringify(r)}`);
    return r;
  };
  const setFiles = async (selector, paths) => {
    const { root } = await s('DOM.getDocument', { depth: 0 });
    const { nodeId } = await s('DOM.querySelector', { nodeId: root.nodeId, selector });
    await s('DOM.setFileInputFiles', { nodeId, files: paths });
  };
  const status = (sel) => evaluate(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); return {text: e.textContent, bad: e.classList.contains('vault-bad'), hidden: e.hidden}; })()`);
  const importFile = async (file, ms = 120000) => {
    await go(page('ImportController', 'index'));
    await setFiles('[data-vault-import-file]', [join(WORK, file)]);
    await evaluate(`(() => { document.querySelector('[data-vault-import-password]').value = ${JSON.stringify(PASSWORD)};
      document.querySelector('[data-vault-import-form]').requestSubmit(); return true; })()`);
    await waitFor(`!document.querySelector('[data-vault-import-submit]').disabled && !document.querySelector('[data-vault-import-status]').hidden
      && document.querySelector('[data-vault-import-progress]').hidden`, `the import of ${file} to end`, ms);
    return status('[data-vault-import-status]');
  };
  const report = () => evaluate(`Object.fromEntries([...document.querySelectorAll('[data-vault-import-report] [data-field]')].map((e) => [e.getAttribute('data-field'), e.textContent]))`);
  const rootIds = async () => (await api('tree', {})).groups.filter((g) => g.parent_id === null).map((g) => g.id);
  // One entry read back through the page's endpoints, as a Vault payload.
  const readEntry = async (id) => {
    const e = (await api('entry', { id })).entry;
    const field = async (f) => (await api('field', { id, field: f })).value;
    const fields = [];
    for (const f of e.fields) fields.push({ name: f.name, value: await field('field:' + f.name), protected: f.protected });
    return { title: e.title, username: e.username, password: await field('password'), url: e.url, notes: await field('notes'), tags: e.tags, expires_at: e.expires_at, otp: await field('otp'), fields };
  };

  // ── Login and enrolment ──────────────────────────────────────────────────────────────────────────────────────
  await go(`${BASE}/?controller=AuthController&action=login`);
  await evaluate(`(() => { const f = document.querySelector('form'); f.querySelector('[name=username]').value = ${JSON.stringify(USER)};
    f.querySelector('[name=password]').value = ${JSON.stringify(LOGIN)}; f.submit(); return true; })()`);
  await waitFor(`!location.href.includes('action=login') && document.readyState === 'complete'`, 'login');
  await go(page('VaultController', 'index'));
  await evaluate(`(() => { document.getElementById('vault-new-passphrase').value = ${JSON.stringify(PASSPHRASE)};
    document.getElementById('vault-new-confirm').value = ${JSON.stringify(PASSPHRASE)};
    document.querySelector('[data-vault-form="enrol"]').requestSubmit(); return true; })()`);
  await waitFor(`(document.getElementById('vault-app') || {getAttribute: () => ''}).getAttribute('data-vault-state') === 'unlocked'`, 'enrolled and unlocked');
  check(await evaluate(`!!document.querySelector('[data-vault-link="export"]')`), 'the vault toolbar links to the export page');

  // ── Import: Unicode and tabs, field for field ────────────────────────────────────────────────────────────────
  let before = await rootIds();
  let st = await importFile(FILES.unicode);
  check(!st.bad && JSON.stringify(await report()) === JSON.stringify({ created: '5', groups: '4', skipped_attachments: '1' }), `${FILES.unicode}: imported ("${st.text}")`);
  const unicodeRoot = (await rootIds()).find((id) => !before.includes(id));
  const tree1 = (await api('tree', {})).groups;
  const byId1 = Object.fromEntries(tree1.map((g) => [g.id, g]));
  const pathOf = (byId, root, id) => {
    const out = [];
    for (let g = byId[id]; g && g.id !== root; g = byId[g.parent_id]) out.unshift(g.name);
    return out;
  };
  const under = (byId, root, g) => g.id === root || (g.parent_id !== null && byId[g.parent_id] !== undefined && under(byId, root, byId[g.parent_id]));
  const got = [];
  for (const g of tree1.filter((x) => under(byId1, unicodeRoot, x))) {
    for (const row of (await api('list', { group_id: g.id, offset: 0 })).entries) got.push({ path: pathOf(byId1, unicodeRoot, g.id), payload: await readEntry(row.id) });
  }
  const k = (x) => JSON.stringify(x.path) + x.payload.title;
  got.sort((a, b) => k(a).localeCompare(k(b)));
  check(JSON.stringify(got) === JSON.stringify([...KPXC_EXPECTED].sort((a, b) => k(a).localeCompare(k(b)))), `${FILES.unicode}: every entry matches field for field (${got.length})`);

  // ── Import: 10,000 entries ───────────────────────────────────────────────────────────────────────────────────
  before = await rootIds();
  const t0 = Date.now();
  st = await importFile(FILES.bulk, 30 * 60000);
  const bulkReport = await report();
  check(!st.bad && bulkReport.created === String(BULK_COUNT) && bulkReport.groups === '20', `${FILES.bulk}: ${bulkReport.created} entries in ${bulkReport.groups} groups, ${Math.round((Date.now() - t0) / 1000)} s ("${st.text}")`);
  const bulkRoot = (await rootIds()).find((id) => !before.includes(id));
  // A sample read back field for field (verify.py checks all 10,000 after the export).
  const tree2 = (await api('tree', {})).groups;
  const byId2 = Object.fromEntries(tree2.map((g) => [g.id, g]));
  const source = Object.fromEntries(bulkEntries().map((e) => [e.fields.Title, e]));
  let sampled = 0;
  let sampleBad = 0;
  for (const g of tree2.filter((x) => x.id !== bulkRoot && under(byId2, bulkRoot, x))) {
    const rows = (await api('list', { group_id: g.id, offset: 0 })).entries;
    for (const row of [rows[0], rows[rows.length - 1]]) {
      const e = source[row.title];
      const custom = Object.keys(e.fields).filter((f) => !['Title', 'UserName', 'Password', 'URL', 'Notes'].includes(f));
      const want = {
        title: e.fields.Title, username: e.fields.UserName, password: e.fields.Password, url: e.fields.URL, notes: e.fields.Notes,
        tags: e.tags, expires_at: e.expires ? Date.parse(e.expires) / 1000 : null, otp: '',
        fields: custom.map((f) => ({ name: f, value: e.fields[f], protected: e.protect.includes(f) })),
      };
      sampled++;
      // KeePassXC writes custom fields sorted by name, so their order is not compared.
      const byName = (p) => ({ ...p, fields: [...p.fields].sort((a, b) => a.name.localeCompare(b.name)) });
      const gotEntry = byName(await readEntry(row.id));
      if (JSON.stringify(pathOf(byId2, bulkRoot, g.id)) !== JSON.stringify(e.path) || JSON.stringify(gotEntry) !== JSON.stringify(byName(want))) {
        sampleBad++;
        console.log('  got:  ' + JSON.stringify(gotEntry).slice(0, 400) + '\n  want: ' + JSON.stringify(byName(want)).slice(0, 400));
      }
    }
  }
  check(sampled === 40 && sampleBad === 0, `${FILES.bulk}: ${sampled} sampled entries match field for field (${sampleBad} differ)`);

  // ── Refused files: the message, and nothing sent ─────────────────────────────────────────────────────────────
  const importPost = (r) => /controller=ImportController&action=(start|batch)|import\/(start|batch)/.test(r.url);
  for (const [file, want] of [[FILES.truncated, /damaged/], [FILES.badHmac, /damaged/], [FILES.hostileKdf, /1 GiB/]]) {
    const sent = requests.filter(importPost).length;
    st = await importFile(file);
    check(st.bad && want.test(st.text) && requests.filter(importPost).length === sent, `${file}: refused ("${st.text.slice(0, 80)}"), nothing sent`);
  }

  // ── Before the export: unique root names, and one entry made in Vault ────────────────────────────────────────
  await go(page('VaultController', 'index'));
  await api('save', { type: 'group', id: unicodeRoot, payload: { name: ROOTS.unicode } });
  await api('save', { type: 'group', id: bulkRoot, payload: { name: ROOTS.bulk } });
  const edgeGroup = (await api('save', { type: 'group', payload: { name: EDGE_ROOT } })).id;
  await api('save', { type: 'entry', group_id: edgeGroup, payload: EDGE_PAYLOAD });

  // ── Export ───────────────────────────────────────────────────────────────────────────────────────────────────
  await go(page('ExportController', 'index'));
  const scripts = await evaluate(`[...document.querySelectorAll('script[src*="plugins/Vault/"]')].map((e) => new URL(e.src).pathname.replace(/^.*\\/Assets\\//, ''))`);
  check(JSON.stringify(scripts) === JSON.stringify(['js/vault.js', 'vendor/kdbxweb/kdbxweb.js', 'js/vault-kdbx.js', 'js/vault-generator.js', 'js/vault-export.js']), `export page scripts: ${scripts.join(', ')}`);
  // Without the export script a submit does nothing visible; stop here rather than wait out the export timeout.
  if (!await evaluate("typeof KBVaultExport === 'object' && typeof KBVaultExport.build === 'function'")) {
    throw new Error('the export script did not load (KBVaultExport is missing)');
  }
  const sentBefore = requests.length;
  const t1 = Date.now();
  await evaluate(`(() => { document.querySelector('[data-vault-export-passphrase]').value = ${JSON.stringify(PASSPHRASE)};
    document.querySelector('[data-vault-export-password]').value = ${JSON.stringify(EXPORT_PASSWORD)};
    document.querySelector('[data-vault-export-confirm]').value = ${JSON.stringify(EXPORT_PASSWORD)};
    document.querySelector('[data-vault-export-form]').requestSubmit(); return true; })()`);
  await waitFor(`!document.querySelector('[data-vault-export-submit]').disabled && !document.querySelector('[data-vault-export-status]').hidden
    && document.querySelector('[data-vault-export-progress]').hidden`, 'the export to end', 15 * 60000);
  st = await status('[data-vault-export-status]');
  for (let i = 0; i < 300 && (!download || download.state !== 'completed'); i++) await sleep(100);
  check(!st.bad && /Exported/.test(st.text) && download && download.state === 'completed', `exported and downloaded in ${Math.round((Date.now() - t1) / 1000)} s ("${st.text}", ${download && download.name})`);
  const file = readdirSync(downloads).find((f) => /^vault-export-\d{4}-\d{2}-\d{2}\.kdbx$/.test(f));
  check(!!file, `the download is ${file}`);
  copyFileSync(join(downloads, file), join(WORK, 'export.kdbx'));
  writeFileSync(join(WORK, 'export-password'), EXPORT_PASSWORD + '\n', { mode: 0o644 });
  writeFileSync(join(WORK, 'expected.json'), JSON.stringify(expected()));

  // ── Hygiene ──────────────────────────────────────────────────────────────────────────────────────────────────
  const exportPosts = requests.slice(sentBefore).filter((r) => /controller=ExportController&action=export(&|$)|vault\/export$/.test(r.url));
  check(exportPosts.length === 1 && /(^|&)include_shared=0(&|$)/.test(exportPosts[0].body) && exportPosts[0].body.includes('csrf_token='), 'one export POST, with the CSRF token and include_shared=0');
  check(requests.every((r) => !(r.url + r.body).includes(EXPORT_PASSWORD) && !(r.url + r.body).includes(encodeURIComponent(EXPORT_PASSWORD)) && !(r.url + r.body).includes(new URLSearchParams({ x: EXPORT_PASSWORD }).toString().slice(2))), `the export password is never sent (${requests.length} requests)`);
  check(requests.every((r) => !r.url.includes('passphrase')), 'no passphrase in any URL');
  const exportResponse = responses.find((r) => /controller=ExportController&action=export(&|$)|vault\/export$/.test(r.url));
  const header = (h, n) => Object.entries(h || {}).find(([k]) => k.toLowerCase() === n)?.[1] || '';
  check(exportResponse && /no-store/.test(header(exportResponse.headers, 'cache-control')) && /frame-ancestors 'none'/.test(header(exportResponse.headers, 'content-security-policy')), `the export answer is no-store and hardened (${exportResponse && header(exportResponse.headers, 'cache-control')})`);
  check(await evaluate(`['passphrase', 'password', 'confirm'].every((s) => document.querySelector('[data-vault-export-' + s + ']').value === '')`), 'the export inputs are cleared');
  const storage = await evaluate('JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])');
  check(!/Mail|Entry 0|pass word|otpauth|kdbx|export/.test(storage), `nothing from the export in browser storage (${storage.slice(0, 120)})`);
  const csp = problems.filter((p) => /Content Security Policy|Refused to/i.test(p));
  check(csp.length === 0, `no CSP violation${csp.length ? ': ' + csp.join(' | ') : ''}`);
  const audit = sql("SELECT COUNT(*) AS n, SUM(count) AS c FROM vault_audit WHERE actor_user_id = ? AND action = 'export'", [uid])[0];
  check(Number(audit.n) === 1 && Number(audit.c) === BULK_COUNT + 6, `export audited once, count ${audit.c}`);
  if (problems.length) console.log('console errors:', problems.join(' | ').slice(0, 800));
} catch (e) {
  failures++;
  console.error(`ERROR ${e.stack || e}`);
} finally {
  try { ws?.close(); } catch {}
  chrome?.kill('SIGKILL');
  try { rmSync(profile, { recursive: true, force: true }); } catch {}
}
console.log(failures === 0 ? 'gate browser: PASS' : `gate browser: FAIL (${failures})`);
process.exit(failures === 0 ? 0 : 1);
