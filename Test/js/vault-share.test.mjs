// node --test Vault/Test/js — the sharing dialog, revoke, the activity view and group rename (spec: UI → The sharing
// dialog; Audit → Who sees what), run against the real templates in the fake DOM (fake-dom.mjs), where innerHTML,
// outerHTML and insertAdjacentHTML throw.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadPage, flush } from './fake-dom.mjs';

const SRC = readFileSync(fileURLToPath(new URL('../../Assets/js/vault-share.js', import.meta.url)), 'utf8');
const XSS = '<img src=x onerror=alert(1)>';
const GROUP = { id: 7, parent_id: null, permission: 'owner', shared_by: null, name: 'Infra' };

// A page whose tree holds GROUP; answers[action] is an answer or a function of the request body.
function page(answers = {}, opts = {}) {
  const p = loadPage({
    ...opts,
    api: (action, body) => {
      if (action === 'tree') return { ok: true, groups: [GROUP], shared_entries: false };
      if (action === 'list') return { ok: true, entries: [], next_offset: null };
      const a = answers[action];
      return typeof a === 'function' ? a(body) : a || { ok: true };
    },
  });
  return p;
}

const q = (doc, sel) => doc.querySelector(sel);
const shareButton = (doc) => q(doc, '[data-vault-action="share-group"]');

async function openGroupShare(p) {
  await flush();
  q(p.doc, '[data-group-id="7"]').click();
  await flush();
  shareButton(p.doc).click();
  await flush();
}

test('vault-share.js writes no HTML and runs no inline code', () => {
  assert.doesNotMatch(SRC, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
});

test('the share dialog lists grantees and grants as text, and an agent gets Read only', async () => {
  const sharing = {
    ok: true,
    candidates: [{ id: 3, name: XSS, kind: 'human' }, { id: 9, name: 'ops.bot', kind: 'agent' }],
    grants: [{ grantee_id: 4, name: XSS, kind: 'human', permission: 'edit', expires_at: null }],
    covered_entries: 3,
  };
  const p = page({ sharing });
  await openGroupShare(p);
  const { doc, calls } = p;
  const dialog = q(doc, '[data-vault-share]');
  assert.equal(dialog.hidden, false);
  assert.deepEqual(calls.filter((c) => c.action === 'sharing').map((c) => c.body), [{ type: 'group', id: '7' }]);
  assert.equal(q(dialog, '[data-vault-share-label]').textContent, 'Infra');
  const options = q(dialog, '[data-vault-share-grantee]').options;
  assert.deepEqual(options.map((o) => [o.value, o.textContent]), [['3', XSS], ['9', 'ops.bot (' + dialog.getAttribute('data-msg-agent') + ')']]);
  const grants = q(dialog, '[data-vault-share-grants]');
  assert.ok(grants.textContent.includes(XSS), 'the grantee name is text');
  assert.equal(grants.querySelectorAll('img').length, 0);
  assert.match(q(dialog, '[data-vault-share-covered]').textContent, /3/);
  assert.equal(q(dialog, '[data-vault-share-covered]').hidden, false);

  const select = q(dialog, '[data-vault-share-grantee]');
  const perm = q(dialog, '[data-vault-share-perm]');
  perm.value = 'edit';
  select.value = '9';
  select.dispatch('change');
  assert.equal(perm.value, 'read', 'an agent is switched to Read');
  assert.equal(perm.querySelector('option[value="edit"]').disabled, true);
  select.value = '3';
  select.dispatch('change');
  assert.equal(perm.querySelector('option[value="edit"]').disabled, false);
});

test('sharing a group asks for confirmation with the covered count before granting', async () => {
  const grants = [];
  const confirms = [];
  let answer = true;
  const p = page({
    sharing: { ok: true, candidates: [{ id: 3, name: 'bob', kind: 'human' }], grants: [], covered_entries: 3 },
    grant: (body) => {
      grants.push({ ...body });
      return body.confirm ? { ok: true, covered_entries: 3 } : { ok: true, confirm_required: true, covered_entries: 3 };
    },
  }, { confirm: (m) => { confirms.push(m); return answer; } });
  await openGroupShare(p);
  const dialog = q(p.doc, '[data-vault-share]');
  q(dialog, '[data-vault-share-perm]').value = 'edit';
  q(dialog, '[data-vault-share-expires]').value = '2030-01-02T03:04';
  q(dialog, 'form').dispatch('submit');
  await flush(10);
  const at = Math.floor(new Date('2030-01-02T03:04').getTime() / 1000);
  assert.deepEqual(grants, [
    { type: 'group', id: '7', grantee_id: '3', perm: 'edit', expires_at: at },
    { type: 'group', id: '7', grantee_id: '3', perm: 'edit', expires_at: at, confirm: 1 },
  ]);
  assert.equal(confirms.length, 1);
  assert.match(confirms[0], /\b3\b/, 'the server count is in the confirmation');

  // Declined: no second request.
  answer = false;
  q(dialog, '[data-vault-share-expires]').value = '';
  q(dialog, 'form').dispatch('submit');
  await flush(10);
  assert.equal(grants.length, 3);
  assert.equal(grants[2].confirm, undefined);
  assert.equal(grants[2].expires_at, '', 'no expiry is sent empty');
});

test('revoking says to rotate the secrets', async () => {
  const revokes = [];
  const p = page({
    sharing: { ok: true, candidates: [], grants: [{ grantee_id: 4, name: 'carol', kind: 'human', permission: 'read', expires_at: 1900000000 }], covered_entries: 1 },
    revoke: (body) => { revokes.push({ ...body }); return { ok: true, suggest_rotate: true }; },
  });
  await openGroupShare(p);
  const dialog = q(p.doc, '[data-vault-share]');
  const rotate = q(dialog, '[data-vault-share-rotate]');
  assert.equal(rotate.hidden, true);
  q(dialog, '[data-vault-revoke]').click();
  await flush(10);
  assert.deepEqual(revokes, [{ type: 'group', id: '7', grantee_id: '4' }]);
  assert.equal(rotate.hidden, false, 'the rotation suggestion shows');
  assert.ok(rotate.textContent.length > 0);
});

test('a late sharing answer never renders into another object\'s dialog', async () => {
  let release;
  const held = new Promise((r) => { release = r; });
  const p = page({
    sharing: (body) => body.type === 'group'
      ? held.then(() => ({ ok: true, candidates: [{ id: 3, name: 'for the group', kind: 'human' }], grants: [], covered_entries: 2 }))
      : { ok: true, candidates: [{ id: 5, name: 'for the entry', kind: 'human' }], grants: [] },
    entry: { ok: true, entry: { id: 11, group_id: 7, permission: 'owner', title: 'E', secrets: {}, fields: [] } },
  });
  await flush();
  q(p.doc, '[data-group-id="7"]').click();
  await flush();
  shareButton(p.doc).click();
  // The entry's dialog opens before the group's answer arrives.
  p.window.KBVaultShare.open('entry', '11', 'E');
  await flush();
  release();
  await flush(10);
  const dialog = q(p.doc, '[data-vault-share]');
  assert.deepEqual(q(dialog, '[data-vault-share-grantee]').options.map((o) => o.textContent), ['for the entry']);
  assert.equal(q(dialog, '[data-vault-share-covered]').hidden, true, 'no group count on an entry');
  assert.equal(q(dialog, '[data-vault-share-label]').textContent, 'E');
});

test('the activity view pages with More and renders rows as text', async () => {
  const pages = {
    0: { ok: true, rows: [{ id: 9, created_at: 1800000000, action: 'read', actor_kind: 'human', via: 'ui', actor: XSS, target: null, object_type: 'entry', object_id: 3, title: XSS, count: null, ip_trunc: '203.0.113.0/24', ua_family: null }], next_offset: 50 },
    50: { ok: true, rows: [{ id: 2, created_at: 1700000000, action: 'grant', actor_kind: 'human', via: 'ui', actor: 'alice', target: 'bob', object_type: 'group', object_id: 7, title: null, count: null, ip_trunc: null, ua_family: null }], next_offset: null },
  };
  const offsets = [];
  const p = page({ activity: (body) => { offsets.push(body.offset); return pages[body.offset]; } });
  await flush();
  const view = q(p.doc, '[data-vault-activity]');
  assert.equal(view.hidden, true);
  q(p.doc, '[data-vault-action="activity"]').click();
  await flush(10);
  assert.equal(view.hidden, false);
  const rows = q(view, '[data-vault-activity-rows]');
  assert.equal(rows.querySelectorAll('tr').length, 1);
  assert.ok(rows.textContent.includes(XSS));
  assert.equal(rows.querySelectorAll('img').length, 0);
  const more = q(view, '[data-vault-action="activity-more"]');
  assert.equal(more.hidden, false);
  more.click();
  await flush(10);
  assert.deepEqual(offsets, [0, 50]);
  assert.equal(rows.querySelectorAll('tr').length, 2);
  assert.ok(rows.textContent.includes('#7'), 'an object without a title shows its id');
  assert.equal(more.hidden, true, 'no More on the last page');
});

test('rename group sends the new name through save', async () => {
  const saves = [];
  const p = page({ save: (body) => { saves.push({ ...body }); return { ok: true, id: 7 }; } }, { prompt: () => '  Infra 2 ' });
  await flush();
  q(p.doc, '[data-group-id="7"]').click();
  await flush();
  const rename = q(p.doc, '[data-vault-action="rename-group"]');
  assert.equal(rename.hidden, false, 'shown to the owner');
  rename.click();
  await flush(10);
  assert.deepEqual(JSON.parse(JSON.stringify(saves)), [{ type: 'group', id: 7, payload: { name: 'Infra 2' } }]);
  assert.ok(p.calls.filter((c) => c.action === 'tree').length >= 2, 'the tree reloads');

  // Read and edit grantees aren't offered it (R50: renaming is the owner's).
  for (const permission of ['read', 'edit']) {
    const ro = loadPage({
      api: (action) => action === 'tree' ? { ok: true, groups: [{ ...GROUP, permission, shared_by: 'Ana' }], shared_entries: false } : { ok: true, entries: [], next_offset: null },
    });
    await flush();
    q(ro.doc, '[data-group-id="7"]').click();
    await flush();
    assert.equal(q(ro.doc, '[data-vault-action="rename-group"]').hidden, true, permission);
    assert.equal(shareButton(ro.doc).hidden, true, permission + ' can\'t share');
  }
});

// ---- Server (spec amendment: The sharing dialog shares with Server) -------------------------------------------------

const ENTRY = { ok: true, entry: { id: 11, group_id: 7, permission: 'owner', title: 'E', secrets: {}, fields: [] } };
const plain = (o) => JSON.parse(JSON.stringify(o));

async function openEntryShare(sharing, more = {}, opts = {}) {
  const p = page({ sharing, entry: ENTRY, ...more }, opts);
  await flush();
  p.window.KBVaultShare.open('entry', '11', 'E');
  await flush(10);
  return { p, dialog: q(p.doc, '[data-vault-share]') };
}

test('the Server section is hidden unless sharing says Server is available', async () => {
  for (const server of [undefined, { available: false }]) {
    const { dialog } = await openEntryShare({ ok: true, candidates: [], grants: [], ...(server ? { server } : {}) });
    assert.equal(q(dialog, '[data-vault-share-server]').hidden, true, JSON.stringify(server));
  }
  const { p, dialog } = await openEntryShare((body) => ({ ok: true, candidates: [], grants: [], server: { available: body.type === 'entry' } }));
  assert.equal(q(dialog, '[data-vault-share-server]').hidden, false);
  // Opened again for a group, where the answer says no: hidden again.
  p.window.KBVaultShare.open('group', '7', 'Infra');
  await flush(10);
  assert.equal(q(dialog, '[data-vault-share-server]').hidden, true);
});

test('sharing with Server posts the consumers, the checked fields and the custom fields', async () => {
  const posts = [];
  const { p, dialog } = await openEntryShare(
    { ok: true, candidates: [], grants: [], server: { available: true } },
    { grant_server: (body) => { posts.push(plain(body)); return { ok: true }; } },
  );
  const server = q(dialog, '[data-vault-share-server]');
  q(server, '[data-vault-server-consumers]').value = 'CveHunter, Lifeboat';
  q(server, '[data-vault-server-field][value="password"]').checked = true;
  q(server, '[data-vault-server-custom]').value = 'API_TOKEN';
  q(server, 'form').dispatch('submit');
  await flush(10);
  assert.deepEqual(posts, [{ id: '11', consumers: 'CveHunter, Lifeboat', 'fields[]': ['password'], custom_fields: 'API_TOKEN' }]);
  assert.equal(p.calls.filter((c) => c.action === 'sharing').length, 2, 'the dialog reloads');

  // Rates go only when given.
  q(server, '[data-vault-server-rate]').value = '30';
  q(server, '[data-vault-server-burst]').value = '5';
  q(server, 'form').dispatch('submit');
  await flush(10);
  assert.deepEqual(posts[1], { id: '11', consumers: 'CveHunter, Lifeboat', 'fields[]': ['password'], custom_fields: 'API_TOKEN', rate_per_hour: '30', rate_burst: '5' });
});

test('a refused Server share shows the reason', async () => {
  const { p, dialog } = await openEntryShare(
    { ok: true, candidates: [], grants: [], server: { available: true } },
    { grant_server: () => ({ ok: false, reason: 'server_off' }) },
  );
  q(dialog, '[data-vault-server-consumers]').value = 'CveHunter';
  q(q(dialog, '[data-vault-share-server]'), 'form').dispatch('submit');
  await flush(10);
  assert.equal(q(dialog, '[data-vault-share-status]').textContent, 'Something went wrong.');
  assert.equal(p.calls.filter((c) => c.action === 'sharing').length, 1, 'no reload');
});

test('a Server grant renders its consumers and fields as text only', async () => {
  const { dialog } = await openEntryShare({
    ok: true, candidates: [], server: { available: true },
    grants: [{ grantee_id: -1, name: 'Server', kind: 'server', permission: 'read', consumers: [XSS, 'Lifeboat'], fields: ['password', XSS, null], rate_per_hour: 60, rate_burst: 10 }],
  });
  const grants = q(dialog, '[data-vault-share-grants]');
  assert.equal(grants.querySelectorAll('img').length, 0);
  const text = grants.textContent;
  assert.ok(text.includes(XSS + ', Lifeboat'), 'the consumers');
  assert.ok(text.includes('password, ' + XSS + ', ' + dialog.getAttribute('data-msg-field-hidden')), 'the fields; an unknown one by label');
  assert.ok(text.includes(dialog.getAttribute('data-msg-server')));
  assert.ok(q(grants, '[data-vault-revoke="-1"]'), 'a revoke button for Server');
});

test('revoking the Server grant says to rotate the secret at its provider', async () => {
  const revokes = [];
  const confirms = [];
  const { dialog } = await openEntryShare({
    ok: true, candidates: [], server: { available: true },
    grants: [{ grantee_id: -1, name: 'Server', kind: 'server', permission: 'read', consumers: ['CveHunter'], fields: ['password'], rate_per_hour: 60, rate_burst: 10 }],
  }, { revoke: (body) => { revokes.push(plain(body)); return { ok: true, suggest_rotate: true }; } }, { confirm: (m) => { confirms.push(m); return true; } });
  const notice = q(dialog, '[data-vault-share-server-rotate]');
  assert.equal(notice.hidden, true);
  q(dialog, '[data-vault-revoke="-1"]').click();
  await flush(10);
  assert.deepEqual(revokes, [{ type: 'entry', id: '11', grantee_id: '-1' }]);
  assert.deepEqual(confirms, [dialog.getAttribute('data-msg-confirm-revoke-server')]);
  assert.equal(notice.hidden, false, 'the rotate-at-provider notice shows');
  assert.match(notice.textContent, /provider/);
  assert.equal(q(dialog, '[data-vault-share-rotate]').hidden, true, 'not the person notice');
});

test('the activity view shows Server reads as Server · consumer · field, with the reason', async () => {
  const rows = [
    { id: 4, created_at: 1800000000, action: 'server_read_denied', actor_kind: 'server', via: 'api', actor: null, target: null, object_type: 'entry', object_id: 11, title: 'E', count: null, ip_trunc: null, ua_family: null, consumer: XSS, field_name: 'password', entry_version: null, reason: 'consumer_not_allowed' },
    { id: 3, created_at: 1800000000, action: 'server_read', actor_kind: 'server', via: 'api', actor: null, target: null, object_type: 'entry', object_id: 11, title: 'E', count: null, ip_trunc: null, ua_family: null, consumer: 'CveHunter', field_name: 'api key', entry_version: 2, reason: null },
  ];
  const p = page({ activity: () => ({ ok: true, rows, next_offset: null }) });
  await flush();
  q(p.doc, '[data-vault-action="activity"]').click();
  await flush(10);
  const body = q(p.doc, '[data-vault-activity-rows]');
  const server = q(p.doc, '[data-vault-share]').getAttribute('data-msg-server');
  const trs = body.querySelectorAll('tr');
  assert.equal(trs.length, 2);
  assert.equal(body.querySelectorAll('img').length, 0);
  assert.ok(trs[0].textContent.includes(server + ' · ' + XSS + ' · password'));
  assert.ok(trs[0].textContent.includes('consumer_not_allowed'));
  assert.ok(trs[1].textContent.includes(server + ' · CveHunter · api key'));
});
