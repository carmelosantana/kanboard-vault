// A KeePass 2 XML file for `keepassxc-cli import`, from entries shaped like fixtures.mjs's KPXC_ENTRIES:
// {path, fields, protect, tags, expires?, attachments?, history?, group?}. Shared by make-seeds.mjs (the import
// fixtures) and Test/kdbx-gate/make-gate-fixtures.mjs (the export gate's). UUIDs are fixed (from uuidPrefix and the
// entry's index), so the same entries give the same XML on every run.
import { createHash } from 'node:crypto';

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

export function keepassXml(dbName, entries, uuidPrefix) {
  const uuid = (label) => createHash('sha256').update(uuidPrefix + label).digest().subarray(0, 16).toString('base64');
  const binaries = [];
  const entryXml = (e, label) => {
    let x = '<Entry><UUID>' + uuid('entry:' + label) + '</UUID><IconID>0</IconID><Tags>' + esc(e.tags.join(';')) + '</Tags>'
      + times(e.expires) + strings(e.fields, e.protect);
    for (const [name, text] of Object.entries(e.attachments || {})) {
      binaries.push(Buffer.from(text, 'utf8').toString('base64'));
      x += '<Binary><Key>' + esc(name) + '</Key><Value Ref="' + (binaries.length - 1) + '"/></Binary>';
    }
    if (e.history && e.history.length) {
      x += '<History>' + e.history.map((h) => '<Entry><UUID>' + uuid('entry:' + label) + '</UUID><IconID>0</IconID>'
        + times() + strings(h, ['Password']) + '</Entry>').join('') + '</History>';
    }
    return x + '</Entry>';
  };

  // The group tree: a group is keyed by its path, plus `group` for siblings of the same name.
  const tree = { name: dbName, key: 'root', entries: [], groups: [] };
  entries.forEach((e, i) => {
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

  const groupXml = (g) => '<Group><UUID>' + uuid('group:' + g.key) + '</UUID><Name>' + esc(g.name) + '</Name><Notes></Notes><IconID>48</IconID>'
    + times() + '<IsExpanded>True</IsExpanded>' + g.entries.join('') + g.groups.map(groupXml).join('') + '</Group>';

  return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<KeePassFile><Meta><Generator>Vault fixture</Generator>'
    + '<DatabaseName>' + esc(dbName) + '</DatabaseName><RecycleBinEnabled>False</RecycleBinEnabled>'
    + '<Binaries>' + binaries.map((b, i) => '<Binary ID="' + i + '" Compressed="False">' + b + '</Binary>').join('') + '</Binaries>'
    + '</Meta><Root>' + groupXml(tree) + '<DeletedObjects/></Root></KeePassFile>\n';
}
