// Writes MAPPED (kpxc-mapped.json): for each KeePassXC fixture (KPXC), what the import page sends the server, made by
// the real page scripts (vault-kdbx-header.js, vault-kdbx.js, vault-import.js) in Test/js/kdbx-page.mjs's realm.
// ImportControllerTest posts these batches; vault-import.test.mjs checks the page still builds exactly them.
// Run by make-fixtures.sh; on its own: node Vault/Test/fixtures/kdbx/make-mapped.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadKdbxPage } from '../../js/kdbx-page.mjs';
import { PASSWORD, KPXC, MAPPED } from './fixtures.mjs';

const file = (name) => fileURLToPath(new URL('./' + name, import.meta.url));

export async function mapAll() {
  const { importer } = loadKdbxPage({ importer: true });
  const out = {};
  for (const [name, c] of Object.entries(KPXC)) {
    const bytes = new Uint8Array(readFileSync(file(c.file)));
    const key = c.keyFile ? new Uint8Array(readFileSync(file(c.keyFile))) : null;
    const p = await importer.open(bytes, PASSWORD, key);
    // Through JSON, as KBVault.api sends them.
    out[name] = JSON.parse(JSON.stringify({ total: p.total, groups: p.groups, skippedAttachments: p.skippedAttachments, batches: p.batches }));
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  writeFileSync(file(MAPPED), JSON.stringify(await mapAll(), null, 1) + '\n');
  console.log('wrote', MAPPED);
}
