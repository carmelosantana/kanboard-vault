// `node --test Vault/Test/js` runs this file: Node 22 resolves a directory argument to its index rather than
// expanding it. It imports every *.test.mjs here, in order and awaited, and their node:test cases run in this
// process. A file that fails to load fails the run (T11 M7).
'use strict';
const { readdirSync } = require('node:fs');
const { join } = require('node:path');
const { pathToFileURL } = require('node:url');

(async () => {
  for (const file of readdirSync(__dirname).filter((f) => f.endsWith('.test.mjs')).sort()) {
    await import(pathToFileURL(join(__dirname, file)).href);
  }
})().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
