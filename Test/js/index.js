// `node --test Vault/Test/js` runs this file: Node 22 resolves a directory argument to its index rather than
// expanding it. It imports every *.test.mjs here, and their node:test cases run in this process.
'use strict';
const { readdirSync } = require('node:fs');
const { join } = require('node:path');
const { pathToFileURL } = require('node:url');

for (const file of readdirSync(__dirname).filter((f) => f.endsWith('.test.mjs')).sort()) {
  import(pathToFileURL(join(__dirname, file)).href);
}
