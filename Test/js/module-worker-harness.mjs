// Runs Assets/js/argon2-worker.js the way a browser runs a module worker, to prove the vendored noble ESM files load
// as they are (spec: KeePassXC → Libraries). Needs `node --experimental-vm-modules`; argon2-worker.test.mjs spawns it.
// Every module is a vm.SourceTextModule in one fresh context that has only what a dedicated worker has (self with
// addEventListener and postMessage, setTimeout, TextEncoder, crypto, …): no require, no process, no Node module
// loader. Imports resolve as URLs relative to the importing file, and each file is read byte for byte from disk.
// Usage: node --experimental-vm-modules module-worker-harness.mjs '<json array of messages>'
// Byte arrays in the messages are given as {hex: '…'}; replies print as one JSON line with hashes in hex.
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const entry = new URL('../../Assets/js/argon2-worker.js', import.meta.url);
const listeners = [];
const replies = [];
const loaded = [];
const self = {
  addEventListener: (type, fn) => { if (type === 'message') listeners.push(fn); },
  postMessage: (msg) => replies.push(msg),
};
const context = vm.createContext({ self, setTimeout, clearTimeout, TextEncoder, TextDecoder, crypto: globalThis.crypto, console });
// A worker's global object is self; noble reads globalThis.
vm.runInContext('globalThis.self = self;', context);

const cache = new Map();
function load(url) {
  if (!cache.has(url.href)) {
    loaded.push(fileURLToPath(url));
    cache.set(url.href, new vm.SourceTextModule(readFileSync(url, 'utf8'), { identifier: url.href, context }));
  }
  return cache.get(url.href);
}

const root = load(entry);
await root.link((specifier, referencing) => {
  if (!/^\.\.?\//.test(specifier)) {
    throw new Error('a bare or absolute import a browser could not resolve: ' + specifier);
  }
  return load(new URL(specifier, referencing.identifier));
});
await root.evaluate();

// Built in the worker's own realm, as structured clone would.
const WorkerU8 = vm.runInContext('Uint8Array', context);
const fromHex = (h) => WorkerU8.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const toHex = (u) => Array.from(u, (x) => x.toString(16).padStart(2, '0')).join('');
const revive = (v) => (v && typeof v === 'object' && typeof v.hex === 'string' ? fromHex(v.hex) : v);

const messages = JSON.parse(process.argv[2] || '[]');
for (const m of messages) {
  const data = Object.fromEntries(Object.entries(m).map(([k, v]) => [k, revive(v)]));
  for (const fn of listeners) fn({ data });
}
const deadline = Date.now() + 60000;
while (replies.length < messages.length && Date.now() < deadline) {
  await new Promise((r) => setTimeout(r, 20));
}
process.stdout.write(JSON.stringify({
  globals: vm.runInContext('[typeof require, typeof process, typeof module]', context),
  loaded: loaded.map((f) => pathToFileURL(f).pathname.split('/Vault/')[1]),
  replies: replies.map((r) => ({ id: r.id, ...(r.hash ? { hash: toHex(r.hash) } : { error: r.error }) })),
}) + '\n');
