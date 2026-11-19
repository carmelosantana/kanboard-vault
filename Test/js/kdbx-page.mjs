// Loads the vendored kdbxweb (and, if asked, vault-kdbx.js) the way the import page does: classic scripts in one
// realm whose global object is window, with WebCrypto, a DOMParser/XMLSerializer (xml-dom.mjs, since Node has none)
// and the real Argon2 module worker (node-worker.mjs). Not a *.test.mjs. Used by kdbx-patches.test.mjs and by
// Test/fixtures/kdbx/make-fixtures.mjs.
//
// No module, exports or define exists in the realm, so kdbxweb's UMD wrapper takes its browser branch
// (root.kdbxweb) and never reaches require('crypto') or require('@xmldom/xmldom'). The binary constructors come from
// this realm, so buffers from Node's WebCrypto and the worker pass kdbxweb's instanceof checks as in a browser.
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { DOMParser, XMLSerializer } from './xml-dom.mjs';
import { workerClass } from './node-worker.mjs';

const file = (p) => new URL('../../' + p, import.meta.url);
export const KDBXWEB_PATH = file('Assets/vendor/kdbxweb/kdbxweb.js');
export const VAULT_KDBX_PATH = file('Assets/js/vault-kdbx.js');
const BASE = 'https://kb.test/plugins/Vault/Assets/';

const BINARY = { ArrayBuffer, DataView, Uint8Array, Int8Array, Uint16Array, Int16Array, Uint32Array, Int32Array, Float32Array, Float64Array, Uint8ClampedArray, BigInt64Array, BigUint64Array };

// crypto: a WebCrypto-shaped object.
// vault: also load Assets/js/vault-kdbx.js. workerLog: node-worker.mjs's log object to fill (optional).
// Returns { win, kdbxweb, vault, log } (log: the worker's counters).
export function loadKdbxPage({ crypto = webcrypto, vault = false, workerLog } = {}) {
  const { Worker, log } = workerClass(workerLog);
  const document = { currentScript: null };
  const ctx = vm.createContext({
    ...BINARY,
    crypto, DOMParser, XMLSerializer, TextEncoder, TextDecoder, atob, btoa, URL, Worker, document,
    setTimeout, clearTimeout,
  });
  vm.runInContext('var window = globalThis; var self = globalThis;', ctx);
  const run = (src, url, name) => {
    document.currentScript = { src: url };
    vm.runInContext(src, ctx, { filename: name });
    document.currentScript = null;
  };
  run(readFileSync(KDBXWEB_PATH, 'utf8'), BASE + 'vendor/kdbxweb/kdbxweb.js', 'kdbxweb.js');
  if (vault) {
    run(readFileSync(VAULT_KDBX_PATH, 'utf8'), BASE + 'js/vault-kdbx.js?1700000000', 'vault-kdbx.js');
  }
  const win = vm.runInContext('window', ctx);
  return { win, kdbxweb: win.kdbxweb, vault: win.KBVaultKdbx, log };
}
