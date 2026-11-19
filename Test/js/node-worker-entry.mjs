// A node:worker_threads stand-in for a browser module worker (not a *.test.mjs): it gives the worker script the
// self.addEventListener / self.postMessage it expects, then imports it. Messages that arrive before the import
// finishes are held and delivered in order. Used by node-worker.mjs.
import { parentPort, workerData } from 'node:worker_threads';

const listeners = [];
const held = [];
globalThis.self = {
  addEventListener: (type, fn) => { if (type === 'message') listeners.push(fn); },
  postMessage: (msg, transfer) => parentPort.postMessage(msg, transfer),
};
parentPort.on('message', (data) => (listeners.length ? listeners.forEach((fn) => fn({ data })) : held.push(data)));
await import(workerData.url);
for (const data of held.splice(0)) listeners.forEach((fn) => fn({ data }));
