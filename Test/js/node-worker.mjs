// The Worker class the Vault JS tests hand to the page in place of the browser's (not a *.test.mjs). It runs the
// real Assets/js/argon2-worker.js in a node worker thread through node-worker-entry.mjs, and counts what it is
// asked: workers.started, workers.messages (each message's type) and workers.terminated.
import { Worker as ThreadWorker } from 'node:worker_threads';

const ENTRY = new URL('./node-worker-entry.mjs', import.meta.url);
export const WORKER_FILE = new URL('../../Assets/js/argon2-worker.js', import.meta.url).href;

export function workerClass(log = { started: [], messages: [], terminated: 0 }) {
  class NodeModuleWorker {
    constructor(url, opts) {
      log.started.push({ url: String(url), type: opts && opts.type });
      this.onmessage = null;
      this.onerror = null;
      this.listeners = { message: [], error: [] };
      // The page names the worker by URL; only the real worker file can run here.
      const target = String(url) === WORKER_FILE || /\/Assets\/js\/argon2-worker\.js$/.test(new URL(String(url)).pathname) ? WORKER_FILE : null;
      if (!target) throw new Error('unexpected worker URL ' + url);
      this.thread = new ThreadWorker(ENTRY, { workerData: { url: target } });
      this.thread.on('message', (data) => this.emit('message', { data }));
      this.thread.on('error', (e) => this.emit('error', { message: String(e && e.message) }));
    }
    emit(type, ev) {
      if (type === 'message' && this.onmessage) this.onmessage(ev);
      if (type === 'error' && this.onerror) this.onerror(ev);
      this.listeners[type].forEach((fn) => fn(ev));
    }
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
    postMessage(msg) {
      log.messages.push(msg.type);
      this.thread.postMessage(msg);
    }
    terminate() {
      log.terminated++;
      this.thread.terminate();
    }
  }
  return { Worker: NodeModuleWorker, log };
}
