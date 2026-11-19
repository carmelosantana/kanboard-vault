// A small fake DOM for the Vault JS tests (zero-dependency; not a *.test.mjs, so index.js doesn't run it).
// It parses the real Template/vault/{tree,list,detail,edit,share_dialog,activity}.php (PHP stripped: t('…') becomes its text, any other
// echo becomes "X"), adds the shell's app, toolbar and toast, and runs vault-browser.js, vault-generator.js and vault-share.js in one
// vm context. Elements support the selectors the scripts use, bubbling events, form.elements and select.options.
// innerHTML, outerHTML and insertAdjacentHTML throw, so a test fails if a script ever reaches for them.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const VOID = new Set(['input', 'br', 'img', 'hr', 'meta', 'link']);

export const flush = async (n = 5) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};

// [attr], [attr="v"], .class, tag and :not(…), compounded; comma lists. Anything else throws.
function parseCompound(sel) {
  const s = sel.trim();
  const m = /^([a-z][a-z0-9]*)?/i.exec(s);
  const parts = { tag: m[1] ? m[1].toUpperCase() : null, cls: [], attrs: [], not: [] };
  let rest = s.slice(m[0].length);
  while (rest !== '') {
    let t;
    if ((t = /^\.([\w-]+)/.exec(rest))) parts.cls.push(t[1]);
    else if ((t = /^\[([\w-]+)(?:="([^"]*)")?\]/.exec(rest))) parts.attrs.push([t[1], t[2]]);
    else if ((t = /^:not\(([^()]*)\)/.exec(rest))) parts.not.push(parseCompound(t[1]));
    else throw new Error('unsupported selector ' + sel);
    rest = rest.slice(t[0].length);
  }
  return parts;
}

function matches(el, c) {
  if (!(el instanceof El)) return false;
  if (c.tag && el.tagName !== c.tag) return false;
  if (c.cls.some((k) => !el.classList.contains(k))) return false;
  if (c.attrs.some(([k, v]) => !el.hasAttribute(k) || (v !== undefined && el.getAttribute(k) !== v))) return false;
  return !c.not.some((n) => matches(el, n));
}

class Text {
  constructor(t) { this.data = String(t); this.parentNode = null; }
  get textContent() { return this.data; }
  set textContent(v) { this.data = String(v); }
  all() { return []; }
}

export class El {
  constructor(doc, tag, attrs = {}) {
    this.ownerDocument = doc;
    this.tagName = tag.toUpperCase();
    this.attrs = { ...attrs };
    this.children = [];
    this.parentNode = null;
    this.listeners = {};
  }
  get id() { return this.getAttribute('id') || ''; }
  get className() { return this.getAttribute('class') || ''; }
  set className(v) { this.setAttribute('class', v); }
  get classList() {
    const el = this;
    const list = () => el.className.split(/\s+/).filter(Boolean);
    const set = (a) => el.setAttribute('class', a.join(' '));
    return {
      contains: (k) => list().includes(k),
      add: (k) => { if (!list().includes(k)) set([...list(), k]); },
      remove: (k) => set(list().filter((x) => x !== k)),
      toggle: (k, on) => { const want = on === undefined ? !list().includes(k) : !!on; want ? this.classList.add(k) : this.classList.remove(k); return want; },
    };
  }
  flag(k, on) { if (on) this.attrs[k] = ''; else delete this.attrs[k]; }
  get hidden() { return this.hasAttribute('hidden'); }
  set hidden(v) { this.flag('hidden', v); }
  get disabled() { return this.hasAttribute('disabled'); }
  set disabled(v) { this.flag('disabled', v); }
  get type() { return this.getAttribute('type') || (this.tagName === 'BUTTON' ? 'submit' : this.tagName === 'INPUT' ? 'text' : ''); }
  set type(v) { this.setAttribute('type', v); }
  get value() {
    if (this._value !== undefined) return this._value;
    if (this.tagName === 'SELECT') {
      const o = this.options.find((x) => x.hasAttribute('selected')) || this.options[0];
      return o ? o.value : '';
    }
    if (this.tagName === 'OPTION') return this.hasAttribute('value') ? this.getAttribute('value') : this.textContent;
    if (this.tagName === 'TEXTAREA') return this.textContent;
    return this.getAttribute('value') || '';
  }
  set value(v) { this._value = String(v); }
  get checked() { return this._checked !== undefined ? this._checked : this.hasAttribute('checked'); }
  set checked(v) { this._checked = !!v; }
  get options() { return this.children.filter((c) => c instanceof El && c.tagName === 'OPTION'); }
  remove(i) { const o = this.options[i]; if (o) this.removeChild(o); }
  get elements() {
    const map = {};
    for (const e of this.all()) {
      if (!(e instanceof El) || !['INPUT', 'TEXTAREA', 'SELECT', 'BUTTON'].includes(e.tagName)) continue;
      if (e.getAttribute('name')) map[e.getAttribute('name')] = map[e.getAttribute('name')] || e;
      if (e.id) map[e.id] = map[e.id] || e;
    }
    return map;
  }
  get textContent() { return this.children.map((c) => c.textContent).join(''); }
  set textContent(v) { this.children = []; if (String(v) !== '') this.appendChild(new Text(v)); }
  set innerHTML(v) { throw new Error('innerHTML write: ' + v); }
  get innerHTML() { throw new Error('innerHTML read'); }
  set outerHTML(v) { throw new Error('outerHTML write: ' + v); }
  insertAdjacentHTML(_, v) { throw new Error('insertAdjacentHTML: ' + v); }
  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  removeAttribute(k) { delete this.attrs[k]; }
  hasAttribute(k) { return k in this.attrs; }
  appendChild(c) { if (c.parentNode) c.parentNode.removeChild(c); c.parentNode = this; this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); c.parentNode = null; return c; }
  all() { return this.children.flatMap((c) => [c, ...c.all()]); }
  querySelectorAll(sel) {
    const list = sel.split(',').map(parseCompound);
    return this.all().filter((e) => list.some((c) => matches(e, c)));
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  closest(sel) {
    const list = sel.split(',').map(parseCompound);
    for (let e = this; e instanceof El; e = e.parentNode) if (list.some((c) => matches(e, c))) return e;
    return null;
  }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  dispatch(type, extra = {}) {
    const ev = { type, target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...extra };
    for (let e = this; e; e = e.parentNode) for (const fn of (e.listeners && e.listeners[type]) || []) fn.call(e, ev);
    return ev;
  }
  click() { if (!this.disabled) this.dispatch('click'); }
  focus() { this.ownerDocument.activeElement = this; }
}

export class Doc {
  constructor() {
    this.readyState = 'complete';
    this.body = new El(this, 'body');
    this.listeners = {};
    this.focused = true;
  }
  createElement(tag) { return new El(this, tag); }
  createTextNode(t) { return new Text(t); }
  querySelectorAll(sel) { return this.body.querySelectorAll(sel); }
  querySelector(sel) { return this.body.querySelector(sel); }
  getElementById(id) { return this.body.all().find((e) => e instanceof El && e.id === id) || null; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  hasFocus() { return this.focused; }
}

// PHP out: t('…') echoes become their text, other echoes "X", blocks vanish.
function stripPhp(src) {
  return src
    .replace(/<\?=\s*t\('((?:[^'\\]|\\.)*)'\)\s*\?>/g, (_, s) => s.replace(/\\'/g, "'"))
    .replace(/<\?=[\s\S]*?\?>/g, 'X')
    .replace(/<\?php[\s\S]*?\?>/g, '');
}

export function parseInto(doc, parent, html) {
  const re = /<!--[\s\S]*?-->|<\/([a-z0-9]+)\s*>|<([a-z0-9]+)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>|([^<]+)/gi;
  const stack = [parent];
  let m;
  while ((m = re.exec(html))) {
    const top = stack[stack.length - 1];
    if (m[1]) {
      if (top.tagName !== m[1].toUpperCase()) throw new Error(`mismatched </${m[1]}> in template (open: ${top.tagName})`);
      stack.pop();
    } else if (m[2]) {
      const attrs = {};
      for (const a of m[3].matchAll(/([^\s=>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
        attrs[a[1]] = a[2] ?? a[3] ?? a[4] ?? '';
      }
      const el = top.appendChild(new El(doc, m[2], attrs));
      if (!VOID.has(m[2].toLowerCase())) stack.push(el);
    } else if (m[4] && m[4].trim() !== '') {
      top.appendChild(new Text(m[4]));
    }
  }
  if (stack.length !== 1) throw new Error('unclosed tag in template');
}

// A Vault template with its parameterless Vault partials inlined ($this->render('Vault:vault/name')), PHP stripped.
export function template(name) {
  const raw = readFileSync(path(`Template/vault/${name}.php`), 'utf8')
    .replace(/<\?=\s*\$this->render\('Vault:vault\/([a-z_]+)'\)\s*\?>/g, (_, n) => readFileSync(path(`Template/vault/${n}.php`), 'utf8'));
  return stripPhp(raw);
}

export const WORDLIST_URL = '/plugins/Vault/Assets/vendor/eff_large_wordlist.txt';

// The unlocked Vault page. api(action, body) answers each KBVault.api call; return a Promise to hold it. fetch, confirm
// and prompt stand in for the window's. onetime: {Worker, scriptSrc} also loads the one-time link dialog and
// vault-onetime.js (T18), with that Worker class and document.currentScript.src.
export function loadPage({ api, crypto, wordlist = '', math = Math, fetch, confirm = () => true, prompt = () => null, onetime = null } = {}) {
  const doc = new Doc();
  const calls = [];
  const fetches = [];
  const tpl = (name) => stripPhp(readFileSync(path(`Template/vault/${name}.php`), 'utf8'));
  parseInto(doc, doc.body, `
    <ul class="vault-toolbar">
      <li><input type="search" data-vault-search></li>
      <li><button type="button" data-vault-action="new-entry">Entry</button></li>
      <li><button type="button" data-vault-action="new-group">Group</button></li>
    </ul>
    <div id="vault-app" data-vault-state="unlocked" data-messages='{"failed":"Something went wrong.","saved":"Saved.","from":"from"}'
         data-endpoints='{"share_show":"/?controller=VaultShareController&amp;action=show&amp;plugin=Vault"}'>
      <div class="vault-panes" data-vault-panes>${tpl('tree')}${tpl('list')}<section class="vault-detail">${tpl('detail')}${tpl('edit')}</section></div>
      ${tpl('share_dialog')}${tpl('activity')}${onetime ? tpl('onetime_dialog') : ''}
    </div>
    <p class="vault-toast" data-vault-toast role="status" hidden></p>`);
  const panel = doc.querySelector('[data-vault-generator]');
  if (panel) panel.setAttribute('data-wordlist', WORDLIST_URL);
  const otDialog = doc.querySelector('[data-vault-onetime]');
  if (otDialog) otDialog.setAttribute('data-wordlist', WORDLIST_URL);
  // The parser keeps entities as written; the browser would have decoded the attribute.
  const app = doc.getElementById('vault-app');
  app.setAttribute('data-endpoints', app.getAttribute('data-endpoints').replace(/&amp;/g, '&'));
  const window = {
    document: doc,
    URL,
    crypto,
    navigator: { clipboard: { writeText: () => Promise.resolve() } },
    setTimeout: () => 0,
    clearTimeout: () => {},
    location: { reload: () => {}, href: 'https://kb.test/?controller=VaultController&action=index&plugin=Vault' },
    Worker: onetime ? onetime.Worker : undefined,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    prompt,
    confirm,
    fetch: (url) => {
      fetches.push(url);
      return fetch ? fetch(url) : Promise.resolve({ ok: true, text: () => Promise.resolve(wordlist) });
    },
    KBVault: {
      api: (action, body) => {
        calls.push({ action, body: { ...body } });
        return Promise.resolve(api ? api(action, body) : { ok: true });
      },
    },
  };
  const ctx = vm.createContext({ window, Math: math });
  for (const f of ['vault-browser.js', 'vault-generator.js', 'vault-share.js']) {
    vm.runInContext(readFileSync(path(`Assets/js/${f}`), 'utf8'), ctx, { filename: f });
  }
  if (onetime) {
    doc.currentScript = { src: onetime.scriptSrc };
    vm.runInContext(readFileSync(path('Assets/js/vault-onetime.js'), 'utf8'), ctx, { filename: 'vault-onetime.js' });
    doc.currentScript = null;
  }
  const messages = {};
  if (panel) {
    for (const [k, v] of Object.entries(panel.attrs)) if (k.startsWith('data-msg-')) messages[k.slice(9)] = v;
  }
  return { doc, window, calls, fetches, messages, wordlistUrl: WORDLIST_URL };
}
