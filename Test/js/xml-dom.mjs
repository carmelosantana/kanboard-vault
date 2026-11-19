// A small, strict XML DOMParser and XMLSerializer for the Vault JS tests (not a *.test.mjs). Node has no DOM, and
// kdbxweb reads KDBX's inner XML through globalThis.DOMParser in the browser; without one it would require
// @xmldom/xmldom, which Vault does not ship. This covers what kdbxweb uses: elements, attributes, text, CDATA,
// comments, the XML declaration, the five predefined entities and character references. Like a browser's XML parser
// it keeps every whitespace character of text as it is (tabs included) and only folds CR LF and a lone CR to LF
// (XML 1.0 §2.11). Malformed input throws, which kdbxweb turns into FileCorrupt. Test-only: never loaded by a page.

const ELEMENT_NODE = 1;
const TEXT_NODE = 3;
const PROCESSING_INSTRUCTION_NODE = 7;
const COMMENT_NODE = 8;
const DOCUMENT_NODE = 9;

class XNode {
  constructor(nodeType, ownerDocument) {
    this.nodeType = nodeType;
    this.ownerDocument = ownerDocument;
    this.parentNode = null;
    this.childNodes = [];
  }
  get firstChild() { return this.childNodes[0] || null; }
  get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
  get nextSibling() {
    if (!this.parentNode) return null;
    const s = this.parentNode.childNodes;
    return s[s.indexOf(this) + 1] || null;
  }
  appendChild(node) { return this.insertBefore(node, null); }
  insertBefore(node, ref) {
    if (node.parentNode) node.parentNode.removeChild(node);
    const i = ref === null ? this.childNodes.length : this.childNodes.indexOf(ref);
    if (i < 0) throw new Error('insertBefore: not a child');
    this.childNodes.splice(i, 0, node);
    node.parentNode = this;
    return node;
  }
  removeChild(node) {
    const i = this.childNodes.indexOf(node);
    if (i < 0) throw new Error('removeChild: not a child');
    this.childNodes.splice(i, 1);
    node.parentNode = null;
    return node;
  }
  get textContent() {
    return this.childNodes.map((c) => (c.nodeType === ELEMENT_NODE || c.nodeType === TEXT_NODE ? c.textContent : '')).join('');
  }
  set textContent(v) {
    for (const c of this.childNodes) c.parentNode = null;
    this.childNodes = [];
    if (v !== '' && v !== null && v !== undefined) this.appendChild(new XText(String(v), this.ownerDocument));
  }
}

class XText extends XNode {
  constructor(data, doc) {
    super(TEXT_NODE, doc);
    this.data = data;
  }
  get nodeName() { return '#text'; }
  get nodeValue() { return this.data; }
  get textContent() { return this.data; }
  set textContent(v) { this.data = String(v); }
}

class XOther extends XNode {
  constructor(nodeType, data, doc) {
    super(nodeType, doc);
    this.data = data;
  }
}

class XElement extends XNode {
  constructor(tagName, doc) {
    super(ELEMENT_NODE, doc);
    this.tagName = tagName;
    this.attrs = new Map();
  }
  get nodeName() { return this.tagName; }
  getAttribute(n) { return this.attrs.has(n) ? this.attrs.get(n) : null; }
  setAttribute(n, v) { this.attrs.set(n, String(v)); }
  removeAttribute(n) { this.attrs.delete(n); }
  hasAttribute(n) { return this.attrs.has(n); }
  getElementsByTagName(n) { return byTag(this, n); }
}

class XDocument extends XNode {
  constructor() {
    super(DOCUMENT_NODE, null);
    this.declaration = null;
  }
  get documentElement() { return this.childNodes.find((c) => c.nodeType === ELEMENT_NODE) || null; }
  createElement(n) { return new XElement(n, this); }
  createTextNode(s) { return new XText(String(s), this); }
  getElementsByTagName(n) { return byTag(this, n); }
}
for (const [k, v] of Object.entries({ ELEMENT_NODE, TEXT_NODE, PROCESSING_INSTRUCTION_NODE, COMMENT_NODE, DOCUMENT_NODE })) {
  XNode.prototype[k] = v;
}

function byTag(root, n) {
  const out = [];
  const walk = (node) => {
    for (const c of node.childNodes) {
      if (c.nodeType === ELEMENT_NODE) {
        if (n === '*' || c.tagName === n) out.push(c);
        walk(c);
      }
    }
  };
  walk(root);
  return out;
}

const NAME = /^[A-Za-z_:][-A-Za-z0-9_:.]*/;
const ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

function decode(s) {
  return s.replace(/&(#x[0-9A-Fa-f]+|#[0-9]+|[A-Za-z]+);|&/g, (m, e) => {
    if (e === undefined) throw new Error('bare &');
    if (e[0] === '#') return String.fromCodePoint(e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
    if (!(e in ENTITIES)) throw new Error('unknown entity ' + e);
    return ENTITIES[e];
  });
}

export class DOMParser {
  parseFromString(src, type) {
    if (type !== 'application/xml' && type !== 'text/xml') throw new Error('unsupported type ' + type);
    const xml = String(src).replace(/\r\n?/g, '\n');
    const doc = new XDocument();
    let i = 0;
    let node = doc;
    const expect = (s) => {
      if (!xml.startsWith(s, i)) throw new Error('expected ' + s + ' at ' + i);
      i += s.length;
    };
    const until = (s) => {
      const j = xml.indexOf(s, i);
      if (j < 0) throw new Error('unterminated, expected ' + s);
      const out = xml.slice(i, j);
      i = j + s.length;
      return out;
    };
    while (i < xml.length) {
      if (xml.startsWith('<?', i)) {
        i += 2;
        const body = until('?>');
        if (/^xml\s/.test(body)) {
          if (node !== doc || doc.childNodes.length) throw new Error('misplaced XML declaration');
          doc.declaration = '<?' + body + '?>';
        } else {
          node.appendChild(new XOther(PROCESSING_INSTRUCTION_NODE, body, doc));
        }
      } else if (xml.startsWith('<!--', i)) {
        i += 4;
        node.appendChild(new XOther(COMMENT_NODE, until('-->'), doc));
      } else if (xml.startsWith('<![CDATA[', i)) {
        if (node === doc) throw new Error('CDATA outside the root');
        i += 9;
        node.appendChild(new XText(until(']]>'), doc));
      } else if (xml.startsWith('<!', i)) {
        throw new Error('DOCTYPE and declarations are not supported');
      } else if (xml.startsWith('</', i)) {
        i += 2;
        const m = NAME.exec(xml.slice(i));
        if (!m || node === doc || m[0] !== node.tagName) throw new Error('mismatched end tag at ' + i);
        i += m[0].length;
        while (/\s/.test(xml[i])) i++;
        expect('>');
        node = node.parentNode;
      } else if (xml[i] === '<') {
        i++;
        const m = NAME.exec(xml.slice(i));
        if (!m) throw new Error('bad tag name at ' + i);
        if (node === doc && doc.documentElement) throw new Error('a second root element');
        const el = doc.createElement(m[0]);
        i += m[0].length;
        for (;;) {
          const ws = /^\s*/.exec(xml.slice(i))[0].length;
          i += ws;
          if (xml.startsWith('/>', i)) {
            i += 2;
            node.appendChild(el);
            break;
          }
          if (xml[i] === '>') {
            i++;
            node.appendChild(el);
            node = el;
            break;
          }
          const a = NAME.exec(xml.slice(i));
          if (!a || !ws) throw new Error('bad attribute at ' + i);
          i += a[0].length;
          expect('=');
          const q = xml[i];
          if (q !== '"' && q !== "'") throw new Error('unquoted attribute at ' + i);
          i++;
          const raw = until(q);
          if (raw.includes('<')) throw new Error('< in attribute');
          if (el.hasAttribute(a[0])) throw new Error('duplicate attribute ' + a[0]);
          // Attribute-value normalisation (XML 1.0 §3.3.3): literal whitespace characters become spaces.
          el.setAttribute(a[0], decode(raw.replace(/[\t\n]/g, ' ')));
        }
      } else {
        const j = xml.indexOf('<', i);
        const raw = xml.slice(i, j < 0 ? xml.length : j);
        i += raw.length;
        if (node === doc) {
          if (/\S/.test(raw)) throw new Error('text outside the root');
        } else {
          if (raw.includes(']]>')) throw new Error(']]> in text');
          node.appendChild(new XText(decode(raw), doc));
        }
      }
    }
    if (node !== doc) throw new Error('unclosed element ' + node.tagName);
    if (!doc.documentElement) throw new Error('no root element');
    return doc;
  }
}

const escText = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const escAttr = (s) => escText(s).replace(/"/g, '&quot;').replace(/\t/g, '&#9;').replace(/\n/g, '&#10;').replace(/\r/g, '&#13;');

export class XMLSerializer {
  serializeToString(node) {
    const out = [];
    const walk = (n) => {
      if (n.nodeType === DOCUMENT_NODE) {
        if (n.declaration) out.push(n.declaration);
        n.childNodes.forEach(walk);
      } else if (n.nodeType === ELEMENT_NODE) {
        out.push('<' + n.tagName);
        for (const [k, v] of n.attrs) out.push(' ' + k + '="' + escAttr(v) + '"');
        if (!n.childNodes.length) {
          out.push('/>');
        } else {
          out.push('>');
          n.childNodes.forEach(walk);
          out.push('</' + n.tagName + '>');
        }
      } else if (n.nodeType === TEXT_NODE) {
        out.push(escText(n.data).replace(/\r/g, '&#13;'));
      } else if (n.nodeType === COMMENT_NODE) {
        out.push('<!--' + n.data + '-->');
      } else if (n.nodeType === PROCESSING_INSTRUCTION_NODE) {
        out.push('<?' + n.data + '?>');
      }
    };
    walk(node);
    return out.join('');
  }
}
