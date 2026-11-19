// Small helpers to find and overwrite values in a KDBX outer header, for crafting hostile headers. Shared by
// make-headers.mjs and Test/js/kdbx-header.test.mjs. Test-only; they trust their input.

// The outer header's fields: [{id, at (offset of the data), size}], up to and including the end field.
export function fields(b) {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const major = v.getUint16(10, true);
  const out = [];
  let p = 12;
  for (;;) {
    const id = b[p];
    const size = major >= 4 ? v.getUint32(p + 1, true) : v.getUint16(p + 1, true);
    const at = p + 1 + (major >= 4 ? 4 : 2);
    out.push({ id, at, size });
    p = at + size;
    if (id === 0) return out;
  }
}

export const field = (b, id) => fields(b).find((f) => f.id === id);

// The value of key `name` in the VarDictionary at `at`: {at (offset of the value), size, type}.
export function dictValue(b, at, name) {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let p = at + 2;
  for (;;) {
    const type = b[p];
    if (type === 0) throw new Error('no ' + name);
    const kl = v.getInt32(p + 1, true);
    const key = new TextDecoder().decode(b.subarray(p + 5, p + 5 + kl));
    const vl = v.getInt32(p + 5 + kl, true);
    const valueAt = p + 9 + kl;
    if (key === name) return { at: valueAt, size: vl, type };
    p = valueAt + vl;
  }
}

export function setUint64(b, at, n) {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  v.setUint32(at, n % 0x100000000, true);
  v.setUint32(at + 4, Math.floor(n / 0x100000000), true);
}

// Overwrites KDF parameter `name` (an integer of any width) in a copy of KDBX 4 file `b`.
export function withKdfParam(b, name, n) {
  const out = b.slice();
  const d = dictValue(out, field(out, 11).at, name);
  const v = new DataView(out.buffer, out.byteOffset, out.byteLength);
  if (d.size === 8) setUint64(out, d.at, n);
  else v.setUint32(d.at, n, true);
  return out;
}

// A copy of `b` with the KDF parameters field (11) replaced by a VarDictionary of `items` ([type, key bytes,
// value bytes]); the rest of the file is kept.
export function withKdfDict(b, items) {
  const f = field(b, 11);
  const parts = [Uint8Array.of(0x00, 0x01)];
  for (const [type, key, value] of items) {
    const head = new Uint8Array(9);
    const hv = new DataView(head.buffer);
    head[0] = type;
    hv.setInt32(1, key.length, true);
    parts.push(head.subarray(0, 5), key);
    const vl = new Uint8Array(4);
    new DataView(vl.buffer).setInt32(0, value.length, true);
    parts.push(vl, value);
  }
  parts.push(Uint8Array.of(0));
  const dict = concat(parts);
  const size = new Uint8Array(4);
  new DataView(size.buffer).setUint32(0, dict.length, true);
  return concat([b.subarray(0, f.at - 4), size, dict, b.subarray(f.at + f.size)]);
}

export function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
export const u64 = (n) => { const b = new Uint8Array(8); setUint64(b, 0, n); return b; };
export const ascii = (s) => new TextEncoder().encode(s);
