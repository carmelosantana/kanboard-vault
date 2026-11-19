// node --test Vault/Test/js — zero-dependency. Loads Assets/js/vault-generator.js into a vm context whose Math.random
// throws, with Node's WebCrypto (or a rigged source) as window.crypto, and the vendored EFF wordlist as data.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { loadPage, flush } from './fake-dom.mjs';

const path = (p) => fileURLToPath(new URL('../../' + p, import.meta.url));
const SRC = readFileSync(path('Assets/js/vault-generator.js'), 'utf8');
const LIST_BYTES = readFileSync(path('Assets/vendor/eff_large_wordlist.txt'));
const LIST = LIST_BYTES.toString('utf8');
const VENDOR = readFileSync(path('Assets/vendor/VENDOR.md'), 'utf8');
const WORDS = LIST.split('\n').filter((l) => l !== '').map((l) => l.split('\t')[1]);
const WORD_SET = new Set(WORDS);
const ANY_WORD = '(?:' + WORDS.map((w) => w.replace(/-/g, '\\-')).join('|') + ')';
const SIX_WORDS = new RegExp(`^${ANY_WORD}(?:-${ANY_WORD}){5}$`);
const LOOKALIKES = /[0O1lI]/;
const CLASSES = {
  lower: /[a-z]/,
  upper: /[A-Z]/,
  digits: /[0-9]/,
  symbols: /[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/,
};
const SYMBOLS = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';

function poisonedMath() {
  const m = Object.create(Math);
  m.random = () => { throw new Error('Math.random used'); };
  return m;
}

function load({ getRandomValues } = {}) {
  const window = { crypto: { getRandomValues: getRandomValues || ((a) => webcrypto.getRandomValues(a)) } };
  vm.runInNewContext(SRC, { window, Math: poisonedMath() });
  return window.KBVaultGen;
}

// A source confined to the top 16 Uint32 values. 2^32 mod 10 = 6, so 6 of the 16 lie past the last whole multiple of
// 10: rejection sampling must discard them, and a plain % 10 maps them onto buckets 0-5 (12.5k there, 6.25k for 6-9).
function top16(a) {
  const r = webcrypto.getRandomValues(new Uint8Array(a.length));
  for (let i = 0; i < a.length; i++) a[i] = 0xfffffff0 + (r[i] & 15);
  return a;
}

test('uniform(10) over 100k draws: every bucket within 5% of 10k', () => {
  assert.doesNotMatch(SRC, /Math\.random/, 'no Math.random in the source');
  for (const [name, gen] of [['webcrypto', load()], ['top16', load({ getRandomValues: top16 })]]) {
    const counts = new Array(10).fill(0);
    for (let i = 0; i < 100000; i++) {
      const v = gen.uniform(10);
      assert.ok(Number.isInteger(v) && v >= 0 && v < 10, `${name}: ${v} in range`);
      counts[v]++;
    }
    for (const [b, c] of counts.entries()) {
      assert.ok(Math.abs(c - 10000) <= 500, `${name}: bucket ${b} has ${c}`);
    }
  }
  const gen = load();
  assert.equal(gen.uniform(1), 0);
  for (const bad of [0, -1, 1.5, 2 ** 32 + 1, NaN, '10']) {
    assert.throws(() => gen.uniform(bad), { name: 'RangeError' }, String(bad));
  }
});

test('excludeLookalikes never yields 0O1lI', () => {
  const gen = load();
  const all = { lower: true, upper: true, digits: true, symbols: true };
  let seen = '';
  for (let i = 0; i < 300; i++) {
    const pw = gen.password({ length: 128, ...all, excludeLookalikes: true });
    assert.doesNotMatch(pw, LOOKALIKES, pw);
    seen += gen.password({ length: 128, ...all, excludeLookalikes: false });
  }
  for (const c of '0O1lI') assert.ok(seen.includes(c), `${c} appears without the option (the check isn't vacuous)`);
});

test('password honours every selected class', () => {
  const gen = load();
  const names = Object.keys(CLASSES);
  for (let mask = 1; mask < 16; mask++) {
    const picked = names.filter((_, i) => mask & (1 << i));
    for (const excludeLookalikes of [false, true]) {
      const opts = { length: 8, excludeLookalikes };
      for (const n of names) opts[n] = picked.includes(n);
      for (let i = 0; i < 200; i++) {
        const pw = gen.password(opts);
        assert.equal(pw.length, 8);
        for (const n of names) {
          if (picked.includes(n)) assert.match(pw, CLASSES[n], `${pw} has ${n}`);
          else assert.doesNotMatch(pw, CLASSES[n], `${pw} has no ${n}`);
        }
      }
    }
  }
  // Every symbol is reachable, so the alphabet the entropy counts is the alphabet drawn from.
  let s = '';
  for (let i = 0; i < 100; i++) s += gen.password({ length: 128, symbols: true });
  for (const c of SYMBOLS) assert.ok(s.includes(c), `symbol ${c} is drawn`);
  assert.equal(gen.password({ length: 128, digits: true }).length, 128);
  for (const bad of [{ length: 7, lower: true }, { length: 129, lower: true }, { length: 8.5, lower: true }, { length: 20 }]) {
    assert.throws(() => gen.password(bad), { name: 'RangeError' }, JSON.stringify(bad));
  }
});

test('passphrase has 6 words from the list', () => {
  const gen = load();
  assert.throws(() => gen.passphrase({ words: 6, sep: '-' }), /wordlist/, 'refused before the list is loaded');
  gen.useWordlist(LIST);
  const spaced = gen.passphrase({ words: 6, sep: ' ' }).split(' ');
  assert.equal(spaced.length, 6);
  for (const w of spaced) assert.ok(WORD_SET.has(w), `${w} is a list word, without its dice number`);
  // The default separator is '-', which four list words contain (drop-down, felt-tip, t-shirt, yo-yo).
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const p = gen.passphrase();
    assert.match(p, SIX_WORDS);
    seen.add(p);
  }
  assert.equal(seen.size, 200, 'no repeats');
  assert.equal(gen.passphrase({ words: 8, sep: '.' }).split('.').length, 8);
  assert.throws(() => gen.passphrase({ words: 3 }), { name: 'RangeError' });
  // A list that isn't exactly the 7776 distinct dice words is refused, so the entropy claim can't silently shrink.
  const lines = LIST.split('\n').filter((l) => l !== '');
  for (const bad of [lines.slice(1).join('\n') + '\n', [lines[0], ...lines.slice(0, -1)].join('\n') + '\n',
    lines.map((l) => l.split('\t')[1]).join('\n') + '\n', '<html>error</html>']) {
    assert.throws(() => load().useWordlist(bad), /wordlist/);
  }
});

test('entropy for 6 words is about 77.5 bits', () => {
  const gen = load();
  const six = gen.entropyBits({ words: 6, sep: '-' });
  assert.ok(Math.abs(six - 77.5) < 0.1, String(six));
  assert.ok(Math.abs(six - 6 * Math.log2(7776)) < 1e-9);
  assert.ok(Math.abs(gen.entropyBits({ words: 8 }) - 8 * Math.log2(7776)) < 1e-9);
  // One class: every string of the alphabet qualifies, so the bits are exactly length × log2(alphabet).
  assert.ok(Math.abs(gen.entropyBits({ length: 20, lower: true }) - 20 * Math.log2(26)) < 1e-9);
  assert.ok(Math.abs(gen.entropyBits({ length: 20, digits: true, excludeLookalikes: true }) - 20 * Math.log2(8)) < 1e-9);
  // Several classes: log2 of the exact number of strings that hold every class (inclusion–exclusion, in BigInt).
  const exact = (sizes, len) => {
    let total = 0n;
    for (let mask = 0; mask < 1 << sizes.length; mask++) {
      let left = sizes.reduce((a, b) => a + b, 0);
      let sign = 1n;
      sizes.forEach((s, i) => { if (mask & (1 << i)) { left -= s; sign = -sign; } });
      total += sign * BigInt(left) ** BigInt(len);
    }
    return Math.log2(Number(total));
  };
  const all = { lower: true, upper: true, digits: true, symbols: true };
  assert.ok(Math.abs(gen.entropyBits({ length: 8, ...all }) - exact([26, 26, 10, 32], 8)) < 1e-6);
  assert.ok(Math.abs(gen.entropyBits({ length: 8, ...all, excludeLookalikes: true }) - exact([25, 24, 8, 32], 8)) < 1e-6);
  assert.ok(gen.entropyBits({ length: 8, ...all }) < 8 * Math.log2(94), 'below the naive figure');
  const long = gen.entropyBits({ length: 128, ...all });
  assert.ok(Number.isFinite(long) && Math.abs(long - 128 * Math.log2(94)) < 1e-6);
  assert.throws(() => gen.entropyBits({ length: 20 }), { name: 'RangeError' });
});

test('wordlist has 7776 lines and its sha256 matches VENDOR.md', () => {
  const lines = LIST.split('\n');
  assert.equal(lines.pop(), '', 'ends with a newline');
  assert.equal(lines.length, 7776);
  for (const l of lines) assert.match(l, /^[1-6]{5}\t[a-z-]+$/);
  assert.equal(WORD_SET.size, 7776);
  const recorded = /sha256 \| `([0-9a-f]{64})`/.exec(VENDOR);
  assert.ok(recorded, 'VENDOR.md records a sha256');
  assert.equal(createHash('sha256').update(LIST_BYTES).digest('hex'), recorded[1]);
  assert.match(VENDOR, /CC BY 3\.0/);
  assert.match(VENDOR, /https:\/\/www\.eff\.org\/files\/2016\/07\/18\/eff_large_wordlist\.txt/);
});

test('the editor generate button fills the password field from the generator', async () => {
  const page = loadPage({ crypto: webcrypto, wordlist: LIST, math: poisonedMath() });
  const { doc, fetches } = page;
  const password = doc.getElementById('vault-e-password');
  const panel = doc.querySelector('[data-vault-generator]');
  const out = panel.querySelector('[data-vault-gen-entropy]');
  const button = doc.querySelector('[data-vault-action="generate"]');
  assert.equal(panel.hidden, true);
  assert.equal(button.getAttribute('type'), 'button', 'never submits the form');

  button.click();
  await flush();
  assert.equal(panel.hidden, false);
  assert.equal(button.getAttribute('aria-expanded'), 'true');
  const first = password.value;
  assert.equal(first.length, 24, 'the template default length');
  for (const n of Object.keys(CLASSES)) assert.match(first, CLASSES[n]);
  assert.match(out.textContent, /\d+ bits/);

  panel.querySelector('[data-vault-gen="length"]').value = '9';
  panel.querySelector('[data-vault-gen="symbols"]').checked = false;
  panel.querySelector('[data-vault-gen="length"]').dispatch('change');
  await flush();
  assert.equal(password.value.length, 9);
  assert.doesNotMatch(password.value, CLASSES.symbols);

  const mode = panel.querySelector('[data-vault-gen="mode"]');
  mode.value = 'passphrase';
  mode.dispatch('change');
  await flush();
  assert.match(password.value, SIX_WORDS, 'six list words joined with the default "-"');
  assert.equal(out.textContent, '≈ 77 bits', 'floor of 6 × log2(7776)');
  panel.querySelector('[data-vault-action="regenerate"]').click();
  await flush();
  assert.deepEqual(fetches, [page.wordlistUrl], 'the list is fetched once, from the template URL');

  for (const n of Object.keys(CLASSES)) panel.querySelector(`[data-vault-gen="${n}"]`).checked = false;
  mode.value = 'password';
  const before = password.value;
  mode.dispatch('change');
  await flush();
  assert.equal(out.textContent, page.messages.invalid, 'no class: a message');
  assert.equal(password.value, before, 'and the field is unchanged');

  // Only the latest request writes: a passphrase still waiting on the wordlist can't overwrite a newer password.
  const race = loadPage({ crypto: webcrypto, wordlist: LIST, math: poisonedMath() });
  const rmode = race.doc.querySelector('[data-vault-gen="mode"]');
  race.doc.querySelector('[data-vault-action="generate"]').click();
  rmode.value = 'passphrase';
  rmode.dispatch('change');
  rmode.value = 'password';
  rmode.dispatch('change');
  await flush();
  const raced = race.doc.getElementById('vault-e-password').value;
  assert.equal(raced.length, 24, 'the password, not the passphrase');
  assert.doesNotMatch(raced, SIX_WORDS);

  // Closing the editor clears the entry inputs but leaves the generator's options alone.
  doc.querySelector('[data-vault-action="cancel"]').click();
  assert.equal(password.value, '');
  assert.equal(panel.querySelector('[data-vault-gen="length"]').value, '9');
  assert.equal(panel.querySelector('[data-vault-gen="sep"]').value, '-');
});
