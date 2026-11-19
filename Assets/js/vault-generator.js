/*
 * Vault's password and passphrase generator (spec: UI → The generator). Loaded by the unlocked shell only; no inline
 * JS. Sets window.KBVaultGen:
 *   uniform(n)               an integer in [0, n), by rejection sampling over crypto.getRandomValues (Uint32): draws
 *                            at or past the last whole multiple of n are discarded, so there is no modulo bias.
 *   password(opts)           {length: 8..128, lower, upper, digits, symbols, excludeLookalikes}. Every character is
 *                            drawn uniformly from the union of the selected classes; a draw missing a selected class is
 *                            discarded whole and redrawn. The result is uniform over the passwords that hold every
 *                            selected class, so no position or character is favoured.
 *   passphrase(opts)         {words: 4..20 (6), sep ('-')}: words drawn uniformly from the EFF large wordlist. sep is
 *                            1 to 8 characters and holds no letter (RangeError otherwise), so the words split back out.
 *   entropyBits(opts)        {words, sep} → words × log2(7776), after the same checks. Otherwise log2 of the exact number of passwords
 *                            password(opts) can return (inclusion–exclusion over the selected classes).
 *   useWordlist(text)        takes the vendored eff_large_wordlist.txt as is, keeps the words and drops the dice
 *                            numbers. Anything but 7776 distinct "<5 dice digits>\t<word>" lines is refused.
 *   loadWordlist(url)        fetches that file once (same origin) and calls useWordlist.
 * Its only randomness is crypto.getRandomValues. Generated values go only into the editor's password input (.value).
 */
(function (win) {
  'use strict';

  var doc = win.document;
  var LIST_SIZE = 7776;
  var MIN_LENGTH = 8;
  var MAX_LENGTH = 128;
  var MIN_WORDS = 4;
  var MAX_WORDS = 20;
  var MAX_TRIES = 1000;
  var LOOKALIKES = '0O1lI';
  var CLASSES = [
    ['lower', 'abcdefghijklmnopqrstuvwxyz'],
    ['upper', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
    ['digits', '0123456789'],
    ['symbols', '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~']
  ];
  var TWO_32 = 4294967296;

  var words = null;
  var loading = null;

  function uniform(n) {
    if (typeof n !== 'number' || !Number.isInteger(n) || n < 1 || n > TWO_32) {
      throw new RangeError('uniform: n must be an integer from 1 to 2^32');
    }
    var limit = TWO_32 - (TWO_32 % n);
    var buf = new Uint32Array(1);
    do {
      win.crypto.getRandomValues(buf);
    } while (buf[0] >= limit);
    return buf[0] % n;
  }

  // The selected classes, look-alikes removed, as arrays of characters. Throws on a bad length or no class.
  function classesFor(opts) {
    var o = opts || {};
    var length = o.length;
    if (typeof length !== 'number' || !Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
      throw new RangeError('password: length must be an integer from ' + MIN_LENGTH + ' to ' + MAX_LENGTH);
    }
    var sets = [];
    CLASSES.forEach(function (c) {
      if (o[c[0]] === true) {
        sets.push(c[1].split('').filter(function (ch) {
          return !(o.excludeLookalikes === true && LOOKALIKES.indexOf(ch) !== -1);
        }));
      }
    });
    if (sets.length === 0) {
      throw new RangeError('password: select at least one character class');
    }
    return sets;
  }

  function password(opts) {
    var sets = classesFor(opts);
    var alphabet = [].concat.apply([], sets);
    for (var tries = 0; tries < MAX_TRIES; tries++) {
      var chars = [];
      for (var i = 0; i < opts.length; i++) {
        chars.push(alphabet[uniform(alphabet.length)]);
      }
      var complete = sets.every(function (set) {
        return chars.some(function (ch) {
          return set.indexOf(ch) !== -1;
        });
      });
      if (complete) {
        return chars.join('');
      }
    }
    throw new Error('password: no draw held every class');
  }

  function wordCount(opts) {
    var n = opts && opts.words !== undefined ? opts.words : 6;
    if (typeof n !== 'number' || !Number.isInteger(n) || n < MIN_WORDS || n > MAX_WORDS) {
      throw new RangeError('passphrase: words must be an integer from ' + MIN_WORDS + ' to ' + MAX_WORDS);
    }
    return n;
  }

  // T13 review minor 2: a separator must be 1 to 8 characters with no letter, so every passphrase splits back into
  // its words and the entropy figure holds. An empty or alphabetic one would let two draws read the same.
  function separator(opts) {
    var sep = opts && opts.sep !== undefined ? opts.sep : '-';
    if (typeof sep !== 'string' || sep.length < 1 || sep.length > 8 || /\p{L}/u.test(sep)) {
      throw new RangeError('passphrase: sep must be 1 to 8 characters, none of them a letter');
    }
    return sep;
  }

  function passphrase(opts) {
    var n = wordCount(opts);
    var sep = separator(opts);
    if (!words) {
      throw new Error('passphrase: the wordlist is not loaded');
    }
    var out = [];
    for (var i = 0; i < n; i++) {
      out.push(words[uniform(words.length)]);
    }
    return out.join(sep);
  }

  function entropyBits(opts) {
    if (opts && opts.words !== undefined) {
      separator(opts);
      return wordCount(opts) * Math.log2(LIST_SIZE);
    }
    var sets = classesFor(opts);
    var total = sets.reduce(function (a, s) {
      return a + s.length;
    }, 0);
    // The share of total^length strings that hold every class: sum over subsets S of (-1)^|S| ((total - |S|) / total)^L.
    var share = 0;
    for (var mask = 0; mask < 1 << sets.length; mask++) {
      var left = total;
      var sign = 1;
      for (var i = 0; i < sets.length; i++) {
        if (mask & (1 << i)) {
          left -= sets[i].length;
          sign = -sign;
        }
      }
      share += sign * Math.pow(left / total, opts.length);
    }
    return opts.length * Math.log2(total) + Math.log2(share);
  }

  function useWordlist(text) {
    var lines = typeof text === 'string' ? text.split('\n') : [];
    if (lines.length && lines[lines.length - 1] === '') {
      lines.pop();
    }
    var list = [];
    var seen = {};
    lines.forEach(function (line) {
      var m = /^[1-6]{5}\t([a-z-]+)$/.exec(line);
      if (m && !Object.prototype.hasOwnProperty.call(seen, m[1])) {
        seen[m[1]] = true;
        list.push(m[1]);
      }
    });
    if (lines.length !== LIST_SIZE || list.length !== LIST_SIZE) {
      throw new Error('wordlist: expected ' + LIST_SIZE + ' distinct dice words');
    }
    words = list;
  }

  function loadWordlist(url) {
    if (words) {
      return Promise.resolve();
    }
    if (!loading) {
      loading = Promise.resolve().then(function () {
        return win.fetch(url, { credentials: 'same-origin' });
      }).then(function (res) {
        if (!res || !res.ok) {
          throw new Error('wordlist: not fetched');
        }
        return res.text();
      }).then(useWordlist).then(null, function (e) {
        loading = null;
        throw e;
      });
    }
    return loading;
  }

  // ---- The editor's generator panel ----------------------------------------------------------------------------

  function bind() {
    var button = doc.querySelector('[data-vault-action="generate"]');
    var panel = doc.querySelector('[data-vault-generator]');
    var target = panel && doc.getElementById(panel.getAttribute('data-vault-gen-target') || '');
    if (!button || !panel || !target) {
      return;
    }
    var out = panel.querySelector('[data-vault-gen-entropy]');
    var seq = 0;

    function opt(name) {
      return panel.querySelector('[data-vault-gen="' + name + '"]');
    }

    function msg(name) {
      return panel.getAttribute('data-msg-' + name) || '';
    }

    function options() {
      if (opt('mode').value === 'passphrase') {
        return { words: parseInt(opt('words').value, 10), sep: opt('sep').value };
      }
      var o = { length: parseInt(opt('length').value, 10) };
      ['lower', 'upper', 'digits', 'symbols', 'excludeLookalikes'].forEach(function (k) {
        o[k] = opt(k).checked;
      });
      return o;
    }

    // The editor session the target's form is in (vault-browser.js bumps it on every open and close).
    function session() {
      var form = target.closest ? target.closest('form') : null;
      return form ? form.getAttribute('data-vault-editor-session') : null;
    }

    // Only the latest request writes, and only into the editor session it started in: a slow wordlist fetch can't
    // overwrite a newer password, nor what was typed after Cancel and reopen (T13 review minor 1).
    function generate() {
      var mine = ++seq;
      var started = session();
      var o = options();
      var ready = o.words !== undefined ? loadWordlist(panel.getAttribute('data-wordlist')) : Promise.resolve();
      return ready.then(function () {
        if (mine !== seq || session() !== started) {
          return;
        }
        var value = o.words !== undefined ? passphrase(o) : password(o);
        var bits = entropyBits(o);
        target.value = value;
        out.textContent = '≈ ' + Math.floor(bits) + ' ' + msg('bits');
      }).then(null, function (e) {
        if (mine === seq) {
          out.textContent = e instanceof RangeError ? msg('invalid') : msg('wordlist');
        }
      });
    }

    button.addEventListener('click', function () {
      panel.hidden = !panel.hidden;
      button.setAttribute('aria-expanded', panel.hidden ? 'false' : 'true');
      if (!panel.hidden) {
        generate();
      }
    });
    panel.addEventListener('change', generate);
    var again = panel.querySelector('[data-vault-action="regenerate"]');
    if (again) {
      again.addEventListener('click', generate);
    }
  }

  win.KBVaultGen = {
    uniform: uniform,
    password: password,
    passphrase: passphrase,
    entropyBits: entropyBits,
    useWordlist: useWordlist,
    loadWordlist: loadWordlist
  };

  if (doc && typeof doc.querySelector === 'function') {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', bind);
    } else {
      bind();
    }
  }
})(window);
