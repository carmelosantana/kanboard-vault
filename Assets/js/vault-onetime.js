/*
 * One-time shares in the browser (spec: One-time shares → Creating a share). Loaded by the unlocked shell, which gets
 * the creator's dialog, and by the public share page (Template/share/show.php), where vault-reveal.js uses the crypto.
 * No inline JS. Sets window.KBVaultOnetime:
 *   enc(...fields)       Encoding::enc, byte for byte: "vault/v1", then per field a u32 big-endian length and its bytes.
 *                        A string is its UTF-8 bytes, a Uint8Array its own bytes, a number a u64 big-endian (only
 *                        non-negative safe integers; anything else throws).
 *   shareAd(id, exp, has) the AD enc("share", 1, share_id, expires_at, has_passphrase). share_id is the 32-character
 *                        lowercase hex string as it is in the link (not its raw bytes); expires_at and has_passphrase
 *                        (0 or 1) are integers. The wire contract in ShareModel's header says the same.
 *   encrypt({plaintext, shareId, expiresAt, passphrase?})
 *                        → {ciphertext, iv, salt, has_passphrase, burn_hash, fragment}. k (32 bytes), b (16), the IV
 *                        (12) and the salt (16) come from crypto.getRandomValues only. Without a passphrase the AES-256
 *                        key is k; with one it is HKDF-SHA256(k ‖ Argon2id(p, salt, t=3, m=64 MiB, p=1, 32 bytes),
 *                        salt = empty, info = "vault/share/v1"), the passphrase taken as UTF-8 after NFC. AES-256-GCM
 *                        with a 128-bit tag. ciphertext, iv and salt are base64 (salt '' without a passphrase);
 *                        has_passphrase is 0 or 1; burn_hash is the hex BLAKE2b-256 of b's 16 raw bytes; fragment is
 *                        base64url(k ‖ b) without padding. The plaintext is at most 64 KiB of UTF-8.
 *   decrypt({ciphertext, iv, salt, has_passphrase, fragment, shareId, expiresAt, passphrase?}) → the plaintext.
 *                        Changes none of its arguments, so a failed attempt can be retried on the same ciphertext.
 *   burnHash(bHex), parseFragment(fragment) → {k, b} (Uint8Arrays) or null.
 *   probe()              resolves once a module worker has run one BLAKE2b job here; rejects worker_failed when
 *                        this browser can't start one. The share page runs it before Reveal burns the link.
 * Failures reject with an Error whose .code is one of bad_input, bad_link, payload_too_large, passphrase_required,
 * decrypt_failed, worker_failed. No message carries a secret.
 *
 * Argon2 and BLAKE2b run in argon2-worker.js, a module worker next to this script (its URL comes from this script's
 * own src), one worker per job, terminated after. Nothing here is logged or stored; k and the Argon2 output are zeroed
 * after use.
 *
 * The creator's dialog ([data-vault-onetime], unlocked shell only): "One-time links" in the tree opens it for pasted
 * text; a [data-vault-onetime-field] button in the entry pane opens it for one field of the shown entry, which is read
 * through vault/field (audited as read) only when Create is pressed, and never put on screen. Create reserves
 * (share_reserve), encrypts here, then sends only {share_id, ciphertext, iv, salt, has_passphrase, burn_hash, label}
 * (share_create), and shows the link: the share page's absolute URL, &id=<share_id>, #<fragment>. The passphrase
 * option fills a generated 5-word passphrase (KBVaultGen) and warns that a weak one can be guessed offline. The
 * dialog lists the creator's live links (share_mine) with a Revoke each (share_revoke). Everything reaches the DOM
 * through textContent, an input's value or a fixed attribute.
 */
(function (win) {
  'use strict';

  var doc = win.document;
  var TAG = 'vault/v1';
  var INFO = 'vault/share/v1';
  var MAX_PLAINTEXT = 65536;
  var K_BYTES = 32;
  var B_BYTES = 16;
  var IV_BYTES = 12;
  var SALT_BYTES = 16;
  var ARGON = { t: 3, m: 65536, p: 1, dkLen: 32 };
  var HEX32 = /^[0-9a-f]{32}$/;
  var script = doc && doc.currentScript;
  var WORKER_URL = script && script.src ? new win.URL('argon2-worker.js', script.src).href : null;

  function fail(code) {
    var e = new Error('vault one-time share: ' + code);
    e.code = code;
    return e;
  }

  function utf8(s) {
    return new win.TextEncoder().encode(s);
  }

  function concat(parts) {
    var n = 0;
    parts.forEach(function (p) {
      n += p.length;
    });
    var out = new Uint8Array(n);
    var at = 0;
    parts.forEach(function (p) {
      out.set(p, at);
      at += p.length;
    });
    return out;
  }

  function u32(n) {
    return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  }

  function u64(n) {
    var hi = Math.floor(n / 4294967296);
    var lo = n % 4294967296;
    return concat([u32(hi), u32(lo)]);
  }

  function enc() {
    var parts = [utf8(TAG)];
    Array.prototype.forEach.call(arguments, function (f) {
      var bytes;
      if (typeof f === 'string') {
        bytes = utf8(f);
      } else if (typeof f === 'number' && Number.isSafeInteger(f) && f >= 0) {
        bytes = u64(f);
      } else if (f && typeof f === 'object' && typeof f.length === 'number' && f.BYTES_PER_ELEMENT === 1) {
        bytes = new Uint8Array(f);
      } else {
        throw new TypeError('enc: a field must be a string, bytes or a non-negative safe integer');
      }
      parts.push(u32(bytes.length), bytes);
    });
    return concat(parts);
  }

  function shareAd(shareId, expiresAt, hasPassphrase) {
    return enc('share', 1, shareId, expiresAt, hasPassphrase ? 1 : 0);
  }

  function random(n) {
    var a = new Uint8Array(n);
    win.crypto.getRandomValues(a);
    return a;
  }

  function hex(a) {
    var s = '';
    for (var i = 0; i < a.length; i++) {
      s += (a[i] < 16 ? '0' : '') + a[i].toString(16);
    }
    return s;
  }

  function fromHex(s) {
    var out = new Uint8Array(s.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(s.substr(i * 2, 2), 16);
    }
    return out;
  }

  function b64(a) {
    var s = '';
    for (var i = 0; i < a.length; i++) {
      s += String.fromCharCode(a[i]);
    }
    return win.btoa(s);
  }

  function unb64(s) {
    var bin;
    try {
      bin = win.atob(s);
    } catch (e) {
      throw fail('bad_input');
    }
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function b64url(a) {
    return b64(a).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function parseFragment(fragment) {
    if (typeof fragment !== 'string' || !/^[A-Za-z0-9_-]{64}$/.test(fragment)) {
      return null;
    }
    var raw = unb64(fragment.replace(/-/g, '+').replace(/_/g, '/'));
    if (raw.length !== K_BYTES + B_BYTES) {
      return null;
    }
    return { k: raw.slice(0, K_BYTES), b: raw.slice(K_BYTES) };
  }

  // One job in a fresh module worker; the reply's bytes are copied into this realm.
  function work(msg) {
    return new Promise(function (resolve, reject) {
      if (!WORKER_URL || typeof win.Worker !== 'function') {
        reject(fail('worker_failed'));
        return;
      }
      var w;
      try {
        w = new win.Worker(WORKER_URL, { type: 'module' });
      } catch (e) {
        reject(fail('worker_failed'));
        return;
      }
      var done = function (fn, v) {
        w.terminate();
        fn(v);
      };
      w.onmessage = function (ev) {
        var d = ev && ev.data;
        if (d && d.id === msg.id && d.hash) {
          done(resolve, new Uint8Array(d.hash));
        } else {
          done(reject, fail('worker_failed'));
        }
      };
      w.onerror = function () {
        done(reject, fail('worker_failed'));
      };
      w.postMessage(msg);
    });
  }

  function probe() {
    return work({ id: 1, type: 'blake2b', data: new Uint8Array(1), dkLen: 32 }).then(function () {
      return true;
    });
  }

  function burnHash(bHex) {
    if (typeof bHex !== 'string' || !HEX32.test(bHex)) {
      return Promise.reject(fail('bad_input'));
    }
    return work({ id: 1, type: 'blake2b', data: fromHex(bHex), dkLen: 32 }).then(hex);
  }

  function passphraseBytes(p) {
    return utf8(String(p).normalize('NFC'));
  }

  // The AES key: k itself, or HKDF-SHA256(k ‖ Argon2id(p, salt)) with a passphrase.
  function shareKey(k, passphrase, salt, usage) {
    var subtle = win.crypto.subtle;
    if (salt === null) {
      return subtle.importKey('raw', k, { name: 'AES-GCM' }, false, [usage]);
    }
    return work({ id: 1, type: 'argon2id', password: passphraseBytes(passphrase), salt: salt, t: ARGON.t, m: ARGON.m, p: ARGON.p, dkLen: ARGON.dkLen })
      .then(function (a) {
        var ikm = concat([k, a]);
        a.fill(0);
        return subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']).then(function (base) {
          ikm.fill(0);
          return subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(INFO) },
            base,
            { name: 'AES-GCM', length: 256 },
            false,
            [usage]
          );
        });
      });
  }

  function checkShare(shareId, expiresAt) {
    if (typeof shareId !== 'string' || !HEX32.test(shareId) || typeof expiresAt !== 'number' || !Number.isSafeInteger(expiresAt) || expiresAt < 0) {
      throw fail('bad_input');
    }
  }

  function encrypt(opts) {
    return Promise.resolve().then(function () {
      opts = opts || {};
      checkShare(opts.shareId, opts.expiresAt);
      if (typeof opts.plaintext !== 'string') {
        throw fail('bad_input');
      }
      var plain = utf8(opts.plaintext);
      if (plain.length > MAX_PLAINTEXT) {
        throw fail('payload_too_large');
      }
      var has = typeof opts.passphrase === 'string' && opts.passphrase !== '';
      var k = random(K_BYTES);
      var b = random(B_BYTES);
      var iv = random(IV_BYTES);
      var salt = has ? random(SALT_BYTES) : null;
      var fragment = b64url(concat([k, b]));
      var bHex = hex(b);
      return shareKey(k, opts.passphrase, salt, 'encrypt').then(function (key) {
        k.fill(0);
        b.fill(0);
        return win.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: shareAd(opts.shareId, opts.expiresAt, has), tagLength: 128 }, key, plain);
      }).then(function (ct) {
        plain.fill(0);
        return burnHash(bHex).then(function (burn) {
          return {
            ciphertext: b64(new Uint8Array(ct)),
            iv: b64(iv),
            salt: has ? b64(salt) : '',
            has_passphrase: has ? 1 : 0,
            burn_hash: burn,
            fragment: fragment
          };
        });
      });
    });
  }

  function flag(v) {
    return v === true || v === 1 || v === '1';
  }

  function decrypt(opts) {
    return Promise.resolve().then(function () {
      opts = opts || {};
      checkShare(opts.shareId, opts.expiresAt);
      var parts = parseFragment(opts.fragment);
      if (!parts) {
        throw fail('bad_link');
      }
      var has = flag(opts.has_passphrase);
      if (typeof opts.ciphertext !== 'string' || typeof opts.iv !== 'string') {
        throw fail('bad_input');
      }
      var ct = unb64(opts.ciphertext);
      var iv = unb64(opts.iv);
      var salt = has ? unb64(String(opts.salt || '')) : null;
      if (iv.length !== IV_BYTES || ct.length < 16 || (has && salt.length !== SALT_BYTES)) {
        throw fail('bad_input');
      }
      if (has && (typeof opts.passphrase !== 'string' || opts.passphrase === '')) {
        throw fail('passphrase_required');
      }
      return shareKey(parts.k, opts.passphrase, salt, 'decrypt').then(function (key) {
        parts.k.fill(0);
        return win.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, additionalData: shareAd(opts.shareId, opts.expiresAt, has), tagLength: 128 }, key, ct)
          .then(null, function () {
            throw fail('decrypt_failed');
          });
      }).then(function (plain) {
        return new win.TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(plain));
      });
    });
  }

  win.KBVaultOnetime = {
    enc: enc,
    shareAd: shareAd,
    encrypt: encrypt,
    decrypt: decrypt,
    burnHash: burnHash,
    parseFragment: parseFragment,
    probe: probe
  };

  // ---- The creator's dialog ----------------------------------------------------------------------------------

  var ui = null;

  function q(sel, root) {
    return (root || doc).querySelector(sel);
  }

  function kb() {
    return win.KBVault;
  }

  function msg(name) {
    return (ui && ui.dialog.getAttribute('data-msg-' + name)) || '';
  }

  function say(text) {
    ui.status.textContent = text;
    ui.status.hidden = text === '';
  }

  function clear(node) {
    while (node.firstChild || (node.children && node.children.length)) {
      node.removeChild(node.firstChild || node.children[0]);
    }
  }

  function el(tag, cls, content) {
    var e = doc.createElement(tag);
    if (cls) {
      e.className = cls;
    }
    if (content !== undefined) {
      e.textContent = content === null ? '' : String(content);
    }
    return e;
  }

  function endpoint(name) {
    var app = doc.getElementById('vault-app');
    try {
      var all = JSON.parse((app && app.getAttribute('data-endpoints')) || '{}');
      return typeof all[name] === 'string' ? all[name] : null;
    } catch (e) {
      return null;
    }
  }

  function day(ts) {
    var d = new Date(ts * 1000);
    return isNaN(d.getTime()) ? '' : d.toLocaleString();
  }

  function open(source) {
    ui.seq++;
    ui.source = source;
    ui.text.value = '';
    ui.text.hidden = source !== null;
    ui.textLabel.hidden = source !== null;
    ui.sourceNote.hidden = source === null;
    ui.sourceNote.textContent = source === null ? '' : msg('field').replace('{field}', source.label).replace('{title}', source.title);
    ui.label.value = '';
    ui.result.hidden = true;
    ui.link.value = '';
    say('');
    ui.dialog.hidden = false;
    loadMine();
  }

  function close() {
    ui.seq++;
    ui.dialog.hidden = true;
    ui.text.value = '';
    ui.link.value = '';
    ui.pass.value = '';
    ui.usePass.checked = false;
    ui.passRow.hidden = true;
    ui.source = null;
    ui.result.hidden = true;
  }

  function suggest() {
    var gen = win.KBVaultGen;
    if (!gen) {
      return;
    }
    var mine = ui.seq;
    gen.loadWordlist(ui.dialog.getAttribute('data-wordlist')).then(function () {
      if (mine === ui.seq && ui.usePass.checked) {
        ui.pass.value = gen.passphrase({ words: 5, sep: '-' });
      }
    }, function () {
      say(msg('wordlist'));
    });
  }

  function togglePass() {
    ui.passRow.hidden = !ui.usePass.checked;
    if (ui.usePass.checked && ui.pass.value === '') {
      suggest();
    }
    if (!ui.usePass.checked) {
      ui.pass.value = '';
    }
  }

  function readSource(source) {
    if (source === null) {
      return Promise.resolve(ui.text.value);
    }
    return kb().api('field', { id: source.id, field: source.field }).then(function (res) {
      if (!res || !res.ok || typeof res.value !== 'string') {
        throw fail('field_failed');
      }
      return res.value;
    });
  }

  function create() {
    if (ui.busy) {
      return;
    }
    var source = ui.source;
    var passphrase = ui.usePass.checked ? ui.pass.value : '';
    if (ui.usePass.checked && passphrase === '') {
      say(msg('no-passphrase'));
      return;
    }
    if (source === null && ui.text.value === '') {
      say(msg('empty'));
      return;
    }
    var mine = ui.seq;
    var expiry = ui.expiry.value;
    var label = ui.label.value;
    ui.busy = true;
    ui.createBtn.disabled = true;
    say(msg('working'));
    var reserved = null;
    readSource(source).then(function (text) {
      if (text === '') {
        throw fail('empty');
      }
      return kb().api('share_reserve', { expiry: expiry }).then(function (res) {
        if (!res || !res.ok) {
          throw fail((res && res.reason) || 'failed');
        }
        reserved = res;
        return encrypt({ plaintext: text, shareId: res.share_id, expiresAt: res.expires_at, passphrase: passphrase });
      });
    }).then(function (s) {
      return kb().api('share_create', {
        share_id: reserved.share_id,
        ciphertext: s.ciphertext,
        iv: s.iv,
        salt: s.salt,
        has_passphrase: s.has_passphrase,
        burn_hash: s.burn_hash,
        label: label
      }).then(function (res) {
        if (!res || !res.ok) {
          throw fail((res && res.reason) || 'failed');
        }
        return s.fragment;
      });
    }).then(function (fragment) {
      if (mine !== ui.seq) {
        return;
      }
      var url = new win.URL(endpoint('share_show') || '', win.location.href);
      url.searchParams.set('id', reserved.share_id);
      url.hash = fragment;
      ui.text.value = '';
      ui.link.value = url.href;
      ui.result.hidden = false;
      say(ui.usePass.checked ? msg('send-passphrase') : '');
      loadMine();
    }, function (e) {
      if (mine === ui.seq) {
        say((e && e.code && msg('error-' + e.code)) || msg('failed'));
      }
    }).then(function () {
      ui.busy = false;
      ui.createBtn.disabled = false;
    });
  }

  function loadMine() {
    var mine = ui.seq;
    return kb().api('share_mine', {}).then(function (res) {
      if (mine !== ui.seq || !res || !res.ok) {
        return;
      }
      clear(ui.list);
      var links = Array.isArray(res.links) ? res.links : [];
      links.forEach(function (l) {
        var li = el('li', 'vault-ot-link');
        li.appendChild(el('span', 'vault-ot-label', l.label === null || l.label === undefined || l.label === '' ? msg('no-label') : l.label));
        li.appendChild(el('span', 'vault-muted', ' ' + msg('expires') + ' ' + day(l.expires_at) + (l.has_passphrase ? ' · ' + msg('with-passphrase') : '')));
        var b = el('button', 'btn btn-small', msg('revoke'));
        b.type = 'button';
        b.setAttribute('data-vault-ot-revoke', String(l.id_hash));
        li.appendChild(b);
        ui.list.appendChild(li);
      });
      ui.none.hidden = links.length > 0;
    });
  }

  function onListClick(ev) {
    var b = ev.target && ev.target.closest ? ev.target.closest('[data-vault-ot-revoke]') : null;
    if (!b || !win.confirm(msg('confirm-revoke'))) {
      return;
    }
    b.disabled = true;
    kb().api('share_revoke', { id_hash: b.getAttribute('data-vault-ot-revoke') }).then(function (res) {
      say(res && res.ok ? msg('revoked') : msg('failed'));
      loadMine();
    });
  }

  function onFieldClick(ev) {
    var b = ev.target && ev.target.closest ? ev.target.closest('[data-vault-onetime-field]') : null;
    var detail = q('[data-vault-detail]');
    var id = detail ? parseInt(detail.getAttribute('data-vault-entry-id') || '', 10) : NaN;
    if (!b || !(id > 0)) {
      return;
    }
    ev.preventDefault();
    var title = q('[data-field="title"]', detail);
    var field = b.getAttribute('data-vault-onetime-field');
    open({ id: id, field: field, label: b.getAttribute('data-vault-onetime-label') || field, title: title ? title.textContent : '' });
  }

  function bind() {
    var dialog = q('[data-vault-onetime]');
    if (!dialog || !kb()) {
      return;
    }
    ui = {
      dialog: dialog,
      seq: 0,
      busy: false,
      source: null,
      text: q('[data-vault-ot-text]', dialog),
      textLabel: q('[data-vault-ot-text-label]', dialog),
      sourceNote: q('[data-vault-ot-source]', dialog),
      label: q('[data-vault-ot-label]', dialog),
      expiry: q('[data-vault-ot-expiry]', dialog),
      usePass: q('[data-vault-ot-use-pass]', dialog),
      passRow: q('[data-vault-ot-pass-row]', dialog),
      pass: q('[data-vault-ot-pass]', dialog),
      createBtn: q('[data-vault-action="onetime-create"]', dialog),
      status: q('[data-vault-ot-status]', dialog),
      result: q('[data-vault-ot-result]', dialog),
      link: q('[data-vault-ot-link]', dialog),
      list: q('[data-vault-ot-list]', dialog),
      none: q('[data-vault-ot-none]', dialog)
    };
    Array.prototype.forEach.call(doc.querySelectorAll('[data-vault-action="onetime-new"]'), function (b) {
      b.addEventListener('click', function (ev) {
        ev.preventDefault();
        open(null);
      });
    });
    var detail = q('[data-vault-detail]');
    if (detail) {
      detail.addEventListener('click', onFieldClick);
    }
    q('[data-vault-action="onetime-close"]', dialog).addEventListener('click', close);
    ui.createBtn.addEventListener('click', function (ev) {
      ev.preventDefault();
      create();
    });
    q('[data-vault-action="onetime-generate"]', dialog).addEventListener('click', function (ev) {
      ev.preventDefault();
      suggest();
    });
    q('[data-vault-action="onetime-copy"]', dialog).addEventListener('click', function () {
      var api = kb();
      if (api && typeof api.copy === 'function' && ui.link.value !== '') {
        api.copy(ui.link.value);
      }
    });
    ui.usePass.addEventListener('change', togglePass);
    ui.list.addEventListener('click', onListClick);
  }

  if (doc && typeof doc.querySelector === 'function') {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', bind);
    } else {
      bind();
    }
  }
})(window);
