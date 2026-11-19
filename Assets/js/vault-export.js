/*
 * KeePassXC export (spec: KeePassXC import and export → Export). The export page's script, loaded after
 * Assets/vendor/kdbxweb/kdbxweb.js and vault-kdbx.js (and vault-generator.js, vault-webauthn.js) as classic scripts on
 * that page only. No inline JS, eval or WebAssembly, so Kanboard's CSP is unchanged. Sets window.KBVaultExport:
 *
 *   build(entries, password) → Promise<Uint8Array>
 *                     Writes a KDBX 4.0 file (Argon2id with KDF below, ChaCha20, GZip) protected by password (a
 *                     non-empty string). entries is vault/export's answer, {groups, entries}: groups are
 *                     {id, parent_id, name, shared} and entries the full payloads plus group_id (null for an entry
 *                     shared on its own). Own top-level groups go under the root group ("Vault export"); shared ones
 *                     and entries shared on their own go under one group named sharedGroupName. Argon2 runs in
 *                     vault-kdbx.js's module worker (KBVaultKdbx.save), so cancel() stops it.
 *   cancel()          Stops the build in progress (it rejects 'cancelled').
 *   KDF               {memory (bytes), iterations, parallelism}: 64 MiB, 8, 2.
 *   sharedGroupName   The group for shared items ('Shared with me'; the page sets the translated name).
 *
 * Mapping (each entry): title, username, password, URL and notes are KeePass's Title, UserName, Password (protected),
 * URL and Notes; custom fields keep their protection; a non-empty TOTP seed is a protected "otp" field (as KeePassXC
 * names it, and as the import reads it); tags and expiry are kept. Nothing is dropped:
 *   - a custom field whose name is a standard field's, or is taken, becomes "name (2)", "name (3)", …;
 *   - a value XML text can't carry exactly (a control character other than tab and LF, or CR, which an XML parser
 *     turns into LF) is written protected, so its bytes are kept: protected values are stored encrypted, not as text;
 *   - U+FFFE and U+FFFF, which no XML can carry, become U+FFFD (KeePassXC empties a value holding one);
 *   - in a group name, field name or tag (always XML text), every such character becomes U+FFFD.
 * Readers differ on control characters even in protected values: KeePassXC keeps them, pykeepass drops them.
 * Tags are written joined by ';', as KeePassXC writes them; readers split them on ';' and ',' (kdbxweb on ':' too).
 *
 * The page: the vault passphrase (and, when the form has data-vault-hw, a fresh hardware-key assertion from
 * KBVaultWebAuthn) goes to vault/export through KBVault.api (POST + CSRF); the answer is built into a file with the
 * export password the user chose (the T13 generator is offered) and downloaded through a Blob and <a download>. The
 * file never goes through the server. The inputs are cleared as soon as they are read; the answer's entries and
 * groups and the file bytes are dropped or zeroed after the download. Nothing goes to storage or into a URL.
 * Failures show vault.js's messages by code: export_<code> first, then the plain code, then 'failed'.
 */
(function (win) {
  'use strict';

  var doc = win.document;
  var STANDARD = ['Title', 'UserName', 'Password', 'URL', 'Notes'];
  // What XML 1.0 text can't carry exactly: control characters other than tab and LF, and CR (an XML parser turns
  // CR LF into LF); a value with one is written protected. NON_CHARS: what no XML can carry, even encrypted.
  var NOT_XML_TEXT = /[\u0000-\u0008\u000B-\u001F]/;
  var NON_CHARS = /[\uFFFE\uFFFF]/g;
  var NOT_XML_NAME = /[\u0000-\u0008\u000B-\u001F\uFFFE\uFFFF]/g;
  var REVOKE_AFTER_MS = 1500;

  var api = {
    build: build,
    cancel: cancel,
    KDF: { memory: 64 * 1024 * 1024, iterations: 8, parallelism: 2 },
    sharedGroupName: 'Shared with me'
  };
  var cancelled = null;

  function fail(code) {
    var e = new Error('vault export: ' + code);
    e.code = code;
    e.vault = true;
    return e;
  }

  function isObj(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
  }

  function text(v) {
    return typeof v === 'string' ? v : '';
  }

  function xmlName(s) {
    return text(s).replace(NOT_XML_NAME, '\uFFFD');
  }

  // name, or the first "name (n)" not in taken; the result is added to taken.
  function unique(name, taken) {
    var out = name;
    for (var n = 2; Object.prototype.hasOwnProperty.call(taken, out); n++) {
      out = name + ' (' + n + ')';
    }
    taken[out] = true;
    return out;
  }

  // The KeePass strings of one entry: [[name, value, protected], …] in order.
  function strings(e) {
    var out = [
      ['Title', text(e.title), false],
      ['UserName', text(e.username), false],
      ['Password', text(e.password), true],
      ['URL', text(e.url), false],
      ['Notes', text(e.notes), false]
    ];
    var fields = Array.isArray(e.fields) ? e.fields.filter(isObj) : [];
    var taken = {};
    STANDARD.forEach(function (k) {
      taken[k] = true;
    });
    var names = fields.map(function (f) {
      return xmlName(f.name);
    });
    // A field keeps its name when it is the first to have it and no standard field does; the others are renamed.
    var first = {};
    names.forEach(function (n, i) {
      if (!Object.prototype.hasOwnProperty.call(taken, n) && !Object.prototype.hasOwnProperty.call(first, n)) {
        first[n] = i;
      }
    });
    Object.keys(first).forEach(function (n) {
      taken[n] = true;
    });
    fields.forEach(function (f, i) {
      var n = names[i];
      out.push([first[n] === i ? n : unique(n, taken), text(f.value), f.protected === true || n === 'otp']);
    });
    if (text(e.otp) !== '') {
      out.push([unique('otp', taken), text(e.otp), true]);
    }
    return out.map(function (s) {
      var value = s[1].replace(NON_CHARS, '\uFFFD');
      return [s[0], value, s[2] || NOT_XML_TEXT.test(value)];
    });
  }

  function writeEntry(kdbxweb, db, group, e) {
    var entry = db.createEntry(group);
    strings(e).forEach(function (s) {
      entry.fields.set(s[0], s[2] ? kdbxweb.ProtectedValue.fromString(s[1]) : s[1]);
    });
    // Written as KeePassXC writes them, joined by ';' (kdbxweb's own ', ' leaves a leading space on every tag but the
    // first for pykeepass, which doesn't trim).
    var tags = (Array.isArray(e.tags) ? e.tags : []).map(xmlName).filter(function (t) {
      return t !== '';
    });
    entry.tags = tags.length > 0 ? [tags.join(';')] : [];
    if (typeof e.expires_at === 'number' && e.expires_at >= 0) {
      entry.times.expires = true;
      entry.times.expiryTime = new Date(e.expires_at * 1000);
    }
  }

  // The KDBX database for an export answer, before it is saved.
  function database(data, password) {
    var kdbxweb = win.kdbxweb;
    if (!kdbxweb || !win.KBVaultKdbx) {
      throw fail('unavailable');
    }
    if (typeof password !== 'string' || password === '' || !isObj(data) || !Array.isArray(data.groups) || !Array.isArray(data.entries)) {
      throw fail('bad_input');
    }
    var db = kdbxweb.Kdbx.create(new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password)), 'Vault export');
    db.setVersion(4);
    db.setKdf(kdbxweb.Consts.KdfId.Argon2id);
    var kdf = db.header.kdfParameters;
    kdf.set('M', kdbxweb.VarDictionary.ValueType.UInt64, kdbxweb.Int64.from(api.KDF.memory));
    kdf.set('I', kdbxweb.VarDictionary.ValueType.UInt64, kdbxweb.Int64.from(api.KDF.iterations));
    kdf.set('P', kdbxweb.VarDictionary.ValueType.UInt32, api.KDF.parallelism);
    db.header.dataCipherUuid = new kdbxweb.KdbxUuid(kdbxweb.Consts.CipherId.ChaCha20);
    // No recycle bin: Kdbx.create adds one, but an export has nothing deleted.
    var root = db.getDefaultGroup();
    root.groups = root.groups.filter(function (g) {
      return !db.meta.recycleBinUuid || !g.uuid.equals(db.meta.recycleBinUuid);
    });
    db.meta.recycleBinEnabled = false;
    db.meta.recycleBinUuid = new kdbxweb.KdbxUuid();

    var byId = {};
    data.groups.forEach(function (g) {
      if (!isObj(g) || typeof g.id !== 'number') {
        throw fail('bad_input');
      }
      byId[g.id] = g;
    });
    var made = {};
    var shared = null;
    var sharedGroup = function () {
      if (shared === null) {
        shared = db.createGroup(root, xmlName(api.sharedGroupName) || 'Shared with me');
      }
      return shared;
    };
    // A group's KDBX group, its parents first, in the answer's order among siblings.
    var groupOf = function (id, depth) {
      if (Object.prototype.hasOwnProperty.call(made, id)) {
        return made[id];
      }
      var g = byId[id];
      if (!g || depth > data.groups.length) {
        throw fail('bad_input');
      }
      var parent = g.parent_id === null || g.parent_id === undefined ? (g.shared ? sharedGroup() : root) : groupOf(g.parent_id, depth + 1);
      made[id] = db.createGroup(parent, xmlName(g.name));
      return made[id];
    };
    data.groups.forEach(function (g) {
      groupOf(g.id, 0);
    });
    data.entries.forEach(function (e) {
      if (!isObj(e)) {
        throw fail('bad_input');
      }
      writeEntry(kdbxweb, db, e.group_id === null ? sharedGroup() : groupOf(e.group_id, 0), e);
    });
    return db;
  }

  function build(data, password) {
    var mine = { cancelled: false };
    cancelled = mine;
    return Promise.resolve().then(function () {
      var db = database(data, password);
      if (mine.cancelled) {
        throw fail('cancelled');
      }
      return win.KBVaultKdbx.save(db);
    }).then(function (buffer) {
      if (mine.cancelled) {
        throw fail('cancelled');
      }
      return new win.Uint8Array(buffer);
    }).then(function (bytes) {
      if (cancelled === mine) {
        cancelled = null;
      }
      return bytes;
    }, function (e) {
      if (cancelled === mine) {
        cancelled = null;
      }
      throw e && e.vault ? e : fail('save_failed');
    });
  }

  function cancel() {
    if (cancelled) {
      cancelled.cancelled = true;
    }
    if (win.KBVaultKdbx) {
      win.KBVaultKdbx.cancel();
    }
  }

  // ---- The page --------------------------------------------------------------------------------------------------

  function messages() {
    var app = doc && doc.getElementById('vault-app');
    try {
      var m = JSON.parse((app && app.getAttribute('data-messages')) || '{}');
      return isObj(m) ? m : {};
    } catch (e) {
      return {};
    }
  }

  function today() {
    var d = new Date();
    var pad = function (n) {
      return (n < 10 ? '0' : '') + n;
    };
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }

  // Hands the file to the browser as a download; the object URL is revoked shortly after.
  function download(bytes) {
    var blob = new win.Blob([bytes], { type: 'application/octet-stream' });
    var url = win.URL.createObjectURL(blob);
    var a = doc.createElement('a');
    a.setAttribute('href', url);
    a.setAttribute('download', 'vault-export-' + today() + '.kdbx');
    a.hidden = true;
    doc.body.appendChild(a);
    a.click();
    a.parentNode.removeChild(a);
    win.setTimeout(function () {
      win.URL.revokeObjectURL(url);
    }, REVOKE_AFTER_MS);
  }

  function bind(root) {
    var msgs = messages();
    var form = root.querySelector('[data-vault-export-form]');
    var passphrase = root.querySelector('[data-vault-export-passphrase]');
    var password = root.querySelector('[data-vault-export-password]');
    var confirm = root.querySelector('[data-vault-export-confirm]');
    var sharedBox = root.querySelector('[data-vault-export-shared]');
    var submit = root.querySelector('[data-vault-export-submit]');
    var cancelButton = root.querySelector('[data-vault-export-cancel]');
    var progress = root.querySelector('[data-vault-export-progress]');
    var status = root.querySelector('[data-vault-export-status]');
    var report = root.querySelector('[data-vault-export-report]');
    var busy = false;
    if (typeof msgs.shared_entries === 'string' && msgs.shared_entries !== '') {
      api.sharedGroupName = msgs.shared_entries;
    }

    var msg = function (k) {
      return Object.prototype.hasOwnProperty.call(msgs, k) ? String(msgs[k]) : '';
    };
    var say = function (lines, ok) {
      status.textContent = lines.filter(function (l) {
        return l !== '';
      }).join(' ');
      status.classList.toggle('vault-ok', ok);
      status.classList.toggle('vault-bad', !ok);
      status.hidden = false;
    };
    var clear = function () {
      passphrase.value = '';
      password.value = '';
      confirm.value = '';
    };
    var done = function () {
      busy = false;
      submit.disabled = false;
      cancelButton.hidden = true;
      progress.hidden = true;
    };
    var setField = function (name, value) {
      var el = report.querySelector('[data-field="' + name + '"]');
      if (el) {
        el.textContent = String(value);
      }
    };

    // Cancel can come before the build starts (re-auth, hardware key, the server's answer); the build's own cancel
    // can't see that, so the page remembers it and drops the answer.
    var aborted = false;
    cancelButton.addEventListener('click', function () {
      aborted = true;
      cancel();
    });
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (busy) {
        return;
      }
      var body = { passphrase: passphrase.value, include_shared: sharedBox.checked ? '1' : '0' };
      var pw = password.value;
      var again = confirm.value;
      clear();
      if (pw === '') {
        say([msg('export_password_required')], false);
        return;
      }
      if (pw !== again) {
        say([msg('passphrase_mismatch')], false);
        return;
      }
      again = '';
      aborted = false;
      busy = true;
      submit.disabled = true;
      cancelButton.hidden = false;
      report.hidden = true;
      progress.removeAttribute('value');
      progress.hidden = false;
      say([msg('export_checking')], true);
      var answer = null;
      var withKey = form.hasAttribute('data-vault-hw')
        ? (win.KBVaultWebAuthn ? win.KBVaultWebAuthn.assertion('ceremony') : Promise.reject(fail('hw_unsupported'))).then(function (a) {
          body.assertion = a;
          return body;
        })
        : Promise.resolve(body);
      withKey.then(function (b) {
        if (aborted) {
          throw fail('cancelled');
        }
        return win.KBVault.api('export', b);
      }).then(function (a) {
        body.passphrase = '';
        if (aborted) {
          answer = a;
          throw fail('cancelled');
        }
        if (!isObj(a) || a.ok !== true) {
          throw fail(isObj(a) && typeof a.reason === 'string' ? a.reason : 'failed');
        }
        answer = a;
        say([msg('export_building')], true);
        return build(a, pw);
      }).then(function (bytes) {
        pw = '';
        download(bytes);
        bytes.fill(0);
        var count = answer.entries.length;
        var skipped = typeof answer.skipped === 'number' ? answer.skipped : 0;
        setField('entries', count);
        report.hidden = false;
        say([msg('export_done'), skipped > 0 ? msg('export_skipped').replace('{count}', String(skipped)) : ''], true);
      }).catch(function (e) {
        var code = e && typeof e.code === 'string' ? e.code : 'failed';
        say([msg('export_' + code) || msg(code) || msg('failed')], false);
      }).then(function () {
        pw = '';
        body.passphrase = '';
        if (answer && isObj(answer)) {
          if (Array.isArray(answer.entries)) {
            answer.entries.length = 0;
          }
          if (Array.isArray(answer.groups)) {
            answer.groups.length = 0;
          }
        }
        answer = null;
        clear();
        done();
      });
    });
  }

  win.KBVaultExport = api;

  function init() {
    var root = doc && doc.querySelector('[data-vault-export]');
    if (root) {
      bind(root);
    }
  }
  if (doc && typeof doc.querySelector === 'function') {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }
})(window);
