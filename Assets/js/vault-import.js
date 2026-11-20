/*
 * KeePassXC import (spec: KeePassXC import and export → Import). Loaded only by Template/vault/import.php, after
 * vault.js, kdbxweb.js, vault-kdbx.js and vault-kdbx-header.js; no inline JS. The database is opened and mapped here,
 * on the page; the server only ever sees Vault entry payloads, never the file, its name or its master password.
 *
 *   1. KBVaultKdbxHeader.check refuses a file before kdbxweb reads it (size, KDF work, Twofish, broken framing).
 *   2. KBVaultKdbx.load opens it (Argon2 in the worker; Cancel terminates it). A wrong key also says what to do with
 *      a YubiKey challenge-response database, which no header shows (yubikey_cr).
 *   3. map(): groups become Vault groups (a path of names below "Imported <date>"; same-named siblings get " (2)" …).
 *      Each entry keeps title, username, password, URL, notes, tags, expiry and its custom fields with their
 *      protection; `otp` becomes a protected custom field. Attachments are counted and skipped; history, icons and
 *      auto-type are dropped.
 *   4. Refused before anything is sent: over LIMITS.entries entries, or any entry over LIMITS.entryBytes of JSON.
 *   5. upload(): vault/import/start {total} → {import_id}, then vault/import/batch {import_id, group_path, entries}
 *      → {created}, at most LIMITS.batchEntries entries (and about LIMITS.batchBytes) per POST, through KBVault.api
 *      (POST with the CSRF token). A group with no entries is sent as an empty batch, so it exists too.
 *
 * The opened database and the mapped entries live only in this page's memory, never in storage. When the import ends,
 * fails or is cancelled, the file and key-file bytes are zeroed, the inputs are cleared and every reference is dropped
 * (a JS string can't be zeroed). Sets window.KBVaultImport = {LIMITS, open, prepare, map, batches, upload, cancel,
 * messageKeys}.
 */
(function (win) {
  'use strict';

  var doc = win.document;
  var LIMITS = { entries: 20000, entryBytes: 262144, batchEntries: 100, batchBytes: 2 * 1024 * 1024 };
  var STANDARD = { Title: 'title', UserName: 'username', Password: 'password', URL: 'url', Notes: 'notes' };
  var encoder = new win.TextEncoder();
  var cancelled = false;

  function fail(code) {
    var e = new Error('vault import: ' + code);
    e.code = code;
    return e;
  }

  function text(v) {
    if (v === undefined || v === null) {
      return '';
    }
    return typeof v === 'string' ? v : (v && typeof v.getText === 'function' ? v.getText() : String(v));
  }

  function isProtected(v) {
    return !!v && typeof v !== 'string' && typeof v.getText === 'function';
  }

  function payloadOf(entry) {
    var p = { title: '', username: '', password: '', url: '', notes: '', tags: [], expires_at: null, otp: '', fields: [] };
    entry.fields.forEach(function (value, name) {
      if (Object.prototype.hasOwnProperty.call(STANDARD, name)) {
        p[STANDARD[name]] = text(value);
      } else if (name !== '') {
        p.fields.push({ name: name, value: text(value), protected: name === 'otp' || isProtected(value) });
      }
    });
    p.tags = (entry.tags || []).filter(function (t) {
      return typeof t === 'string' && t !== '';
    });
    var times = entry.times || {};
    if (times.expires && times.expiryTime instanceof Date && !isNaN(times.expiryTime.getTime())) {
      var at = Math.floor(times.expiryTime.getTime() / 1000);
      p.expires_at = at >= 0 ? at : null;
    }
    return p;
  }

  // Sibling groups' names, kept apart: '' becomes "Group", a repeat gets " (2)", " (3)" …
  function uniqueNames(groups) {
    var used = {};
    return groups.map(function (g) {
      var base = typeof g.name === 'string' && g.name !== '' ? g.name : 'Group';
      var name = base;
      for (var n = 2; Object.prototype.hasOwnProperty.call(used, name); n++) {
        name = base + ' (' + n + ')';
      }
      used[name] = true;
      return name;
    });
  }

  // Every entry in a group and the groups below it.
  function countEntries(group) {
    return group.groups.reduce(function (n, child) {
      return n + countEntries(child);
    }, group.entries.length);
  }

  // kdbxweb database → {entries: [{path, payload}], groups: [path] (every group, entries or not), skippedAttachments,
  // skippedRecycled}. The Recycle Bin (db.meta.recycleBinUuid) holds deleted entries: it and everything below it is
  // skipped, its entries counted, so nothing the user deleted comes back.
  function map(db) {
    var out = { entries: [], groups: [], skippedAttachments: 0, skippedRecycled: 0 };
    var bin = db.meta && db.meta.recycleBinUuid;
    (function walk(group, path) {
      if (bin && group.uuid && group.uuid.equals(bin)) {
        out.skippedRecycled += countEntries(group);
        return;
      }
      out.groups.push(path);
      group.entries.forEach(function (entry) {
        out.skippedAttachments += entry.binaries && entry.binaries.size ? entry.binaries.size : 0;
        out.entries.push({ path: path, payload: payloadOf(entry) });
      });
      var names = uniqueNames(group.groups);
      group.groups.forEach(function (child, i) {
        walk(child, path.concat([names[i]]));
      });
    })(db.getDefaultGroup(), []);
    return out;
  }

  function size(payload) {
    return encoder.encode(JSON.stringify(payload)).length;
  }

  // The refusals that come before any upload: too many entries, or one too large.
  function limit(mapped) {
    if (mapped.entries.length > LIMITS.entries) {
      throw fail('import_limit');
    }
    mapped.entries.forEach(function (e) {
      if (size(e.payload) > LIMITS.entryBytes) {
        throw fail('import_limit');
      }
    });
  }

  // [{group_path, entries}] in tree order: each group's entries in POSTs of at most batchEntries entries and about
  // batchBytes, and an empty batch for a group with none.
  function batches(mapped) {
    var byPath = {};
    var order = [];
    mapped.groups.forEach(function (path) {
      var key = JSON.stringify(path);
      if (!byPath[key]) {
        byPath[key] = { path: path, entries: [] };
        order.push(key);
      }
    });
    mapped.entries.forEach(function (e) {
      var key = JSON.stringify(e.path);
      if (!byPath[key]) {
        byPath[key] = { path: e.path, entries: [] };
        order.push(key);
      }
      byPath[key].entries.push(e.payload);
    });
    var out = [];
    order.forEach(function (key) {
      var g = byPath[key];
      var current = { group_path: g.path, entries: [] };
      var bytes = 0;
      g.entries.forEach(function (payload) {
        var n = size(payload);
        if (current.entries.length >= LIMITS.batchEntries || (current.entries.length > 0 && bytes + n > LIMITS.batchBytes)) {
          out.push(current);
          current = { group_path: g.path, entries: [] };
          bytes = 0;
        }
        current.entries.push(payload);
        bytes += n;
      });
      // A group with no entries still gets one (empty) batch, so it exists in Vault too.
      if (current.entries.length > 0 || g.entries.length === 0) {
        out.push(current);
      }
    });
    return out;
  }

  // An opened database → {batches, total, groups, skippedAttachments, skippedRecycled}, or import_limit. groups: the groups made
  // below "Imported <date>" (the database's root is that group itself).
  function prepare(db) {
    var mapped = map(db);
    limit(mapped);
    return { batches: batches(mapped), total: mapped.entries.length, groups: mapped.groups.length - 1, skippedAttachments: mapped.skippedAttachments, skippedRecycled: mapped.skippedRecycled };
  }

  // The file (and key file) bytes → the batches to send. Rejects with .code: a pre-check reason, a KBVaultKdbx code,
  // or import_limit. The given bytes are zeroed whatever happens.
  function open(fileBytes, password, keyBytes) {
    cancelled = false;
    var zero = function () {
      if (fileBytes instanceof Uint8Array) {
        fileBytes.fill(0);
      }
      if (keyBytes instanceof Uint8Array) {
        keyBytes.fill(0);
      }
    };
    return Promise.resolve().then(function () {
      var header = win.KBVaultKdbxHeader.check(fileBytes);
      if (!header.ok) {
        throw fail(header.reason);
      }
      return win.KBVaultKdbx.load(fileBytes, password, keyBytes || undefined);
    }).then(function (db) {
      if (cancelled) {
        throw fail('cancelled');
      }
      var prepared = prepare(db);
      db = null;
      return prepared;
    }).then(function (r) {
      zero();
      return r;
    }, function (e) {
      zero();
      throw e && typeof e.code === 'string' ? fail(e.code) : fail('load_failed');
    });
  }

  // Sends the batches through api(action, body) (KBVault.api). onProgress(sent entries) after each batch. Resolves to
  // {created}; rejects with .code (the server's reason, or cancelled) and .created (entries already stored).
  function upload(prepared, api, onProgress) {
    var created = 0;
    var stop = function (code) {
      var e = fail(code);
      e.created = created;
      throw e;
    };
    return api('import_start', { total: prepared.total }).then(function (res) {
      if (!res || !res.ok || typeof res.import_id !== 'number') {
        stop(res && typeof res.reason === 'string' ? res.reason : 'failed');
      }
      var id = res.import_id;
      var i = 0;
      var next = function () {
        if (cancelled) {
          stop('cancelled');
        }
        if (i >= prepared.batches.length) {
          return { created: created };
        }
        var b = prepared.batches[i];
        prepared.batches[i] = null;
        i += 1;
        return api('import_batch', { import_id: id, group_path: b.group_path, entries: b.entries }).then(function (r) {
          if (!r || !r.ok || typeof r.created !== 'number') {
            stop(r && typeof r.reason === 'string' ? r.reason : 'failed');
          }
          created += r.created;
          if (onProgress) {
            onProgress(created);
          }
          return next();
        });
      };
      return next();
    });
  }

  function cancel() {
    cancelled = true;
    if (win.KBVaultKdbx) {
      win.KBVaultKdbx.cancel();
    }
  }

  // The message keys for a failure: import_<reason>, and for a wrong key also the YubiKey hint.
  function messageKeys(reason) {
    var keys = ['import_' + reason];
    if (reason === 'invalid_key') {
      keys.push('import_yubikey_cr');
    }
    return keys;
  }

  // --- The page ---------------------------------------------------------------------------------------------------

  function messages() {
    var el = doc.getElementById('vault-app');
    try {
      var m = JSON.parse((el && el.getAttribute('data-messages')) || '');
      return m && typeof m === 'object' ? m : {};
    } catch (e) {
      return {};
    }
  }

  function readFile(input) {
    var f = input && input.files && input.files[0];
    if (!f) {
      return Promise.resolve(null);
    }
    return f.arrayBuffer().then(function (buf) {
      return new Uint8Array(buf);
    });
  }

  function bind(root) {
    var msgs = messages();
    var form = root.querySelector('[data-vault-import-form]');
    var file = root.querySelector('[data-vault-import-file]');
    var key = root.querySelector('[data-vault-import-keyfile]');
    var password = root.querySelector('[data-vault-import-password]');
    var submit = root.querySelector('[data-vault-import-submit]');
    var cancelButton = root.querySelector('[data-vault-import-cancel]');
    var progress = root.querySelector('[data-vault-import-progress]');
    var status = root.querySelector('[data-vault-import-status]');
    var report = root.querySelector('[data-vault-import-report]');
    var busy = false;

    var say = function (lines, ok) {
      status.textContent = lines.join(' ');
      status.classList.toggle('vault-ok', ok);
      status.classList.toggle('vault-bad', !ok);
      status.hidden = false;
    };
    var msg = function (k) {
      return Object.prototype.hasOwnProperty.call(msgs, k) ? msgs[k] : '';
    };
    // import_<code> first, then the plain reason (a server reason such as payload_too_large or import_limit).
    var failure = function (code) {
      var keys = messageKeys(code);
      var lines = [msg(keys[0]) || msg(code) || msg('failed')];
      keys.slice(1).forEach(function (k) {
        if (msg(k) !== '') {
          lines.push(msg(k));
        }
      });
      return lines;
    };
    var clear = function () {
      password.value = '';
      file.value = '';
      if (key) {
        key.value = '';
      }
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

    cancelButton.addEventListener('click', function () {
      cancel();
    });
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (busy) {
        return;
      }
      busy = true;
      submit.disabled = true;
      cancelButton.hidden = false;
      report.hidden = true;
      progress.removeAttribute('value');
      progress.hidden = false;
      say([msg('import_opening')], true);
      var pw = password.value;
      password.value = '';
      Promise.all([readFile(file), readFile(key)]).then(function (files) {
        if (!files[0]) {
          throw fail('not_kdbx');
        }
        var opening = open(files[0], pw, files[1]);
        pw = '';
        return opening;
      }).then(function (prepared) {
        progress.max = Math.max(prepared.total, 1);
        progress.value = 0;
        say([msg('import_uploading')], true);
        var api = function (action, body) {
          return win.KBVault.api(action, body);
        };
        return upload(prepared, api, function (n) {
          progress.value = n;
        }).then(function (r) {
          setField('created', r.created);
          setField('groups', prepared.groups);
          setField('skipped_attachments', prepared.skippedAttachments);
          setField('skipped_recycled', prepared.skippedRecycled);
          prepared.batches.length = 0;
          report.hidden = false;
          say([msg('import_done')], true);
        });
      }).catch(function (e) {
        pw = '';
        var code = e && typeof e.code === 'string' ? e.code : 'failed';
        var lines = failure(code);
        if (e && typeof e.created === 'number' && e.created > 0) {
          lines.push(msg('import_partial').replace('{count}', String(e.created)));
        }
        say(lines, false);
      }).then(function () {
        clear();
        done();
      });
    });
  }

  win.KBVaultImport = { LIMITS: LIMITS, open: open, prepare: prepare, map: map, batches: batches, upload: upload, cancel: cancel, messageKeys: messageKeys };

  function init() {
    var root = doc && doc.querySelector('[data-vault-import]');
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
