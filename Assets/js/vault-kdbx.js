/*
 * Opening KeePass (KDBX) files on the page (spec: KeePassXC import and export → Where the code runs). Loaded as a
 * classic script after Assets/vendor/kdbxweb/kdbxweb.js (2.1.1 with Vault's reviewed patches; VENDOR.md). kdbxweb
 * runs here because a worker has no DOMParser; only Argon2 runs in argon2-worker.js, a module worker next to this
 * script (its URL comes from this script's own src), wired in through kdbxweb.CryptoEngine.setArgon2Impl. No inline
 * JS, eval or WebAssembly, so Kanboard's CSP is unchanged. Sets window.KBVaultKdbx:
 *   load(fileBytes, password, keyFileBytes?) → Promise<kdbxweb.Kdbx>
 *                        fileBytes and keyFileBytes are Uint8Array (a view's own bytes only) or ArrayBuffer, copied,
 *                        so the caller's bytes are not changed. password is a string. '' is tried as no password
 *                        part (a key-file-only database), then, if that key is wrong, as a literally empty password,
 *                        as KeePassXC does. One load at a time.
 *   cancel()             Stops the load in progress: terminates its Argon2 worker, and the load rejects 'cancelled'.
 *   argon2TimeoutMs      How long one Argon2 job may run (120000 by default) before its worker is terminated and the
 *                        load rejects 'timeout'.
 * Failures reject with an Error whose .code is one of bad_input, busy, unavailable, cancelled, timeout, kdf_limits,
 * worker_failed, not_kdbx, invalid_key, file_corrupt, unsupported, too_large, load_failed. No message carries a
 * secret. too_large: the payload would inflate past kdbxweb.KdbxFormat.inflateLimit (Vault patch 04, 256 MiB).
 *
 * Argon2 limits: the worker refuses m > 1 GiB, t > 100, p > 8 (the spec's import caps) and answers kdf_limits, so a
 * hostile header can't make it allocate or spin, even if the caller skipped the import pre-check. Each job runs in a
 * fresh worker that is terminated after its answer, on timeout and on cancel. The credential hash is copied into the
 * job and that copy is transferred (the worker zeroes it); the worker's answer is copied out and zeroed, and kdbxweb
 * zeroes its own copy (patch 03).
 */
(function (win) {
  'use strict';

  var kdbxweb = win.kdbxweb;
  var doc = win.document;
  var script = doc && doc.currentScript;
  var WORKER_URL = script && script.src ? new win.URL('argon2-worker.js', script.src).href : null;
  var DEFAULT_TIMEOUT_MS = 120000;
  var KDBX_CODES = {
    BadSignature: 'not_kdbx',
    InvalidVersion: 'unsupported',
    Unsupported: 'unsupported',
    InvalidKey: 'invalid_key',
    FileCorrupt: 'file_corrupt',
    InflateLimit: 'too_large'
  };

  var api = { load: load, cancel: cancel, argon2TimeoutMs: DEFAULT_TIMEOUT_MS };
  // The load in progress: {cancelled, jobs}. A job is {stop(code)} for a running worker.
  var op = null;

  function fail(code) {
    var e = new Error('vault kdbx: ' + code);
    e.code = code;
    e.vault = true;
    return e;
  }

  function bytes(v) {
    if (v instanceof ArrayBuffer) {
      return new Uint8Array(v.slice(0));
    }
    if (v instanceof Uint8Array) {
      return v.slice();
    }
    return null;
  }

  function timeoutMs() {
    var t = api.argon2TimeoutMs;
    return typeof t === 'number' && t > 0 && t < Infinity ? t : DEFAULT_TIMEOUT_MS;
  }

  // kdbxweb's Argon2Fn: (password, salt, memory KiB, iterations, length, parallelism, type, version) → bytes.
  function argon2(password, salt, memory, iterations, length, parallelism, type, version) {
    return new Promise(function (resolve, reject) {
      var name = type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? 'argon2id'
        : type === kdbxweb.CryptoEngine.Argon2TypeArgon2d ? 'argon2d' : null;
      if (op && op.cancelled) {
        reject(fail('cancelled'));
        return;
      }
      if (name === null) {
        reject(fail('unsupported'));
        return;
      }
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
      var jobs = op ? op.jobs : [];
      var done = false;
      var timer = null;
      var job = {
        stop: function (code, hash) {
          if (done) {
            return;
          }
          done = true;
          win.clearTimeout(timer);
          w.terminate();
          var i = jobs.indexOf(job);
          if (i >= 0) {
            jobs.splice(i, 1);
          }
          if (code === null) {
            resolve(hash);
          } else {
            reject(fail(code));
          }
        }
      };
      jobs.push(job);
      timer = win.setTimeout(function () {
        job.stop('timeout');
      }, timeoutMs());
      w.onmessage = function (ev) {
        var d = ev && ev.data;
        if (d && d.id === 1 && d.hash instanceof Uint8Array && d.hash.length === length) {
          var out = new Uint8Array(d.hash);
          d.hash.fill(0);
          job.stop(null, out);
        } else {
          job.stop(d && d.error === 'bad_params' ? 'kdf_limits' : 'worker_failed');
        }
      };
      w.onerror = function () {
        job.stop('worker_failed');
      };
      var pw = new Uint8Array(password.byteLength);
      pw.set(new Uint8Array(password));
      w.postMessage({
        id: 1, type: name, password: pw, salt: new Uint8Array(salt.slice(0)),
        t: iterations, m: memory, p: parallelism, dkLen: length, version: version
      }, [pw.buffer]);
    });
  }

  function load(fileBytes, password, keyFileBytes) {
    if (!kdbxweb) {
      return Promise.reject(fail('unavailable'));
    }
    if (op) {
      return Promise.reject(fail('busy'));
    }
    var data = bytes(fileBytes);
    var keyFile = keyFileBytes === undefined || keyFileBytes === null ? null : bytes(keyFileBytes);
    if (data === null || typeof password !== 'string' || (keyFileBytes != null && keyFile === null)) {
      return Promise.reject(fail('bad_input'));
    }
    var mine = { cancelled: false, jobs: [] };
    op = mine;
    var settle = function () {
      if (keyFile) {
        keyFile.fill(0);
      }
      if (op === mine) {
        op = null;
      }
    };
    var open = function (pv) {
      // Each attempt gets its own copies: kdbxweb keeps the buffers it is given, and XORs a 32-byte key file in place.
      return kdbxweb.Kdbx.load(data.slice().buffer, new kdbxweb.Credentials(pv, keyFile && keyFile.slice()));
    };
    return Promise.resolve().then(function () {
      if (password !== '') {
        return open(kdbxweb.ProtectedValue.fromString(password));
      }
      return open(null).catch(function (e) {
        if (mine.cancelled || !e || e.code !== 'InvalidKey') {
          throw e;
        }
        return open(kdbxweb.ProtectedValue.fromString(''));
      });
    }).then(function (db) {
      settle();
      if (mine.cancelled) {
        throw fail('cancelled');
      }
      return db;
    }, function (e) {
      settle();
      if (mine.cancelled) {
        throw fail('cancelled');
      }
      if (e && e.vault) {
        throw e;
      }
      var code = e && typeof e.code === 'string' && Object.prototype.hasOwnProperty.call(KDBX_CODES, e.code) ? KDBX_CODES[e.code] : 'load_failed';
      throw fail(code);
    });
  }

  function cancel() {
    if (op) {
      op.cancelled = true;
      op.jobs.slice().forEach(function (job) {
        job.stop('cancelled');
      });
    }
  }

  if (kdbxweb) {
    kdbxweb.CryptoEngine.setArgon2Impl(argon2);
  }
  win.KBVaultKdbx = api;
})(window);
