/*
 * The import pre-check (spec: KeePassXC import and export → Import, step 1). Before kdbxweb sees a file, Vault reads
 * the outer KDBX header itself (a small TLV structure) and refuses work it must not start: kdbxweb's AES-KDF and
 * gunzip run on the page, where cancel() can't stop them, and Argon2 runs in a worker that only Cancel or a timeout
 * stops. Loaded as a classic script on the import page; no inline JS, eval or storage. Sets window.KBVaultKdbxHeader:
 *   check(bytes) → {ok: true, version: '3.1'|'4.0'|'4.1', kdf: 'aes'|'argon2d'|'argon2id', cipher: 'aes'|'chacha20'}
 *                | {ok: false, reason}
 *       bytes is a Uint8Array or ArrayBuffer; it is only read. Reasons, checked in this order:
 *         too_large     the file is over MAX_FILE_BYTES (50 MiB), checked before anything is parsed;
 *         not_kdbx      not a KeePass 2 file;
 *         unsupported   KeePass 1, a KDBX version kdbxweb can't read, or an unknown cipher, KDF or compression;
 *         file_corrupt  the header runs off the end or has a malformed value; the KDBX 4 HMAC block stream is cut
 *                       short or has bytes after its final block (T21 M4); a KDBX 3 payload isn't whole AES blocks;
 *         twofish       the cipher is Twofish (kdbxweb has none; the page says so by name);
 *         argon_mem     Argon2 memory over 1 GiB; argon_iter: over 100 iterations; argon_lanes: over 8 lanes;
 *         aes_rounds    AES-KDF over 10^8 rounds: KDBX 3 TransformRounds or KDBX 4 R (T21 M5).
 *       yubikey_cr is in REASONS for the page's messages, but no header shows it: KeePassXC writes nothing into the
 *       file for a challenge-response key (the challenge is the KDF salt). The page explains it when the key is
 *       wrong instead.
 *   MAX_FILE_BYTES, LIMITS, REASONS
 *
 * The check reads every occurrence of a value the way kdbxweb 2.1.1 does, so nothing can hide a hostile value:
 * kdbxweb keeps the last of a repeated header field or KDF key and decodes keys as UTF-8 (dropping a BOM), so every
 * occurrence is checked, under any of the four integer types kdbxweb accepts; the high word of a 64-bit value counts.
 * The size of the decompressed payload can't be known here; kdbxweb's Vault patch 04 caps it while inflating.
 */
(function (win) {
  'use strict';

  var MiB = 1024 * 1024;
  var MAX_FILE_BYTES = 50 * MiB;
  var LIMITS = { argonMemBytes: 1024 * MiB, argonIterations: 100, argonLanes: 8, aesRounds: 100000000 };
  var REASONS = ['too_large', 'not_kdbx', 'unsupported', 'file_corrupt', 'twofish', 'argon_mem', 'argon_iter', 'argon_lanes', 'aes_rounds', 'yubikey_cr'];
  var SIG1 = 0x9aa2d903;
  var SIG2_KDBX = 0xb54bfb67;
  var SIG2_OLD = [0xb54bfb65, 0xb54bfb66]; // KeePass 1.x and the 2.x pre-release format
  var CIPHERS = {
    '31c1f2e6bf714350be5805216afc5aff': 'aes',
    'd6038a2b8b6f4cb5a524339a31dbb59a': 'chacha20',
    'ad68f29f576f4bb9a36ad47af965346c': 'twofish'
  };
  var KDFS = {
    'c9d9f39a628a4460bf740d08c18a4fea': 'aes',
    'ef636ddf8c29444b91f7a9a403e30a0c': 'argon2d',
    '9e298b1956db4773b23dfc3ec6f0a1e6': 'argon2id'
  };
  // Refusals found in the header; the first in this order wins over the others.
  var CAPS = ['twofish', 'argon_mem', 'argon_iter', 'argon_lanes', 'aes_rounds'];
  var decoder = new win.TextDecoder();

  function Refuse(reason) {
    this.reason = reason;
  }

  function corrupt() {
    throw new Refuse('file_corrupt');
  }

  function hex(b, at, n) {
    var s = '';
    for (var i = 0; i < n; i++) {
      s += (b[at + i] < 16 ? '0' : '') + b[at + i].toString(16);
    }
    return s;
  }

  // An unsigned 64-bit little-endian integer as a Number (exact below 2^53; above, still far over every cap).
  function u64(v, at) {
    return v.getUint32(at + 4, true) * 0x100000000 + v.getUint32(at, true);
  }

  // A KDBX 4 VarDictionary in b[at, end): its integer values and $UUIDs, every occurrence, in file order.
  function dictionary(b, v, at, end) {
    if (end - at < 3 || b[at + 1] === 0 || b[at + 1] > 1) {
      throw new Refuse(end - at < 3 ? 'file_corrupt' : 'unsupported');
    }
    var items = [];
    var p = at + 2;
    for (;;) {
      if (p + 1 > end) {
        corrupt();
      }
      var type = b[p];
      if (type === 0) {
        return items;
      }
      if (p + 5 > end) {
        corrupt();
      }
      var keyLength = v.getInt32(p + 1, true);
      if (keyLength <= 0 || p + 5 + keyLength + 4 > end) {
        corrupt();
      }
      var key = decoder.decode(b.subarray(p + 5, p + 5 + keyLength));
      var q = p + 5 + keyLength;
      var valueLength = v.getInt32(q, true);
      var at2 = q + 4;
      if (valueLength < 0 || at2 + valueLength > end) {
        corrupt();
      }
      var value;
      switch (type) {
        case 0x04: // UInt32
        case 0x0c: // Int32
          if (valueLength !== 4) {
            corrupt();
          }
          value = type === 0x04 ? v.getUint32(at2, true) : v.getInt32(at2, true);
          break;
        case 0x05: // UInt64
        case 0x0d: // Int64 (kdbxweb reads both as unsigned lo/hi words)
          if (valueLength !== 8) {
            corrupt();
          }
          value = u64(v, at2);
          break;
        case 0x08: // Bool
          if (valueLength !== 1) {
            corrupt();
          }
          value = null;
          break;
        case 0x18: // String
          value = null;
          break;
        case 0x42: // Bytes
          value = key === '$UUID' && valueLength === 16 ? hex(b, at2, 16) : null;
          break;
        default:
          corrupt();
      }
      items.push({ key: key, value: value });
      p = at2 + valueLength;
    }
  }

  function parse(b) {
    var v = new DataView(b.buffer, b.byteOffset, b.byteLength);
    if (b.length < 12 || v.getUint32(0, true) !== SIG1) {
      throw new Refuse('not_kdbx');
    }
    var sig2 = v.getUint32(4, true);
    if (sig2 !== SIG2_KDBX) {
      throw new Refuse(SIG2_OLD.indexOf(sig2) >= 0 ? 'unsupported' : 'not_kdbx');
    }
    var minor = v.getUint16(8, true);
    var major = v.getUint16(10, true);
    if ((major !== 3 && major !== 4) || minor > 1) {
      throw new Refuse('unsupported');
    }
    var sizeBytes = major >= 4 ? 4 : 2;
    var found = {};
    var cipher = null;
    var kdf = major === 3 ? 'aes' : null;
    var compression = null;
    var p = 12;
    for (;;) {
      if (p + 1 + sizeBytes > b.length) {
        corrupt();
      }
      var id = b[p];
      var size = sizeBytes === 4 ? v.getUint32(p + 1, true) : v.getUint16(p + 1, true);
      var at = p + 1 + sizeBytes;
      if (at + size > b.length) {
        corrupt();
      }
      // kdbxweb reads any known field in either version, and fails on an unknown one.
      if (id > 12) {
        corrupt();
      }
      if (id === 2) {
        cipher = size === 16 ? (CIPHERS[hex(b, at, 16)] || 'unknown') : 'unknown';
        if (cipher === 'twofish') {
          found.twofish = true;
        }
      } else if (id === 3) {
        if (size !== 4) {
          corrupt();
        }
        compression = v.getUint32(at, true);
      } else if (id === 6) {
        if (size !== 8) {
          corrupt();
        }
        if (u64(v, at) > LIMITS.aesRounds) {
          found.aes_rounds = true;
        }
      } else if (id === 11 || id === 12) {
        var items = dictionary(b, v, at, at + size);
        for (var i = 0; id === 11 && i < items.length; i++) {
          var it = items[i];
          var n = typeof it.value === 'number' ? it.value : null;
          if (it.key === '$UUID') {
            kdf = it.value === null ? 'unknown' : (KDFS[it.value] || 'unknown');
          } else if (n !== null && it.key === 'M' && n > LIMITS.argonMemBytes) {
            found.argon_mem = true;
          } else if (n !== null && it.key === 'I' && n > LIMITS.argonIterations) {
            found.argon_iter = true;
          } else if (n !== null && it.key === 'P' && n > LIMITS.argonLanes) {
            found.argon_lanes = true;
          } else if (n !== null && it.key === 'R' && n > LIMITS.aesRounds) {
            found.aes_rounds = true;
          }
        }
      }
      p = at + size;
      if (id === 0) {
        break;
      }
    }
    for (var c = 0; c < CAPS.length; c++) {
      if (found[CAPS[c]]) {
        throw new Refuse(CAPS[c]);
      }
    }
    if (cipher === null || kdf === null || compression === null) {
      corrupt();
    }
    if (cipher === 'unknown' || kdf === 'unknown' || compression > 1) {
      throw new Refuse('unsupported');
    }
    if (major >= 4) {
      // Header SHA-256 and HMAC, then HMAC blocks (32-byte HMAC, int32 length, data) up to the empty final block,
      // which must end the file.
      p += 64;
      for (;;) {
        if (p + 36 > b.length) {
          corrupt();
        }
        var length = v.getInt32(p + 32, true);
        if (length < 0 || p + 36 + length > b.length) {
          corrupt();
        }
        p += 36 + length;
        if (length === 0) {
          break;
        }
      }
      if (p !== b.length) {
        corrupt();
      }
    } else {
      var rest = b.length - p;
      if (rest <= 0 || rest % 16 !== 0) {
        corrupt();
      }
    }
    return { ok: true, version: major + '.' + minor, kdf: kdf, cipher: cipher };
  }

  function check(input) {
    var b = input instanceof Uint8Array ? input : input instanceof ArrayBuffer ? new Uint8Array(input) : null;
    if (b === null) {
      return { ok: false, reason: 'not_kdbx' };
    }
    if (b.length > MAX_FILE_BYTES) {
      return { ok: false, reason: 'too_large' };
    }
    try {
      return parse(b);
    } catch (e) {
      if (e instanceof Refuse) {
        return { ok: false, reason: e.reason };
      }
      return { ok: false, reason: 'file_corrupt' };
    }
  }

  win.KBVaultKdbxHeader = { check: check, MAX_FILE_BYTES: MAX_FILE_BYTES, LIMITS: LIMITS, REASONS: REASONS };
})(window);
