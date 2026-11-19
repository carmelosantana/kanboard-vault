/*
 * Hardware keys, WebAuthn with the PRF extension (spec: Hardware keys). Loaded only by Vault's own templates (the
 * locked page when the user has keys, the hardware-key page, the security page for R54); no inline JS. Every request
 * goes through window.KBVault.api (vault.js: POST with Kanboard's CSRF token). Messages come from #vault-app and are
 * written with textContent only. Binary values travel as base64url.
 *
 *   Each ceremony asks the server for a single-use challenge (hw_challenge {purpose}) right before it calls the
 *   browser, and posts the result once. navigator.credentials.get always asks for the PRF output, with each key's own
 *   salt (extensions.prf.evalByCredential); a response without prf.results.first is refused here. create asks for
 *   extensions.prf and a key whose results don't report prf.enabled === true is refused before anything is posted.
 *
 *   [data-vault-action="hw-unlock"]    (locked page) passphrase field of the unlock form + a fresh 'unlock' assertion.
 *   [data-vault-action="hw-register"]  create() a new key, a get() with it for its PRF output, then a get() from
 *                                      the existing key (every key when it's the second: the vault rotates).
 *   [data-vault-hw-remove="<id>"]      a get() from any other key (none for the last key) plus the passphrase.
 *   [data-vault-action="hw-rotate"]    a get() from every key in turn, the passphrase and an optional new one.
 *   window.KBVaultWebAuthn.assertion(purpose) resolves to one fresh assertion from any of the user's keys
 *                                      (vault-security.js uses it for the recovery code, R54).
 */
(function (win) {
  'use strict';

  var doc = win.document;

  function messages() {
    var el = doc.getElementById('vault-app');
    try {
      var m = JSON.parse((el && el.getAttribute('data-messages')) || '');
      return m && typeof m === 'object' ? m : {};
    } catch (e) {
      return {};
    }
  }

  var MSG = messages();

  function msg(reason) {
    return Object.prototype.hasOwnProperty.call(MSG, reason) ? MSG[reason] : (MSG.failed || 'Error');
  }

  // A rejection carrying one of the server's or this file's fixed reasons.
  function Refusal(reason) {
    this.reason = reason;
  }

  function refuse(reason) {
    return Promise.reject(new Refusal(reason));
  }

  function reasonOf(err) {
    if (err instanceof Refusal) {
      return err.reason;
    }
    // A browser error (NotAllowedError: cancelled or timed out; InvalidStateError: an excluded key) is never shown raw.
    return 'hw_cancelled';
  }

  function b64u(buf) {
    var bytes = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return win.btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function unb64u(s) {
    var bin = win.atob(String(s).replace(/-/g, '+').replace(/_/g, '/'));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  function supported() {
    return !!(win.PublicKeyCredential && win.navigator && win.navigator.credentials);
  }

  function api(action, body) {
    return win.KBVault.api(action, body).then(function (res) {
      return res && res.ok ? res : refuse((res && res.reason) || 'failed');
    });
  }

  function challenge(purpose) {
    return api('hw_challenge', { purpose: purpose });
  }

  // The assertion as the server reads it, with this key's PRF output; refused without one.
  function wire(cred) {
    var ext = typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : {};
    var first = ext && ext.prf && ext.prf.results ? ext.prf.results.first : null;
    if (!first) {
      throw new Refusal('hw_prf_unsupported');
    }
    return {
      credential_id: b64u(cred.rawId),
      clientDataJSON: b64u(cred.response.clientDataJSON),
      authenticatorData: b64u(cred.response.authenticatorData),
      signature: b64u(cred.response.signature),
      prf: b64u(first)
    };
  }

  // navigator.credentials.get for the challenge ch, limited to the keys whose ids are in only (all when null). Each
  // allowed key gets its own PRF salt. UP is required, UV preferred (the passphrase is the knowledge factor).
  function get(ch, only) {
    var keys = (ch.credentials || []).filter(function (c) {
      return !only || only.indexOf(c.id) !== -1;
    });
    if (keys.length === 0) {
      return refuse('hw_key_invalid');
    }
    var byCred = {};
    keys.forEach(function (c) {
      byCred[c.id] = { first: unb64u(c.prf_salt) };
    });
    return win.navigator.credentials.get({
      publicKey: {
        challenge: unb64u(ch.challenge),
        rpId: ch.rp_id,
        allowCredentials: keys.map(function (c) {
          return { type: 'public-key', id: unb64u(c.id) };
        }),
        userVerification: 'preferred',
        timeout: 60000,
        extensions: { prf: { evalByCredential: byCred } }
      }
    }).then(wire);
  }

  // One fresh assertion for purpose from a key in only (any of the user's keys when null).
  function assertion(purpose, only) {
    if (!supported()) {
      return refuse('hw_unsupported');
    }
    return challenge(purpose).then(function (ch) {
      return get(ch, only);
    });
  }

  // A fresh 'ceremony' assertion from each key in keys, one after the other; say(label) before each.
  function eachKey(keys, say) {
    var out = [];
    return keys.reduce(function (p, k) {
      return p.then(function () {
        say(k.label);
        return assertion('ceremony', [k.id]).then(function (a) {
          out.push(a);
        });
      });
    }, Promise.resolve()).then(function () {
      return out;
    });
  }

  function status(el, text, ok) {
    if (!el) {
      return;
    }
    el.textContent = text;
    el.classList.toggle('vault-ok', !!ok);
    el.classList.toggle('vault-bad', !ok);
    el.hidden = false;
  }

  function field(form, name) {
    var input = form && form.querySelector('[data-vault-hw-field="' + name + '"]');
    return input ? input.value : '';
  }

  function clearPasswords(form) {
    if (!form) {
      return;
    }
    Array.prototype.forEach.call(form.querySelectorAll('input[type="password"]'), function (input) {
      input.value = '';
    });
  }

  // Runs a ceremony once at a time from a button; done(res) on success, the reason's message otherwise.
  function bindButton(button, out, run, done) {
    var busy = false;
    button.addEventListener('click', function () {
      if (busy) {
        return;
      }
      busy = true;
      button.disabled = true;
      status(out, msg('hw_touch'), true);
      Promise.resolve().then(run).then(function (res) {
        done(res);
      }, function (err) {
        status(out, msg(reasonOf(err)), false);
      }).then(function () {
        busy = false;
        button.disabled = false;
      });
    });
  }

  function reload() {
    win.location.reload();
  }

  // Locked page: the unlock form's passphrase plus a fresh 'unlock' assertion.
  function bindUnlock() {
    var button = doc.querySelector('[data-vault-action="hw-unlock"]');
    var form = doc.querySelector('[data-vault-form="unlock"]');
    if (!button || !form) {
      return;
    }
    var out = form.querySelector('.vault-error');
    var pass = form.querySelector('input[name="passphrase"]');
    bindButton(button, out, function () {
      var passphrase = pass ? pass.value : '';
      return assertion('unlock', null).then(function (a) {
        if (pass) {
          pass.value = '';
        }
        return api('hw_unlock', { passphrase: passphrase, assertion: a });
      }, function (err) {
        if (pass) {
          pass.value = '';
        }
        throw err;
      });
    }, reload);
  }

  function register(form, out) {
    if (!supported()) {
      return refuse('hw_unsupported');
    }
    var label = field(form, 'label');
    var passphrase = field(form, 'passphrase');
    return challenge('register').then(function (ch) {
      var existing = ch.credentials || [];
      return win.navigator.credentials.create({
        publicKey: {
          rp: { id: ch.rp_id, name: ch.rp_name },
          user: { id: unb64u(ch.user_handle), name: ch.user_name, displayName: ch.user_name },
          challenge: unb64u(ch.challenge),
          pubKeyCredParams: [{ type: 'public-key', alg: -8 }, { type: 'public-key', alg: -7 }],
          attestation: 'none',
          authenticatorSelection: { userVerification: 'preferred', residentKey: 'discouraged' },
          excludeCredentials: existing.map(function (c) {
            return { type: 'public-key', id: unb64u(c.id) };
          }),
          timeout: 60000,
          extensions: { prf: {} }
        }
      }).then(function (cred) {
        var ext = typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : {};
        if (!ext || !ext.prf || ext.prf.enabled !== true) {
          throw new Refusal('hw_prf_unsupported');
        }
        var create = {
          clientDataJSON: b64u(cred.response.clientDataJSON),
          attestationObject: b64u(cred.response.attestationObject),
          clientExtensionResults: { prf: { enabled: true } }
        };
        var id = b64u(cred.rawId);
        status(out, msg('hw_touch'), true);
        return challenge('ceremony').then(function (c2) {
          return get({ challenge: c2.challenge, rp_id: c2.rp_id, credentials: [{ id: id, prf_salt: ch.prf_salt }] }, null);
        }).then(function (assertNew) {
          // The second key rotates the vault: every existing key takes part. Later keys need one to prove the passphrase.
          var others = existing.length === 1 ? existing : [];
          if (existing.length > 1) {
            status(out, msg('hw_touch'), true);
            return assertion('ceremony', null).then(function (a) {
              return [assertNew, [a]];
            });
          }
          return eachKey(others, function (l) {
            status(out, msg('hw_touch_other') + ' ' + l, true);
          }).then(function (list) {
            return [assertNew, list];
          });
        }).then(function (both) {
          return api('hw_register', { label: label, passphrase: passphrase, create: create, assert: both[0], others: both[1] });
        });
      });
    });
  }

  function remove(id, passForm) {
    var passphrase = field(passForm, 'passphrase');
    return challenge('ceremony').then(function (ch) {
      var others = (ch.credentials || []).filter(function (c) {
        return c.id !== id;
      }).map(function (c) {
        return c.id;
      });
      if (others.length === 0) {
        return api('hw_remove', { credential_id: id, passphrase: passphrase });
      }
      return get(ch, others).then(function (a) {
        return api('hw_remove', { credential_id: id, assertion: a, passphrase: passphrase });
      });
    });
  }

  function rotate(form, out) {
    if (!supported()) {
      return refuse('hw_unsupported');
    }
    var body = { passphrase: field(form, 'passphrase'), new_passphrase: field(form, 'new_passphrase'), confirm: field(form, 'confirm') };
    if (body.new_passphrase !== body.confirm) {
      return refuse('passphrase_mismatch');
    }
    return challenge('ceremony').then(function (ch) {
      return eachKey(ch.credentials || [], function (l) {
        status(out, msg('hw_touch_other') + ' ' + l, true);
      });
    }).then(function (list) {
      body.assertions = list;
      return api('hw_rotate', body);
    });
  }

  function bindPage() {
    var regForm = doc.querySelector('[data-vault-form="hwregister"]');
    var regButton = doc.querySelector('[data-vault-action="hw-register"]');
    if (regForm && regButton) {
      var regOut = regForm.querySelector('[data-vault-hw-status="register"]');
      bindButton(regButton, regOut, function () {
        return register(regForm, regOut).then(function (res) {
          clearPasswords(regForm);
          return res;
        }, function (err) {
          clearPasswords(regForm);
          throw err;
        });
      }, reload);
    }
    var passForm = doc.querySelector('[data-vault-form="hwremove"]');
    var removeOut = doc.querySelector('[data-vault-hw-status="remove"]');
    if (passForm) {
      passForm.hidden = false;
    }
    Array.prototype.forEach.call(doc.querySelectorAll('[data-vault-hw-remove]'), function (button) {
      var id = button.getAttribute('data-vault-hw-remove');
      bindButton(button, removeOut, function () {
        if (!win.confirm(msg('confirm_hw_remove'))) {
          return refuse('hw_cancelled');
        }
        return remove(id, passForm).then(function (res) {
          clearPasswords(passForm);
          return res;
        }, function (err) {
          clearPasswords(passForm);
          throw err;
        });
      }, reload);
    });
    var rotForm = doc.querySelector('[data-vault-form="hwrotate"]');
    var rotButton = doc.querySelector('[data-vault-action="hw-rotate"]');
    if (rotForm && rotButton) {
      var rotOut = rotForm.querySelector('[data-vault-hw-status="rotate"]');
      bindButton(rotButton, rotOut, function () {
        return rotate(rotForm, rotOut).then(function (res) {
          clearPasswords(rotForm);
          return res;
        }, function (err) {
          clearPasswords(rotForm);
          throw err;
        });
      }, function (res) {
        var text = typeof res.message === 'string' && res.message !== '' ? res.message : msg('keys_rotated');
        status(rotOut, text, true);
      });
    }
  }

  win.KBVaultWebAuthn = {
    assertion: function (purpose) {
      return assertion(purpose || 'ceremony', null);
    },
    reasonOf: reasonOf
  };

  function init() {
    bindUnlock();
    bindPage();
  }

  if (doc && typeof doc.querySelector === 'function') {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }
})(window);
