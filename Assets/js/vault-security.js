/*
 * "My vault security" (R40). Loaded only by Template/vault/security.php; no inline JS. Uses window.KBVault.api
 * (vault.js), which adds Kanboard's CSRF token. Every value is written with textContent.
 *
 *   [data-vault-form="passphrase"|"rotate"]  sent as {name: value} of its named inputs, one request at a time.
 *       ok (ROTATED or PENDING) is a success: the answer's message (PENDING says the re-encryption finishes at the
 *       next unlock), else the page's own; offer_recovery_code reveals the "create a new code" hint (R36). Any
 *       failure shows the message for its fixed reason. The password inputs are cleared either way.
 *   [data-vault-action="recovery-create"]  after a confirm (it replaces any code), asks for a code and shows it
 *       once. [data-vault-action="recovery-confirm"] clears it from the page only when the typed text is group 3
 *       of the code (spec: Recovery).
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

  function say(el, text, ok) {
    if (!el) {
      return;
    }
    el.textContent = text;
    el.classList.toggle('vault-ok', ok);
    el.classList.toggle('vault-bad', !ok);
    el.hidden = false;
  }

  function failure(msgs, res) {
    var reason = res && typeof res.reason === 'string' ? res.reason : 'failed';
    return Object.prototype.hasOwnProperty.call(msgs, reason) ? msgs[reason] : msgs.failed || 'Error';
  }

  function bindCeremony(msgs, form, action, doneKey) {
    var status = form.querySelector('[data-vault-status]');
    var button = form.querySelector('button[type="submit"]');
    var busy = false;
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (busy) {
        return;
      }
      busy = true;
      var data = {};
      Array.prototype.forEach.call(form.querySelectorAll('input[name]'), function (input) {
        data[input.getAttribute('name')] = input.value;
      });
      if (button) {
        button.disabled = true;
      }
      say(status, msgs.working || '', true);
      win.KBVault.api(action, data).then(function (res) {
        Array.prototype.forEach.call(form.querySelectorAll('input[type="password"]'), function (input) {
          input.value = '';
        });
        var show = form.querySelector('[data-vault-gen-show]');
        if (show) {
          show.textContent = '';
        }
        if (res && res.ok) {
          var pending = res.rotation === 'pending';
          var text = typeof res.message === 'string' && res.message !== '' ? res.message : (pending ? msgs.rotation_pending : msgs[doneKey]);
          say(status, text || '', true);
          var offer = doc.querySelector('[data-vault-recovery-offer]');
          if (res.offer_recovery_code && offer) {
            offer.hidden = false;
          }
        } else {
          say(status, failure(msgs, res), false);
        }
      }).then(function () {
        busy = false;
        if (button) {
          button.disabled = false;
        }
      });
    });
  }

  // Group 3 of a displayed code (XXXX-XXXX-XXXX-…), upper-cased.
  function group3(code) {
    var groups = String(code).split('-');
    return groups.length > 2 ? groups[2].toUpperCase() : null;
  }

  function bindRecovery(msgs) {
    var create = doc.querySelector('[data-vault-action="recovery-create"]');
    var show = doc.querySelector('[data-vault-recovery-show]');
    var codeEl = doc.querySelector('[data-vault-recovery-code]');
    var input = doc.querySelector('[data-vault-recovery-confirm]');
    var done = doc.querySelector('[data-vault-action="recovery-confirm"]');
    var status = doc.querySelector('[data-vault-recovery-status]');
    if (!create || !show || !codeEl || !input || !done) {
      return;
    }
    var expected = null;

    function clear() {
      expected = null;
      codeEl.textContent = '';
      input.value = '';
      show.hidden = true;
      create.disabled = false;
    }

    create.addEventListener('click', function () {
      if (create.disabled || !win.confirm(msgs.confirm_new_code || '')) {
        return;
      }
      create.disabled = true;
      win.KBVault.api('recovery_code', {}).then(function (res) {
        var g = res && res.ok && typeof res.code === 'string' ? group3(res.code) : null;
        if (g === null) {
          clear();
          say(status, failure(msgs, res), false);
          return;
        }
        expected = g;
        codeEl.textContent = res.code;
        show.hidden = false;
        if (status) {
          status.hidden = true;
        }
      });
    });

    done.addEventListener('click', function () {
      if (expected === null) {
        return;
      }
      if (input.value.replace(/\s+/g, '').toUpperCase() !== expected) {
        say(status, msgs.code_group_mismatch || '', false);
        return;
      }
      clear();
      say(status, msgs.code_saved || '', true);
    });
  }

  function init() {
    var msgs = messages();
    var passphrase = doc.querySelector('[data-vault-form="passphrase"]');
    if (passphrase) {
      bindCeremony(msgs, passphrase, 'passphrase', 'passphrase_changed');
    }
    var rotate = doc.querySelector('[data-vault-form="rotate"]');
    if (rotate) {
      bindCeremony(msgs, rotate, 'rotate', 'keys_rotated');
    }
    bindRecovery(msgs);
  }

  if (doc && typeof doc.querySelector === 'function') {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }
})(window);
