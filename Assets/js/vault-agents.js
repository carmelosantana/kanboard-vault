/*
 * The owner's agents page (Template/vault/agents.php). Loaded only there; no inline JS. Uses window.KBVault.api
 * (vault.js), which adds Kanboard's CSRF token. Every value is written with textContent.
 *
 *   [data-vault-form="agent-enrol"|"agent-reenrol"]  {agent_id}. Re-enrolment asks first (the old key dies and other
 *       people's shares go). The answer's ready-to-paste line (env: KANBOARD_VAULT_KEY=…) is shown once in
 *       [data-vault-agent-env]; [data-vault-action="agent-key-done"] clears it from the page. One request at a time.
 *   [data-vault-form="agent-cap"]  {agent_id, cap}.
 * A failure shows the message for its fixed reason.
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

  function failure(msgs, res) {
    var reason = res && typeof res.reason === 'string' ? res.reason : 'failed';
    return Object.prototype.hasOwnProperty.call(msgs, reason) ? msgs[reason] : msgs.failed || 'Error';
  }

  function init() {
    var msgs = messages();
    var status = doc.querySelector('[data-vault-agent-status]');
    var panel = doc.querySelector('[data-vault-agent-key-panel]');
    var env = doc.querySelector('[data-vault-agent-env]');
    var done = doc.querySelector('[data-vault-action="agent-key-done"]');
    var busy = false;

    function say(text, ok) {
      if (!status) {
        return;
      }
      status.textContent = text;
      status.classList.toggle('vault-ok', ok);
      status.classList.toggle('vault-bad', !ok);
      status.hidden = false;
    }

    function send(form, action, data, onOk) {
      if (busy) {
        return;
      }
      busy = true;
      var button = form.querySelector('button[type="submit"]');
      if (button) {
        button.disabled = true;
      }
      say(msgs.working || '', true);
      win.KBVault.api(action, data).then(function (res) {
        if (res && res.ok) {
          onOk(res);
        } else {
          say(failure(msgs, res), false);
        }
      }).then(function () {
        busy = false;
        if (button) {
          button.disabled = false;
        }
      });
    }

    function agentId(form) {
      var input = form.querySelector('input[name="agent_id"]');
      return input ? input.value : '';
    }

    function bindKey(form, action) {
      form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        if (busy || (action === 'agent_reenrol' && !win.confirm(msgs.confirm_reenrol || ''))) {
          return;
        }
        send(form, action, { agent_id: agentId(form) }, function (res) {
          if (!panel || !env || typeof res.env !== 'string') {
            say(msgs.failed || '', false);
            return;
          }
          env.textContent = res.env;
          panel.hidden = false;
          say(msgs.key_shown || '', true);
        });
      });
    }

    Array.prototype.forEach.call(doc.querySelectorAll('[data-vault-form="agent-enrol"]'), function (form) {
      bindKey(form, 'agent_enrol');
    });
    Array.prototype.forEach.call(doc.querySelectorAll('[data-vault-form="agent-reenrol"]'), function (form) {
      bindKey(form, 'agent_reenrol');
    });
    Array.prototype.forEach.call(doc.querySelectorAll('[data-vault-form="agent-cap"]'), function (form) {
      form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        var cap = form.querySelector('input[name="cap"]');
        send(form, 'agent_cap', { agent_id: agentId(form), cap: cap ? cap.value : '' }, function () {
          say(msgs.saved || '', true);
        });
      });
    });
    if (done) {
      done.addEventListener('click', function () {
        if (env) {
          env.textContent = '';
        }
        if (panel) {
          panel.hidden = true;
        }
        say(msgs.key_cleared || '', true);
      });
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
