/*
 * Vault page script (spec: UI). Loaded only by Vault's own templates; no inline JS anywhere.
 * Reads its configuration from #vault-app (data-csrf, data-endpoints, data-messages, data-idle-ms) and exposes
 * window.KBVault:
 *   api(action, body)  POSTs body plus Kanboard's CSRF token to the named endpoint and resolves to the JSON answer
 *                      ({ok: false, reason: 'failed'} when there is none). The token is set last, so a body can't
 *                      replace it.
 *   lockOnIdle(ms)     locks the vault after ms without keyboard, mouse or touch activity, then reloads.
 * Messages are written with textContent only.
 */
(function (win) {
  'use strict';

  var doc = win.document;
  var ACTIVITY = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'];

  function parse(json, fallback) {
    try {
      var v = JSON.parse(json || '');
      return v && typeof v === 'object' ? v : fallback;
    } catch (e) {
      return fallback;
    }
  }

  function config() {
    var el = doc && doc.getElementById('vault-app');
    if (!el) {
      return null;
    }
    return {
      el: el,
      csrf: el.getAttribute('data-csrf') || '',
      endpoints: parse(el.getAttribute('data-endpoints'), {}),
      messages: parse(el.getAttribute('data-messages'), {}),
      idleMs: parseInt(el.getAttribute('data-idle-ms') || '0', 10) || 0
    };
  }

  function api(action, body) {
    var cfg = config();
    var url = cfg && Object.prototype.hasOwnProperty.call(cfg.endpoints, action) ? cfg.endpoints[action] : null;
    if (!url) {
      return Promise.resolve({ ok: false, reason: 'failed' });
    }
    var params = new win.URLSearchParams();
    Object.keys(body || {}).forEach(function (k) {
      var v = body[k];
      params.append(k, v !== null && typeof v === 'object' ? JSON.stringify(v) : String(v));
    });
    params.set('csrf_token', cfg.csrf);
    return win.fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest' },
      body: params.toString()
    }).then(function (res) {
      return res.json().then(function (data) {
        return data && typeof data === 'object' ? data : { ok: false, reason: 'failed' };
      }, function () {
        return { ok: false, reason: 'failed' };
      });
    }, function () {
      return { ok: false, reason: 'failed' };
    });
  }

  var idleTimer = null;
  var idleBound = false;

  function lockNow() {
    return api('lock', {}).then(function () {
      win.location.reload();
    });
  }

  function lockOnIdle(ms) {
    if (!(ms > 0)) {
      return;
    }
    var reset = function () {
      win.clearTimeout(idleTimer);
      idleTimer = win.setTimeout(lockNow, ms);
    };
    if (!idleBound) {
      idleBound = true;
      ACTIVITY.forEach(function (ev) {
        doc.addEventListener(ev, reset, { passive: true, capture: true });
      });
    }
    reset();
  }

  function message(cfg, reason) {
    return cfg.messages[reason] || cfg.messages.failed || 'Error';
  }

  function bindForm(cfg, form, action) {
    var error = form.querySelector('.vault-error');
    var button = form.querySelector('button[type="submit"]');
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var data = {};
      Array.prototype.forEach.call(form.querySelectorAll('input[name]'), function (input) {
        data[input.name] = input.value;
      });
      if (button) {
        button.disabled = true;
      }
      if (error) {
        error.textContent = message(cfg, 'working');
        error.hidden = false;
      }
      api(action, data).then(function (res) {
        if (res && res.ok) {
          win.location.reload();
          return;
        }
        Array.prototype.forEach.call(form.querySelectorAll('input[type="password"]'), function (input) {
          input.value = '';
        });
        if (error) {
          error.textContent = message(cfg, res && res.reason);
          error.hidden = false;
        }
        if (button) {
          button.disabled = false;
        }
      });
    });
  }

  function init() {
    var cfg = config();
    if (!cfg) {
      return;
    }
    var unlock = doc.querySelector('[data-vault-form="unlock"]');
    if (unlock) {
      bindForm(cfg, unlock, 'unlock');
    }
    var enrol = doc.querySelector('[data-vault-form="enrol"]');
    if (enrol) {
      bindForm(cfg, enrol, 'enrol');
    }
    var lock = doc.querySelector('[data-vault-action="lock"]');
    if (lock) {
      lock.addEventListener('click', lockNow);
    }
    if (cfg.el.getAttribute('data-vault-state') === 'unlocked') {
      lockOnIdle(cfg.idleMs);
    }
  }

  win.KBVault = { api: api, lockOnIdle: lockOnIdle };

  if (doc) {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }
})(window);
