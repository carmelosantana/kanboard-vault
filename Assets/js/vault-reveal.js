/*
 * The one-time share page's script (spec: One-time shares → Opening a share). Loaded after vault-onetime.js by
 * Template/share/show.php; no inline JS. On load it reads the id from the query string and k ‖ b from the #fragment,
 * then removes the fragment from the address bar (history.replaceState), so it is not left in the history or seen by
 * anyone looking over the screen. The fragment is never sent, put in a query, logged or stored.
 *
 * Opening the page reveals nothing. Reveal (the button, or Enter in the passphrase field; both preventDefault, since
 * the page has no form to submit) POSTs {id, b, csrf_token} to #vault-reveal's data-reveal-url. That burns the link,
 * and the answer {ciphertext, iv, salt, has_passphrase, expires_at} is kept in this closure only. The secret is then
 * decrypted here with the AD enc("share", 1, id, expires_at, has_passphrase). A missing or wrong passphrase leaves the
 * kept answer in memory: the next Reveal decrypts it again without another POST. Once the secret is shown, the answer
 * and the passphrase field are dropped. Every failure of the link itself (burned, revoked, expired, unknown, wrong b)
 * is the server's one "not available"; Reveal then stays off. Text reaches the DOM through textContent and a
 * textarea's value only.
 */
(function (win) {
  'use strict';

  var doc = win.document;
  var HEX32 = /^[0-9a-f]{32}$/;

  function q(sel, root) {
    return (root || doc).querySelector(sel);
  }

  function hex(a) {
    var s = '';
    for (var i = 0; i < a.length; i++) {
      s += (a[i] < 16 ? '0' : '') + a[i].toString(16);
    }
    return s;
  }

  function init() {
    var root = doc.getElementById('vault-reveal');
    var ot = win.KBVaultOnetime;
    if (!root) {
      return;
    }
    var button = q('[data-vault-reveal-button]', root);
    var pass = q('[data-vault-reveal-passphrase]', root);
    var form = q('[data-vault-reveal-form]', root);
    var status = q('[data-vault-reveal-status]', root);
    var result = q('[data-vault-reveal-result]', root);
    var secret = q('[data-vault-reveal-secret]', root);
    var copy = q('[data-vault-reveal-copy]', root);

    var msg = function (name) {
      return root.getAttribute('data-msg-' + name) || '';
    };
    var say = function (text) {
      status.textContent = text;
      status.hidden = text === '';
    };

    // Read the link once, then take the fragment out of the address bar.
    var loc = win.location;
    var fragment = loc.hash ? loc.hash.slice(1) : '';
    if (loc.hash && win.history && typeof win.history.replaceState === 'function') {
      win.history.replaceState(null, '', loc.pathname + loc.search);
    }
    var id = new win.URLSearchParams(loc.search).get('id') || '';
    var parts = ot ? ot.parseFragment(fragment) : null;
    var burn = parts ? hex(parts.b) : '';
    if (parts) {
      parts.k.fill(0);
      parts.b.fill(0);
    }

    var answer = null;
    var busy = false;
    var done = false;

    if (!ot || !HEX32.test(id) || !parts) {
      button.disabled = true;
      say(msg('incomplete'));
      done = true;
    } else if (root.getAttribute('data-vault-https') !== '1') {
      button.disabled = true;
      done = true;
    }

    function show(text) {
      answer = null;
      fragment = '';
      burn = '';
      pass.value = '';
      secret.value = text;
      form.hidden = true;
      result.hidden = false;
      say('');
      done = true;
    }

    function open() {
      var passphrase = pass.value;
      if (answer.has_passphrase && passphrase === '') {
        say(msg('need-passphrase'));
        pass.focus();
        return Promise.resolve();
      }
      say(msg('decrypting'));
      return ot.decrypt({
        ciphertext: answer.ciphertext,
        iv: answer.iv,
        salt: answer.salt,
        has_passphrase: answer.has_passphrase,
        fragment: fragment,
        shareId: id,
        expiresAt: answer.expires_at,
        passphrase: passphrase
      }).then(show, function (e) {
        if (answer.has_passphrase && e && (e.code === 'decrypt_failed' || e.code === 'passphrase_required')) {
          say(msg('wrong-passphrase'));
          pass.focus();
          return;
        }
        answer = null;
        done = true;
        button.disabled = true;
        say(msg(e && e.code === 'worker_failed' ? 'unsupported' : 'damaged'));
      });
    }

    function post() {
      var body = new win.URLSearchParams();
      body.set('id', id);
      body.set('b', burn);
      body.set('csrf_token', root.getAttribute('data-csrf') || '');
      return win.fetch(root.getAttribute('data-reveal-url'), {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest' },
        body: body.toString()
      }).then(function (res) {
        return res.json().then(null, function () {
          return null;
        }).then(function (data) {
          return { status: res.status, data: data && typeof data === 'object' ? data : {} };
        });
      });
    }

    function reveal(ev) {
      if (ev && typeof ev.preventDefault === 'function') {
        ev.preventDefault();
      }
      if (busy || done) {
        return;
      }
      busy = true;
      button.disabled = true;
      var step = answer !== null ? open() : post().then(function (r) {
        var d = r.data;
        if (r.status === 200 && d.ok === true && typeof d.ciphertext === 'string') {
          answer = {
            ciphertext: d.ciphertext,
            iv: d.iv,
            salt: d.salt,
            has_passphrase: d.has_passphrase === true || d.has_passphrase === 1 || d.has_passphrase === '1',
            expires_at: d.expires_at
          };
          return open();
        }
        if (d.reason === 'not_available') {
          done = true;
          say(msg('not-available'));
        } else {
          say(msg(d.reason === 'rate_limited' ? 'rate-limited' : d.reason === 'https_required' ? 'https' : 'failed'));
        }
      }, function () {
        say(msg('failed'));
      });
      step.then(function () {
        busy = false;
        button.disabled = done;
      });
    }

    button.addEventListener('click', reveal);
    pass.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') {
        reveal(ev);
      }
    });
    copy.addEventListener('click', function (ev) {
      ev.preventDefault();
      if (secret.value !== '' && win.navigator && win.navigator.clipboard) {
        win.navigator.clipboard.writeText(secret.value).then(function () {
          say(msg('copied'));
        }, function () {
          say(msg('failed'));
        });
      }
    });
  }

  if (doc && typeof doc.querySelector === 'function') {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }
})(window);
