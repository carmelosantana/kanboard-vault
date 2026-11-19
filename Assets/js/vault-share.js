/*
 * Vault's sharing dialog and activity view (spec: UI → The sharing dialog; Audit → Who sees what). Loaded by the
 * unlocked shell only, after vault.js and vault-browser.js; no inline JS anywhere. Sets window.KBVaultShare:
 *   open(type, id, label)   opens the dialog for one entry or group: vault/sharing gives the people it may be shared
 *                           with, its direct grants and, for a group, how many entries a grant covers.
 *   activity(offset)        loads one page of vault/activity into the activity view (offset 0 starts it again).
 * The share buttons vault-browser.js shows (owner only) carry data-vault-share-type/-id/-label. A grant on a group is
 * sent once to get the server's count, confirmed with that count, then sent again with confirm=1. An agent can only be
 * given Read. A revoke shows the suggestion to rotate the secrets. Only the latest dialog renders: an answer for a
 * dialog that has since been closed or opened for another item is dropped. Everything reaches the DOM through
 * textContent, an input's value or setAttribute on a fixed attribute.
 */
(function (win) {
  'use strict';

  var doc = win.document;
  var ui = null;

  function kb() {
    return win.KBVault;
  }

  function text(v) {
    return v === null || v === undefined ? '' : String(v);
  }

  function q(sel, root) {
    return (root || doc).querySelector(sel);
  }

  function el(tag, cls, content) {
    var e = doc.createElement(tag);
    if (cls) {
      e.className = cls;
    }
    if (content !== undefined) {
      e.textContent = text(content);
    }
    return e;
  }

  function parse(json) {
    try {
      var v = JSON.parse(json || '');
      return v && typeof v === 'object' ? v : {};
    } catch (e) {
      return {};
    }
  }

  // A reason from the server, through #vault-app's messages; a locked session reloads into the locked view.
  function failure(res, status) {
    var reason = res && res.reason;
    if (reason === 'locked') {
      win.location.reload();
      return;
    }
    status.textContent = text(ui.messages[reason] || ui.messages.failed || 'Error');
  }

  function dmsg(name, n) {
    return text(ui.dialog.getAttribute('data-msg-' + name)).replace('{n}', n === undefined ? '' : String(n));
  }

  function when(ts) {
    if (!ts) {
      return '';
    }
    var d = new Date(ts * 1000);
    var pad = function (x) {
      return (x < 10 ? '0' : '') + x;
    };
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  // ---- The sharing dialog --------------------------------------------------------------------------------------

  function open(type, id, label) {
    var mine = ++ui.session;
    ui.target = { type: type, id: id };
    ui.label.textContent = text(label);
    ui.status.textContent = '';
    ui.rotate.hidden = true;
    ui.covered.hidden = true;
    ui.expires.value = '';
    ui.dialog.hidden = false;
    return refresh(mine);
  }

  function close() {
    ui.session++;
    ui.target = null;
    ui.dialog.hidden = true;
  }

  function current(mine) {
    return mine === ui.session && ui.target !== null;
  }

  function refresh(mine) {
    var target = ui.target;
    return kb().api('sharing', { type: target.type, id: target.id }).then(function (res) {
      if (!current(mine)) {
        return;
      }
      if (!res || !res.ok) {
        return failure(res, ui.status);
      }
      fillCandidates(res.candidates || []);
      fillGrants(res.grants || []);
      var n = res.covered_entries;
      ui.covered.hidden = target.type !== 'group' || typeof n !== 'number';
      ui.covered.textContent = ui.covered.hidden ? '' : dmsg('covered', n);
    });
  }

  function fillCandidates(list) {
    var select = ui.grantee;
    while (select.options.length) {
      select.remove(0);
    }
    ui.kinds = {};
    list.forEach(function (c) {
      var o = el('option', '', text(c.name) + (c.kind === 'agent' ? ' (' + dmsg('agent') + ')' : ''));
      o.value = String(c.id);
      ui.kinds[String(c.id)] = c.kind;
      select.appendChild(o);
    });
    if (!list.length) {
      ui.status.textContent = dmsg('no-candidates');
    }
    agentRule();
  }

  // Spec, Agents: an agent reads what it is granted and never writes what a human shared, so Edit is not offered.
  function agentRule() {
    var agent = ui.kinds[ui.grantee.value] === 'agent';
    var edit = q('option[value="edit"]', ui.perm);
    if (edit) {
      edit.disabled = agent;
    }
    if (agent) {
      ui.perm.value = 'read';
    }
    ui.agentNote.hidden = !agent;
  }

  function fillGrants(list) {
    ui.grants.textContent = '';
    list.forEach(function (g) {
      var li = el('li', 'vault-share-grant');
      var who = text(g.name) + (g.kind === 'agent' ? ' (' + dmsg('agent') + ')' : '');
      var what = dmsg(g.permission === 'edit' ? 'edit' : 'read') + (g.expires_at ? ' ' + dmsg('until') + ' ' + when(g.expires_at) : '');
      li.appendChild(el('span', 'vault-share-who', who));
      li.appendChild(el('span', 'vault-muted', ' ' + what + ' '));
      var b = el('button', 'btn btn-small btn-red', dmsg('revoke'));
      b.type = 'button';
      b.setAttribute('data-vault-revoke', String(g.grantee_id));
      b.addEventListener('click', function () {
        revoke(String(g.grantee_id));
      });
      li.appendChild(b);
      ui.grants.appendChild(li);
    });
    ui.none.hidden = list.length > 0;
  }

  // The expiry input is local time ("2030-01-02T03:04"); the server takes a Unix time, or '' for none.
  function expiresAt() {
    var v = text(ui.expires.value);
    if (v === '') {
      return '';
    }
    var t = new Date(v).getTime();
    return isNaN(t) ? 'invalid' : Math.floor(t / 1000);
  }

  function submit(ev) {
    ev.preventDefault();
    if (!ui.target || ui.busy) {
      return;
    }
    var mine = ui.session;
    var body = { type: ui.target.type, id: ui.target.id, grantee_id: ui.grantee.value, perm: ui.perm.value, expires_at: expiresAt() };
    ui.busy = true;
    ui.rotate.hidden = true;
    var done = function () {
      ui.busy = false;
    };
    kb().api('grant', body).then(function (res) {
      if (!current(mine)) {
        return done();
      }
      if (res && res.ok && res.confirm_required) {
        if (!win.confirm(dmsg('confirm-group', res.covered_entries))) {
          return done();
        }
        var confirmed = {};
        Object.keys(body).forEach(function (k) {
          confirmed[k] = body[k];
        });
        confirmed.confirm = 1;
        return kb().api('grant', confirmed).then(function (again) {
          granted(mine, again);
          done();
        });
      }
      granted(mine, res);
      done();
    }, done);
  }

  function granted(mine, res) {
    if (!current(mine)) {
      return;
    }
    if (!res || !res.ok) {
      return failure(res, ui.status);
    }
    ui.status.textContent = text(ui.messages.shared || '');
    ui.expires.value = '';
    refresh(mine);
  }

  function revoke(granteeId) {
    if (!ui.target || !win.confirm(dmsg('confirm-revoke'))) {
      return;
    }
    var mine = ui.session;
    kb().api('revoke', { type: ui.target.type, id: ui.target.id, grantee_id: granteeId }).then(function (res) {
      if (!current(mine)) {
        return;
      }
      if (!res || !res.ok) {
        return failure(res, ui.status);
      }
      ui.status.textContent = '';
      ui.rotate.hidden = !res.suggest_rotate;
      refresh(mine);
    });
  }

  // ---- The activity view ---------------------------------------------------------------------------------------

  function activity(offset) {
    var mine = offset === 0 ? ++ui.activitySession : ui.activitySession;
    if (offset === 0) {
      ui.activityRows.textContent = '';
      ui.activityMore.hidden = true;
    }
    ui.activity.hidden = false;
    return kb().api('activity', { offset: offset }).then(function (res) {
      if (mine !== ui.activitySession) {
        return;
      }
      if (!res || !res.ok) {
        return failure(res, ui.activityEmpty);
      }
      (res.rows || []).forEach(addActivityRow);
      ui.nextActivity = res.next_offset;
      ui.activityMore.hidden = res.next_offset === null || res.next_offset === undefined;
      ui.activityEmpty.hidden = ui.activityRows.querySelectorAll('tr').length > 0;
    });
  }

  function addActivityRow(r) {
    var tr = el('tr', 'vault-row');
    var who = r.actor !== null && r.actor !== undefined ? text(r.actor) : text(r.actor_kind);
    var item = r.object_type ? (r.title !== null && r.title !== undefined && r.title !== '' ? text(r.title) : text(r.object_type) + ' #' + text(r.object_id)) : '';
    var details = [];
    if (r.target !== null && r.target !== undefined && r.target !== '') {
      details.push('→ ' + text(r.target));
    }
    if (r.count !== null && r.count !== undefined) {
      details.push('× ' + text(r.count));
    }
    if (r.ip_trunc) {
      details.push(text(r.ip_trunc));
    }
    if (r.ua_family) {
      details.push(text(r.ua_family));
    }
    details.push(text(r.via));
    tr.appendChild(el('td', '', when(r.created_at)));
    tr.appendChild(el('td', '', who));
    tr.appendChild(el('td', '', text(r.action)));
    tr.appendChild(el('td', '', item));
    tr.appendChild(el('td', 'vault-muted', details.join(' · ')));
    ui.activityRows.appendChild(tr);
  }

  // ---- Wiring --------------------------------------------------------------------------------------------------

  function init() {
    var app = doc.getElementById('vault-app');
    var dialog = q('[data-vault-share]');
    if (!app || app.getAttribute('data-vault-state') !== 'unlocked' || !dialog) {
      return;
    }
    ui = {
      messages: parse(app.getAttribute('data-messages')),
      dialog: dialog,
      label: q('[data-vault-share-label]', dialog),
      covered: q('[data-vault-share-covered]', dialog),
      form: q('[data-vault-form="share"]', dialog),
      grantee: q('[data-vault-share-grantee]', dialog),
      perm: q('[data-vault-share-perm]', dialog),
      agentNote: q('[data-vault-share-agent]', dialog),
      expires: q('[data-vault-share-expires]', dialog),
      status: q('[data-vault-share-status]', dialog),
      rotate: q('[data-vault-share-rotate]', dialog),
      grants: q('[data-vault-share-grants]', dialog),
      none: q('[data-vault-share-none]', dialog),
      activity: q('[data-vault-activity]'),
      activityRows: q('[data-vault-activity-rows]'),
      activityEmpty: q('[data-vault-activity-empty]'),
      activityMore: q('[data-vault-action="activity-more"]'),
      session: 0,
      activitySession: 0,
      target: null,
      kinds: {},
      busy: false,
      nextActivity: null
    };
    Array.prototype.forEach.call(doc.querySelectorAll('[data-vault-share-button]'), function (b) {
      b.addEventListener('click', function () {
        var type = b.getAttribute('data-vault-share-type');
        var id = b.getAttribute('data-vault-share-id');
        if (type && id) {
          open(type, id, b.getAttribute('data-vault-share-label'));
        }
      });
    });
    q('[data-vault-action="share-close"]', dialog).addEventListener('click', close);
    ui.form.addEventListener('submit', submit);
    ui.grantee.addEventListener('change', agentRule);
    var link = q('[data-vault-action="activity"]');
    if (link && ui.activity) {
      link.addEventListener('click', function () {
        activity(0);
      });
      ui.activityMore.addEventListener('click', function () {
        activity(ui.nextActivity || 0);
      });
      q('[data-vault-action="activity-close"]', ui.activity).addEventListener('click', function () {
        ui.activitySession++;
        ui.activity.hidden = true;
      });
    }
  }

  win.KBVaultShare = {
    open: function (type, id, label) {
      return ui ? open(type, id, label) : Promise.resolve();
    },
    activity: function (offset) {
      return ui ? activity(offset || 0) : Promise.resolve();
    }
  };

  if (doc && typeof doc.querySelector === 'function') {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }
})(window);
