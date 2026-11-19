/*
 * Vault's three-pane browser (spec: UI). Loaded by the unlocked shell only, after vault.js; no inline JS anywhere.
 * Adds to window.KBVault:
 *   render(node, data)          fills node's [data-field] elements with textContent, and an element that also has
 *                               data-href with an href only when safeHref allows the value. Never HTML.
 *   safeHref(url)               the URL when its scheme is http: or https:, else null.
 *   copy(text)                  writes text to the clipboard, then 30 s later writes "" if the tab still has focus.
 *   reveal(id, field, node)     fetches one field through vault/field into node's text, or masks it again.
 * Everything decrypted reaches the DOM through textContent, an input's value, or setAttribute on a fixed attribute.
 * Secrets (password, notes, OTP seed, custom field values) are fetched one field at a time from vault/field, which
 * audits each as read; the list and the detail answers carry metadata only.
 */
(function (win) {
  'use strict';

  var doc = win.document;
  var MASK = '••••••••';
  var CLEAR_MS = 30000;
  var TOAST_MS = 4000;
  var SECRETS = ['password', 'otp', 'notes'];

  function kb() {
    return win.KBVault;
  }

  function text(v) {
    return v === null || v === undefined ? '' : String(v);
  }

  function own(data, key) {
    return data && Object.prototype.hasOwnProperty.call(data, key) ? data[key] : undefined;
  }

  function safeHref(url) {
    if (typeof url !== 'string' || url === '') {
      return null;
    }
    var parsed;
    try {
      parsed = new win.URL(url);
    } catch (e) {
      return null;
    }
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : null;
  }

  function render(node, data) {
    var els = [node].concat(Array.prototype.slice.call(node.querySelectorAll('[data-field]')));
    els.forEach(function (el) {
      var key = el.getAttribute('data-field');
      if (key === null) {
        return;
      }
      el.textContent = text(own(data, key));
      var hrefKey = el.getAttribute('data-href');
      if (hrefKey === null) {
        return;
      }
      var href = safeHref(text(own(data, hrefKey)));
      if (href) {
        el.setAttribute('href', href);
        el.setAttribute('rel', 'noopener noreferrer');
        el.setAttribute('target', '_blank');
      } else {
        el.removeAttribute('href');
        el.removeAttribute('rel');
        el.removeAttribute('target');
      }
    });
    return node;
  }

  function copy(value) {
    var clip = win.navigator && win.navigator.clipboard;
    if (!clip || typeof clip.writeText !== 'function') {
      return Promise.resolve(false);
    }
    return clip.writeText(text(value)).then(function () {
      win.setTimeout(function () {
        if (doc.hasFocus()) {
          return clip.writeText('').then(null, function () {});
        }
      }, CLEAR_MS);
      return true;
    }, function () {
      return false;
    });
  }

  function reveal(id, field, node) {
    if (node.getAttribute('data-revealed') === '1') {
      node.textContent = MASK;
      node.removeAttribute('data-revealed');
      return Promise.resolve(false);
    }
    return kb().api('field', { id: id, field: field }).then(function (res) {
      if (!res || !res.ok) {
        report(res);
        return false;
      }
      node.textContent = text(res.value);
      node.setAttribute('data-revealed', '1');
      return true;
    });
  }

  // ---- The page ------------------------------------------------------------------------------------------------

  var ui = null;

  function parse(json) {
    try {
      var v = JSON.parse(json || '');
      return v && typeof v === 'object' ? v : {};
    } catch (e) {
      return {};
    }
  }

  function msg(key) {
    var m = ui ? ui.messages : {};
    return text(own(m, key) || own(m, 'failed') || 'Error');
  }

  function toast(message) {
    if (!ui || !ui.toast) {
      return;
    }
    ui.toast.textContent = message;
    ui.toast.hidden = false;
    win.clearTimeout(ui.toastTimer);
    ui.toastTimer = win.setTimeout(function () {
      ui.toast.hidden = true;
    }, TOAST_MS);
  }

  function report(res) {
    var reason = res && res.reason;
    if (reason === 'locked') {
      win.location.reload();
      return;
    }
    toast(msg(reason));
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

  function clear(node) {
    node.textContent = '';
  }

  function ago(ts) {
    var s = Math.max(0, Math.floor(Date.now() / 1000) - (ts || 0));
    if (s < 3600) {
      return Math.max(1, Math.floor(s / 60)) + ' min';
    }
    if (s < 86400) {
      return Math.floor(s / 3600) + ' h';
    }
    return Math.floor(s / 86400) + ' d';
  }

  function day(ts) {
    return ts ? new Date(ts * 1000).toISOString().slice(0, 10) : '';
  }

  function host(url) {
    try {
      return new win.URL(url).host || url;
    } catch (e) {
      return url;
    }
  }

  function canEdit(perm) {
    return perm === 'owner' || perm === 'edit';
  }

  // Tree

  function loadTree() {
    return kb().api('tree', {}).then(function (res) {
      if (!res || !res.ok) {
        return report(res);
      }
      ui.groups = res.groups || [];
      var known = {};
      var children = {};
      ui.groups.forEach(function (g) {
        known[g.id] = g;
      });
      ui.groups.forEach(function (g) {
        var parent = g.parent_id !== null && known[g.parent_id] ? g.parent_id : 'root';
        (children[parent] = children[parent] || []).push(g);
      });
      clear(ui.ownTree);
      clear(ui.sharedTree);
      (children.root || []).forEach(function (g) {
        (g.shared_by === null ? ui.ownTree : ui.sharedTree).appendChild(treeNode(g, children));
      });
      ui.sharedEntries.hidden = !res.shared_entries;
      if (ui.current && ui.current.group && !known[ui.current.group.id]) {
        ui.current = null;
        showList(null);
      }
    });
  }

  function treeNode(g, children) {
    var li = el('li');
    var label = g.integrity_error ? msg('integrity_error') : text(g.name);
    if (g.shared_by) {
      label += ' (' + msg('from') + ' ' + text(g.shared_by) + ')';
    }
    var button = el('button', 'vault-node', label);
    button.type = 'button';
    button.setAttribute('data-group-id', String(g.id));
    button.disabled = !!g.integrity_error;
    button.addEventListener('click', function () {
      selectGroup(g);
    });
    li.appendChild(button);
    var kids = children[g.id] || [];
    if (kids.length) {
      var ul = el('ul', 'vault-tree-list');
      kids.forEach(function (c) {
        ul.appendChild(treeNode(c, children));
      });
      li.appendChild(ul);
    }
    return li;
  }

  function markActive(button) {
    Array.prototype.forEach.call(ui.panes.querySelectorAll('.vault-node'), function (b) {
      b.classList.toggle('is-active', b === button);
    });
  }

  function selectGroup(g) {
    ui.current = { group: g };
    markActive(q('[data-group-id="' + g.id + '"]', ui.panes));
    showList(text(g.name));
    loadList(0);
  }

  function selectShared() {
    ui.current = { shared: true };
    markActive(ui.sharedEntries);
    showList(msg('shared_entries'));
    loadList(0);
  }

  // List

  function showList(title) {
    ui.listTitle.textContent = text(title);
    clear(ui.rows);
    ui.rowIndex = [];
    ui.more.hidden = true;
    ui.listEmpty.hidden = false;
    ui.listEmpty.textContent = title === null ? ui.selectGroupText : msg('no_entries');
    ui.deleteGroup.hidden = !(ui.current && ui.current.group && ui.current.group.permission === 'owner');
    hideDetail();
  }

  function loadList(offset) {
    var cur = ui.current;
    if (!cur) {
      return Promise.resolve();
    }
    var body = cur.shared ? { shared: 1, offset: offset } : { group_id: cur.group.id, offset: offset };
    return kb().api('list', body).then(function (res) {
      if (ui.current !== cur) {
        return;
      }
      if (!res || !res.ok) {
        return report(res);
      }
      if (offset === 0) {
        clear(ui.rows);
        ui.rowIndex = [];
      }
      (res.entries || []).forEach(addRow);
      ui.nextOffset = res.next_offset;
      ui.more.hidden = res.next_offset === null || res.next_offset === undefined;
      ui.listEmpty.hidden = ui.rowIndex.length > 0;
      filter();
    });
  }

  function addRow(e) {
    var tr = el('tr', 'vault-row');
    if (e.integrity_error) {
      var td = el('td', 'vault-muted', msg('integrity_error'));
      td.colSpan = 4;
      tr.appendChild(td);
      ui.rows.appendChild(tr);
      ui.rowIndex.push({ tr: tr, hay: '' });
      return;
    }
    tr.tabIndex = 0;
    tr.appendChild(el('td', '', e.title));
    tr.appendChild(el('td', '', e.username));
    tr.appendChild(el('td', '', host(text(e.url))));
    tr.appendChild(el('td', '', ago(e.updated_at)));
    var open = function () {
      Array.prototype.forEach.call(ui.rows.querySelectorAll('.is-active'), function (r) {
        r.classList.remove('is-active');
      });
      tr.classList.add('is-active');
      loadEntry(e.id);
    };
    tr.addEventListener('click', open);
    tr.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') {
        open();
      }
    });
    ui.rows.appendChild(tr);
    ui.rowIndex.push({ tr: tr, hay: (text(e.title) + ' ' + text(e.username) + ' ' + text(e.url)).toLowerCase() });
  }

  function filter() {
    var needle = text(ui.search && ui.search.value).trim().toLowerCase();
    ui.rowIndex.forEach(function (r) {
      r.tr.hidden = needle !== '' && r.hay.indexOf(needle) === -1;
    });
  }

  // Detail

  function hideDetail() {
    ui.entry = null;
    ui.detail.hidden = true;
    ui.detailEmpty.hidden = false;
    closeEditor();
    maskAll();
  }

  function maskAll() {
    Array.prototype.forEach.call(ui.panes.querySelectorAll('[data-vault-value]'), function (v) {
      v.textContent = MASK;
      v.removeAttribute('data-revealed');
    });
  }

  function loadEntry(id) {
    return kb().api('entry', { id: id }).then(function (res) {
      if (!res || !res.ok) {
        return report(res);
      }
      showEntry(res.entry);
    });
  }

  function showEntry(entry) {
    closeEditor();
    ui.entry = entry;
    render(ui.detail, {
      title: entry.title,
      username: entry.username,
      url: entry.url,
      tags: (entry.tags || []).join(', '),
      expires: day(entry.expires_at),
      modified: ago(entry.updated_at)
    });
    maskAll();
    SECRETS.forEach(function (name) {
      Array.prototype.forEach.call(ui.detail.querySelectorAll('[data-vault-secret="' + name + '"]'), function (n) {
        n.hidden = !(entry.secrets && entry.secrets[name]);
      });
    });
    clear(ui.custom);
    (entry.fields || []).forEach(function (f) {
      var ref = 'field:' + f.name;
      ui.custom.appendChild(el('dt', '', f.name));
      var dd = el('dd');
      var value = el('span', 'vault-secret', MASK);
      value.setAttribute('data-vault-value', ref);
      dd.appendChild(value);
      dd.appendChild(document_text(' '));
      dd.appendChild(iconButton('data-vault-reveal', ref, 'fa-eye'));
      dd.appendChild(iconButton('data-vault-copy', ref, 'fa-clipboard'));
      ui.custom.appendChild(dd);
    });
    ui.editBtn.hidden = !canEdit(entry.permission);
    ui.deleteBtn.hidden = entry.permission !== 'owner';
    fillMove(entry);
    ui.detail.hidden = false;
    ui.detailEmpty.hidden = true;
  }

  function document_text(s) {
    return doc.createTextNode(s);
  }

  function iconButton(attr, ref, icon) {
    var b = el('button', 'vault-icon');
    b.type = 'button';
    b.setAttribute(attr, ref);
    var i = el('i', 'fa ' + icon);
    i.setAttribute('aria-hidden', 'true');
    b.appendChild(i);
    return b;
  }

  function fillMove(entry) {
    var select = ui.move;
    while (select.options.length > 1) {
      select.remove(1);
    }
    select.value = '';
    if (entry.permission !== 'owner') {
      select.hidden = true;
      return;
    }
    (ui.groups || []).forEach(function (g) {
      if (g.permission === 'owner' && !g.integrity_error && g.id !== entry.group_id) {
        var o = el('option', '', g.name);
        o.value = String(g.id);
        select.appendChild(o);
      }
    });
    select.hidden = select.options.length < 2;
  }

  function copyField(field) {
    if (!ui.entry) {
      return Promise.resolve();
    }
    return kb().api('field', { id: ui.entry.id, field: field }).then(function (res) {
      if (!res || !res.ok) {
        return report(res);
      }
      return copy(res.value).then(function (ok) {
        toast(ok ? msg('copied') : msg('failed'));
      });
    });
  }

  function onDetailClick(ev) {
    var b = ev.target && ev.target.closest ? ev.target.closest('button') : null;
    if (!b || !ui.entry) {
      return;
    }
    var revealRef = b.getAttribute('data-vault-reveal');
    var copyRef = b.getAttribute('data-vault-copy');
    if (revealRef !== null) {
      var node = null;
      Array.prototype.forEach.call(ui.detail.querySelectorAll('[data-vault-value]'), function (v) {
        if (v.getAttribute('data-vault-value') === revealRef) {
          node = v;
        }
      });
      if (node) {
        reveal(ui.entry.id, revealRef, node);
      }
    } else if (copyRef !== null) {
      copyField(copyRef);
    }
  }

  // Editor

  function closeEditor() {
    if (!ui.form) {
      return;
    }
    ui.form.hidden = true;
    Array.prototype.forEach.call(ui.form.querySelectorAll('input:not([type="hidden"]), textarea'), function (i) {
      i.value = '';
    });
    clear(ui.editFields);
    ui.editing = null;
  }

  function addFieldRow(f) {
    var row = el('div', 'vault-edit-field');
    var name = el('input');
    name.type = 'text';
    name.className = 'vault-field-name';
    name.value = text(f && f.name);
    name.setAttribute('aria-label', 'name');
    var value = el('input');
    value.type = f && f.protected ? 'password' : 'text';
    value.className = 'vault-field-value';
    value.value = text(f && f.value);
    value.setAttribute('autocomplete', 'off');
    value.setAttribute('aria-label', 'value');
    var label = el('label', 'vault-field-protected');
    var prot = el('input');
    prot.type = 'checkbox';
    prot.checked = !!(f && f.protected);
    prot.addEventListener('change', function () {
      value.type = prot.checked ? 'password' : 'text';
    });
    label.appendChild(prot);
    label.appendChild(document_text(' 🔒'));
    var remove = el('button', 'vault-icon');
    remove.type = 'button';
    remove.appendChild(el('i', 'fa fa-times'));
    remove.addEventListener('click', function () {
      value.value = '';
      ui.editFields.removeChild(row);
    });
    row.appendChild(name);
    row.appendChild(value);
    row.appendChild(label);
    row.appendChild(remove);
    ui.editFields.appendChild(row);
  }

  function openEditor(entry) {
    if (!entry && !(ui.current && ui.current.group && canEdit(ui.current.group.permission))) {
      toast(msg('not_found'));
      return Promise.resolve();
    }
    closeEditor();
    var f = ui.form.elements;
    ui.editing = entry ? { id: entry.id, version: entry.version } : { group_id: ui.current.group.id };
    var editing = ui.editing;
    if (!entry) {
      showEditor();
      return Promise.resolve();
    }
    f.title.value = text(entry.title);
    f.username.value = text(entry.username);
    f.url.value = text(entry.url);
    f.tags.value = (entry.tags || []).join(', ');
    f.expires.value = day(entry.expires_at);
    // The secrets come one field at a time from vault/field, like a reveal (and audited the same way).
    var wanted = SECRETS.filter(function (n) {
      return entry.secrets && entry.secrets[n];
    });
    var fetches = wanted.map(function (n) {
      return kb().api('field', { id: entry.id, field: n });
    }).concat((entry.fields || []).map(function (fd) {
      return kb().api('field', { id: entry.id, field: 'field:' + fd.name });
    }));
    return Promise.all(fetches).then(function (results) {
      if (ui.editing !== editing) {
        return;
      }
      for (var i = 0; i < results.length; i++) {
        if (!results[i] || !results[i].ok) {
          closeEditor();
          return report(results[i]);
        }
      }
      wanted.forEach(function (n, i) {
        f[n].value = text(results[i].value);
      });
      (entry.fields || []).forEach(function (fd, i) {
        addFieldRow({ name: fd.name, protected: fd.protected, value: results[wanted.length + i].value });
      });
      showEditor();
    });
  }

  function showEditor() {
    ui.detail.hidden = true;
    ui.detailEmpty.hidden = true;
    ui.form.hidden = false;
    ui.form.elements.title.focus();
  }

  function collect() {
    var f = ui.form.elements;
    var exp = text(f.expires.value);
    var fields = [];
    Array.prototype.forEach.call(ui.editFields.querySelectorAll('.vault-edit-field'), function (row) {
      var name = row.querySelector('.vault-field-name').value;
      if (name.trim() !== '') {
        fields.push({ name: name, value: row.querySelector('.vault-field-value').value, protected: row.querySelector('input[type="checkbox"]').checked });
      }
    });
    return {
      title: f.title.value,
      username: f.username.value,
      password: f.password.value,
      url: f.url.value,
      notes: f.notes.value,
      otp: f.otp.value,
      tags: text(f.tags.value).split(',').map(function (t) {
        return t.trim();
      }).filter(function (t) {
        return t !== '';
      }),
      expires_at: exp ? Math.floor(Date.parse(exp + 'T00:00:00Z') / 1000) : null,
      fields: fields
    };
  }

  function save(ev) {
    ev.preventDefault();
    var editing = ui.editing;
    if (!editing) {
      return;
    }
    var body = { type: 'entry', payload: collect() };
    if (editing.id) {
      body.id = editing.id;
      body.version = editing.version;
    } else {
      body.group_id = editing.group_id;
    }
    kb().api('save', body).then(function (res) {
      if (!res || !res.ok) {
        return report(res);
      }
      closeEditor();
      toast(msg('saved'));
      loadList(0);
      loadEntry(res.id);
    });
  }

  function newGroup() {
    var name = win.prompt(msg('group_name'));
    if (name === null || name.trim() === '') {
      return;
    }
    var parent = ui.current && ui.current.group && ui.current.group.permission === 'owner' ? ui.current.group.id : '';
    kb().api('save', { type: 'group', parent_id: parent, payload: { name: name.trim() } }).then(function (res) {
      if (!res || !res.ok) {
        return report(res);
      }
      loadTree();
    });
  }

  function remove(type, id, after) {
    if (!win.confirm(msg('confirm_delete'))) {
      return;
    }
    kb().api('delete', { type: type, id: id }).then(function (res) {
      if (!res || !res.ok) {
        return report(res);
      }
      after();
    });
  }

  function moveEntry() {
    var target = ui.move.value;
    if (!ui.entry || target === '') {
      return;
    }
    kb().api('move', { type: 'entry', id: ui.entry.id, parent_id: target }).then(function (res) {
      if (!res || !res.ok) {
        return report(res);
      }
      loadList(0);
    });
  }

  function on(sel, ev, fn) {
    var n = q(sel);
    if (n) {
      n.addEventListener(ev, fn);
    }
    return n;
  }

  function init() {
    var panes = q('[data-vault-panes]');
    var app = doc.getElementById('vault-app');
    if (!panes || !app || app.getAttribute('data-vault-state') !== 'unlocked') {
      return;
    }
    ui = {
      panes: panes,
      messages: parse(app.getAttribute('data-messages')),
      ownTree: q('[data-vault-tree="own"]', panes),
      sharedTree: q('[data-vault-tree="shared"]', panes),
      sharedEntries: q('[data-vault-action="shared-entries"]', panes),
      listTitle: q('[data-vault-list-title]', panes),
      rows: q('[data-vault-rows]', panes),
      listEmpty: q('[data-vault-list-empty]', panes),
      more: q('[data-vault-action="more"]', panes),
      deleteGroup: q('[data-vault-action="delete-group"]', panes),
      detail: q('[data-vault-detail]', panes),
      detailEmpty: q('[data-vault-detail-empty]', panes),
      custom: q('[data-vault-custom]', panes),
      editBtn: q('[data-vault-action="edit"]', panes),
      deleteBtn: q('[data-vault-action="delete"]', panes),
      move: q('[data-vault-move]', panes),
      form: q('[data-vault-form="edit"]', panes),
      editFields: q('[data-vault-edit-fields]', panes),
      search: q('[data-vault-search]'),
      toast: q('[data-vault-toast]'),
      groups: [],
      rowIndex: [],
      current: null,
      entry: null,
      editing: null
    };
    ui.selectGroupText = ui.listEmpty.textContent;
    ui.sharedEntries.addEventListener('click', selectShared);
    ui.more.addEventListener('click', function () {
      loadList(ui.nextOffset || 0);
    });
    ui.deleteGroup.addEventListener('click', function () {
      if (ui.current && ui.current.group) {
        remove('group', ui.current.group.id, function () {
          ui.current = null;
          showList(null);
          loadTree();
        });
      }
    });
    ui.detail.addEventListener('click', onDetailClick);
    ui.editBtn.addEventListener('click', function () {
      openEditor(ui.entry);
    });
    ui.deleteBtn.addEventListener('click', function () {
      if (ui.entry) {
        remove('entry', ui.entry.id, function () {
          hideDetail();
          loadList(0);
        });
      }
    });
    ui.move.addEventListener('change', moveEntry);
    ui.form.addEventListener('submit', save);
    on('[data-vault-action="cancel"]', 'click', function () {
      closeEditor();
      if (ui.entry) {
        showEntry(ui.entry);
      } else {
        hideDetail();
      }
    });
    on('[data-vault-action="add-field"]', 'click', function () {
      addFieldRow({ name: '', value: '', protected: true });
    });
    on('[data-vault-action="new-entry"]', 'click', function () {
      openEditor(null);
    });
    on('[data-vault-action="new-group"]', 'click', newGroup);
    if (ui.search) {
      ui.search.addEventListener('input', filter);
    }
    loadTree();
  }

  var api = kb() || (win.KBVault = {});
  api.render = render;
  api.safeHref = safeHref;
  api.copy = copy;
  api.reveal = reveal;

  if (doc && typeof doc.querySelector === 'function') {
    if (doc.readyState === 'loading') {
      doc.addEventListener('DOMContentLoaded', init);
    } else {
      init();
    }
  }
})(window);
