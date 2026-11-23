<?php
// Settings → Vault (spec: Admin settings). A plain form POST with the CSRF token to vault/settings/save; no script.
// The bound rp_id and origin, the effective idle cap, the deployment checks and the integrity faults are shown,
// never edited. Messages are fixed sentences (no paths, no secrets); integrity faults are type and id only.
$policies = [
    'none' => t('None: a forgotten passphrase means a lost vault'),
    'code' => t('Personal recovery code'),
    'code_org' => t('Personal recovery code and organisation key'),
];
$expiries = [3600 => t('1 hour'), 86400 => t('1 day'), 604800 => t('7 days')];
?>
<?= $this->asset->css('plugins/Vault/Assets/css/vault.css') ?>
<div class="page-header"><h2><?= t('Vault') ?></h2></div>
<?php if ($saved): ?>
<p class="alert alert-success" role="status"><?= t('Settings saved.') ?></p>
<?php endif ?>
<?php if ($orphan_notice !== ''): ?>
<p class="alert alert-success" role="status" data-vault-orphan-notice><?= $this->text->e($orphan_notice) ?></p>
<?php endif ?>
<?php if ($error !== ''): ?>
<p class="alert alert-error" role="alert"><?= $this->text->e($error) ?></p>
<?php endif ?>

<form method="post" action="<?= $this->url->href('SettingsController', 'save', ['plugin' => 'Vault']) ?>" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= $this->text->e($csrf) ?>">

    <fieldset>
        <legend><?= t('Recovery') ?></legend>
        <label for="vault-s-policy"><?= t('Recovery policy') ?></label>
        <select id="vault-s-policy" name="vault_recovery_policy">
            <?php foreach ($policies as $value => $label): ?>
            <option value="<?= $this->text->e($value) ?>"<?= $vault['vault_recovery_policy'] === $value ? ' selected' : '' ?>><?= $this->text->e($label) ?></option>
            <?php endforeach ?>
        </select>
        <p class="form-help"><?= t('Lowering the policy deletes the recovery codes or organisation wraps it no longer allows, and each affected user\'s keys rotate at their next unlock. The organisation key is made with php cli vault:org-keygen.') ?></p>
    </fieldset>

    <fieldset>
        <legend><?= t('Unlocking') ?></legend>
        <input type="hidden" name="vault_hw_required" value="0">
        <label><input type="checkbox" name="vault_hw_required" value="1"<?= $vault['vault_hw_required'] ? ' checked' : '' ?>> <?= t('Require two hardware keys for every user') ?></label>
        <label for="vault-s-idle"><?= t('Idle timeout (minutes)') ?></label>
        <input type="number" id="vault-s-idle" name="vault_idle_timeout" min="5" max="60" required value="<?= (int) $vault['vault_idle_timeout'] ?>">
        <p class="form-help"><?= t('Effective idle timeout:') ?> <strong data-vault-effective-idle><?= (int) $effective_idle ?></strong> <?= t('min') ?>.
            <?= t('It can\'t outlive the Kanboard session (%d min: SESSION_DURATION, or PHP\'s session.gc_maxlifetime when that is 0).', (int) $session_minutes) ?></p>
        <label for="vault-s-proxies"><?= t('Trusted proxy addresses') ?></label>
        <textarea id="vault-s-proxies" name="vault_trusted_proxy_cidrs" rows="3" spellcheck="false"><?= $this->text->e(str_replace(',', "\n", (string) $vault['vault_trusted_proxy_cidrs'])) ?></textarea>
        <p class="form-help"><?= t('Addresses or CIDR ranges, one per line, that may send X-Forwarded-For, CF-Connecting-IP and X-Forwarded-Proto: your reverse proxy or cloudflared. Empty means no forwarding header is trusted.') ?></p>
        <?php foreach ($mapped_cidrs as $cidr): ?>
        <p class="alert alert-error" data-vault-mapped-cidr><?= t('%s is an IPv4-mapped IPv6 range and matches nothing. Write it as an IPv4 address or range.', $this->text->e($cidr)) ?></p>
        <?php endforeach ?>
    </fieldset>

    <fieldset>
        <legend><?= t('Sharing and agents') ?></legend>
        <label for="vault-s-expiry"><?= t('Longest one-time link expiry') ?></label>
        <select id="vault-s-expiry" name="vault_share_max_expiry">
            <?php foreach ($share_expiries as $seconds): ?>
            <option value="<?= (int) $seconds ?>"<?= (int) $vault['vault_share_max_expiry'] === (int) $seconds ? ' selected' : '' ?>><?= $this->text->e($expiries[$seconds] ?? (string) $seconds) ?></option>
            <?php endforeach ?>
        </select>
        <label for="vault-s-reveal"><?= t('One-time link reveals per client address per 10 minutes') ?></label>
        <input type="number" id="vault-s-reveal" name="vault_reveal_limit" min="1" max="1000" required value="<?= (int) $vault['vault_reveal_limit'] ?>">
        <label for="vault-s-agent"><?= t('Most secret reads an agent may make per hour') ?></label>
        <input type="number" id="vault-s-agent" name="vault_agent_cap_max" min="1" max="10000" required value="<?= (int) $vault['vault_agent_cap_max'] ?>">
        <label for="vault-s-server-rate"><?= t('Most secret reads a Server grant may allow per hour') ?></label>
        <input type="number" id="vault-s-server-rate" name="vault_server_rate_max" min="1" max="10000" required value="<?= (int) $vault['vault_server_rate_max'] ?>">
        <label for="vault-s-server-burst"><?= t('Largest burst a Server grant may allow') ?></label>
        <input type="number" id="vault-s-server-burst" name="vault_server_burst_max" min="1" max="1000" required value="<?= (int) $vault['vault_server_burst_max'] ?>">
    </fieldset>

    <fieldset>
        <legend><?= t('Audit') ?></legend>
        <label for="vault-s-retention"><?= t('Keep audit rows for (days)') ?></label>
        <input type="number" id="vault-s-retention" name="vault_audit_retention_days" min="1" max="3650" required value="<?= (int) $vault['vault_audit_retention_days'] ?>">
    </fieldset>

    <div class="form-actions"><button type="submit" class="btn btn-blue"><?= t('Save') ?></button></div>
</form>

<h3><?= t('Server sharing') ?></h3>
<p data-vault-server-state="<?= $server_on ? 'on' : 'off' ?>"><?= $server_on
    ? t('On. Owners can share single entries with Kanboard plugins that read them on the server.')
    : t('Off. No plugin can read a vault entry on the server.') ?></p>
<label for="vault-s-server-key"><?= t('Server key file') ?></label>
<input type="text" id="vault-s-server-key" data-vault-server-key-path readonly spellcheck="false" value="<?= $this->text->e($server_key_path) ?>">
<p class="form-help"><?= t('Read-only: set it with VAULT_SERVER_KEY_FILE in config.php. Keep this file out of your database backups: a backup without it can\'t open what is shared with Server, and with it, it can.') ?></p>
<form method="post" action="<?= $this->url->href('SettingsController', 'server', ['plugin' => 'Vault']) ?>" autocomplete="off" data-vault-form="server">
    <input type="hidden" name="csrf_token" value="<?= $this->text->e($csrf) ?>">
    <?php if ($server_on): ?>
    <input type="hidden" name="enabled" value="0">
    <label><input type="checkbox" name="confirm" value="1" required> <?= t('Turning Server sharing off deletes every Server share. Owners must share each entry again after it is turned back on.') ?></label>
    <div class="form-actions"><button type="submit" class="btn btn-red"><?= t('Turn Server sharing off') ?></button></div>
    <?php else: ?>
    <input type="hidden" name="enabled" value="1">
    <label for="vault-s-server-passphrase"><?= t('Your vault passphrase') ?></label>
    <input type="password" id="vault-s-server-passphrase" name="passphrase" autocomplete="off" data-lpignore="true" data-1p-ignore data-bwignore required>
    <p class="form-help"><?= t('Your vault must be unlocked. Turning this on lets a server that has both the database and the key file read the entries owners share with Server.') ?></p>
    <div class="form-actions"><button type="submit" class="btn btn-blue"><?= t('Turn Server sharing on') ?></button></div>
    <?php endif ?>
</form>

<h3><?= t('Orphaned entries') ?></h3>
<p><?= t('Entries shared with Server whose owner was deleted. Nobody can read them, Server included, until an administrator with access claims one (it is re-encrypted into a group of yours) or deletes it. Only the entry number is shown.') ?></p>
<?php if ($orphans === []): ?>
<p data-vault-orphans-none><?= t('None.') ?></p>
<?php endif ?>
<?php foreach ($orphans as $o): ?>
<div class="vault-orphan" data-vault-orphan="<?= (int) $o['entry_id'] ?>">
    <h4><?= t('Entry #%d', (int) $o['entry_id']) ?></h4>
    <?php if (empty($o['can_claim'])): ?>
    <p class="form-help" data-vault-no-claim="<?= (int) $o['entry_id'] ?>"><?= t('You weren\'t given access to this entry, so you can\'t claim it. An administrator who was can, or you can delete it.') ?></p>
    <?php else: ?>
    <form method="post" action="<?= $this->url->href('OrphanController', 'claim', ['plugin' => 'Vault']) ?>" autocomplete="off" data-vault-form="orphan-claim">
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($csrf) ?>">
        <input type="hidden" name="entry_id" value="<?= (int) $o['entry_id'] ?>">
        <?php if ($claim_groups === null): ?>
        <p class="form-help"><?= t('Unlock your vault to claim.') ?></p>
        <?php elseif ($claim_groups === []): ?>
        <p class="form-help"><?= t('Create a group in your vault to claim into.') ?></p>
        <?php else: ?>
        <label for="vault-orphan-group-<?= (int) $o['entry_id'] ?>"><?= t('Move it into your group') ?></label>
        <select id="vault-orphan-group-<?= (int) $o['entry_id'] ?>" name="group_id" required>
            <?php foreach ($claim_groups as $id => $name): ?>
            <option value="<?= (int) $id ?>"><?= $this->text->e($name) ?></option>
            <?php endforeach ?>
        </select>
        <div class="form-actions"><button type="submit" class="btn btn-blue"><?= t('Claim') ?></button></div>
        <?php endif ?>
    </form>
    <?php endif ?>
    <form method="post" action="<?= $this->url->href('OrphanController', 'destroy', ['plugin' => 'Vault']) ?>" autocomplete="off" data-vault-form="orphan-destroy">
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($csrf) ?>">
        <input type="hidden" name="entry_id" value="<?= (int) $o['entry_id'] ?>">
        <label for="vault-orphan-passphrase-<?= (int) $o['entry_id'] ?>"><?= t('Your vault passphrase') ?></label>
        <input type="password" id="vault-orphan-passphrase-<?= (int) $o['entry_id'] ?>" name="passphrase" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore required>
        <p class="form-help"><?= t('Your vault must be unlocked. Deleting can\'t be undone.') ?></p>
        <div class="form-actions"><button type="submit" class="btn btn-red"><?= t('Delete') ?></button></div>
    </form>
</div>
<?php endforeach ?>

<?php if (! empty($blocked_ids)): ?>
<p class="alert alert-error"><?= t('These user numbers still belong to a deleted user whose orphaned entries are listed above. Kanboard has given the number to a new user, who can\'t set up a vault until those entries are claimed or deleted:') ?></p>
<ul class="vault-blocked-ids">
    <?php foreach ($blocked_ids as $id): ?>
    <li data-vault-blocked-id="<?= (int) $id ?>"><?= t('User #%d', (int) $id) ?></li>
    <?php endforeach ?>
</ul>
<?php endif ?>

<h3><?= t('Entries at risk') ?></h3>
<p><?= t('Entries shared with Server whose owner is disabled, or that no other administrator has access to: if the owner were deleted, nobody could claim them. Only the entry number is shown.') ?></p>
<?php if ($at_risk === []): ?>
<p data-vault-at-risk-none><?= t('None.') ?></p>
<?php else: ?>
<ul class="vault-at-risk">
    <?php foreach ($at_risk as $r): ?>
    <li data-vault-at-risk="<?= (int) $r['entry_id'] ?>"><?= t('Entry #%d', (int) $r['entry_id']) ?>: <?= $r['reason'] === 'owner_disabled' ? t('the owner is disabled') : t('no other administrator has access') ?></li>
    <?php endforeach ?>
</ul>
<?php endif ?>

<h3><?= t('Hardware keys') ?></h3>
<?php if ($relying_party !== null): ?>
<dl class="vault-readonly">
    <dt><?= t('Relying party ID') ?></dt><dd><code data-vault-rp-id><?= $this->text->e($relying_party['rp_id']) ?></code></dd>
    <dt><?= t('Origin') ?></dt><dd><code data-vault-origin><?= $this->text->e($relying_party['origin']) ?></code></dd>
</dl>
<p class="form-help"><?= t('Read-only: both come from Kanboard\'s Application URL. Hardware keys are bound to this host, so moving Kanboard to another domain makes them unusable. Users should export their vault or remove their keys first.') ?></p>
<?php else: ?>
<p class="alert alert-error" data-vault-rp-unset><?= t('Kanboard\'s Application URL is not an https:// address, so hardware keys can\'t be enrolled. Set it in Settings → Application.') ?></p>
<?php endif ?>

<h3><?= t('Deployment checks') ?></h3>
<ul class="vault-checks">
    <?php foreach ($checks as $key => $check): ?>
    <li class="<?= $check['ok'] ? 'vault-check-ok' : 'vault-check-warn' ?>" data-vault-check="<?= $this->text->e($key) ?>">
        <i class="fa <?= $check['ok'] ? 'fa-check' : 'fa-exclamation-triangle' ?>" aria-hidden="true"></i>
        <span class="sr-only"><?= $check['ok'] ? t('OK') : t('Warning') ?></span>
        <?= $this->text->e($check['message']) ?>
    </li>
    <?php endforeach ?>
</ul>

<h3><?= t('Integrity faults') ?></h3>
<p><?= t('Objects that a key rotation found but couldn\'t re-encrypt:') ?> <strong data-vault-integrity-count><?= (int) $integrity['count'] ?></strong>.
    <?= t('Their old key is kept until someone with access re-saves or deletes them. Nothing about their contents is shown here.') ?></p>
<?php if ($integrity['objects'] !== []): ?>
<ul class="vault-integrity">
    <?php foreach ($integrity['objects'] as $o): ?>
    <li data-vault-integrity-object><?= $this->text->e($o['object_type']) ?> #<?= (int) $o['object_id'] ?></li>
    <?php endforeach ?>
</ul>
<?php endif ?>
