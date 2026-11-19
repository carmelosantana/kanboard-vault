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
    </fieldset>

    <fieldset>
        <legend><?= t('Audit') ?></legend>
        <label for="vault-s-retention"><?= t('Keep audit rows for (days)') ?></label>
        <input type="number" id="vault-s-retention" name="vault_audit_retention_days" min="1" max="3650" required value="<?= (int) $vault['vault_audit_retention_days'] ?>">
    </fieldset>

    <div class="form-actions"><button type="submit" class="btn btn-blue"><?= t('Save') ?></button></div>
</form>

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
