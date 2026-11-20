<?php
// "My vault security" (R40). The passphrase forms POST natively to their own endpoints with the CSRF token (fix C1)
// and vault-security.js sends them through KBVault.api instead when it runs. A recovery code needs the current
// passphrase (R54); with vault.js it comes back as JSON, without it this page is rendered once with it ($code,
// no-store). Either way it is shown once and vault-security.js asks for group 3 back before clearing it. No inline JS.
?>
<div class="page-header vault-header">
    <h2><?= t('Vault security') ?></h2>
    <ul class="vault-toolbar">
        <li><a class="btn" href="<?= $this->url->href('VaultController', 'index', ['plugin' => 'Vault']) ?>"><i class="fa fa-arrow-left" aria-hidden="true"></i> <?= t('Back to the vault') ?></a></li>
        <li><button type="button" class="btn" data-vault-action="lock"><i class="fa fa-lock" aria-hidden="true"></i> <?= t('Lock') ?></button></li>
    </ul>
</div>
<?= $this->render('Vault:vault/app', ['state' => 'unlocked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-generator.js') ?>
<?php if (! empty($hw_keys)): ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-webauthn.js') ?>
<?php endif ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-security.js') ?>
<?php if ($notice !== ''): ?>
<p class="alert alert-success vault-banner" role="status"><?= $this->text->e($notice) ?></p>
<?php endif ?>
<?php if ($error !== ''): ?>
<p class="alert alert-error vault-banner" role="alert"><?= $this->text->e($error) ?></p>
<?php endif ?>

<section class="vault-card vault-section">
    <h3><?= t('Hardware keys') ?></h3>
    <p><?= t('Add security keys so unlocking needs your passphrase and a key. With keys, change your passphrase or rotate your keys on the hardware key page.') ?> <?= $this->url->link(t('Manage hardware keys'), 'HardwareKeyController', 'index', ['plugin' => 'Vault'], false, '', '', false, '', false) ?></p>
</section>

<section class="vault-card vault-section">
    <h3><?= t('Change passphrase') ?></h3>
    <p><?= t('Your vault gets a new key and is re-encrypted. Backups taken before the change still open with the old passphrase.') ?></p>
    <form class="vault-form" data-vault-form="passphrase" method="post" action="<?= $this->url->href('SecurityController', 'passphrase', ['plugin' => 'Vault']) ?>">
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
        <label for="vault-current"><?= t('Current passphrase') ?></label>
        <input type="password" id="vault-current" name="current" required autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <label for="vault-new-passphrase"><?= t('New passphrase') ?></label>
        <input type="password" id="vault-new-passphrase" name="passphrase" required minlength="<?= \Kanboard\Plugin\Vault\Model\PrincipalModel::MIN_PASSPHRASE_CHARS ?>" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <label for="vault-new-confirm"><?= t('Type it again') ?></label>
        <input type="password" id="vault-new-confirm" name="confirm" required autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <p class="form-help"><?= t('At least %d characters. A few unrelated words work well.', \Kanboard\Plugin\Vault\Model\PrincipalModel::MIN_PASSPHRASE_CHARS) ?></p>
        <?= $this->render('Vault:vault/passphrase_generator') ?>
        <p class="vault-status" data-vault-status role="status" hidden></p>
        <div class="form-actions"><button type="submit" class="btn btn-blue"><?= t('Change passphrase') ?></button></div>
    </form>
</section>

<section class="vault-card vault-section">
    <h3><?= t('Rotate my keys') ?></h3>
    <p><?= t('Keeps your passphrase and gives your vault a new key, so a backup taken afterwards is useless to anyone who learned your old key.') ?></p>
    <form class="vault-form" data-vault-form="rotate" method="post" action="<?= $this->url->href('SecurityController', 'rotate', ['plugin' => 'Vault']) ?>">
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
        <label for="vault-rotate-passphrase"><?= t('Your passphrase') ?></label>
        <input type="password" id="vault-rotate-passphrase" name="passphrase" required autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <p class="vault-status" data-vault-status role="status" hidden></p>
        <div class="form-actions"><button type="submit" class="btn btn-blue"><?= t('Rotate my keys') ?></button></div>
    </form>
</section>

<?php if ($codes_allowed): ?>
<section class="vault-card vault-section" id="vault-recovery" data-vault-recovery>
    <h3><?= t('Recovery code') ?></h3>
    <p class="alert alert-info" data-vault-recovery-offer hidden><?= t('Your old recovery code no longer works. Create a new one if you want one.') ?></p>
    <p><?= t('A recovery code resets your passphrase if you forget it, and it bypasses hardware keys. It is shown once. Creating one replaces any code you have.') ?></p>
    <?php // R54: the current passphrase is asked again; posts natively too (fix C1), never through a URL. ?>
    <?php // R54: with hardware keys, vault-webauthn.js adds a fresh assertion (data-vault-hw); that needs JavaScript. ?>
    <form class="vault-form" data-vault-form="recovery" method="post" action="<?= $this->url->href('SecurityController', 'recoveryCode', ['plugin' => 'Vault']) ?>" <?= empty($hw_keys) ? '' : 'data-vault-hw="1"' ?>>
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
        <label for="vault-recovery-passphrase"><?= t('Your passphrase') ?></label>
        <input type="password" id="vault-recovery-passphrase" name="passphrase" required autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <div class="form-actions"><button type="submit" class="btn btn-blue" data-vault-action="recovery-create"><?= t('Create a recovery code') ?></button></div>
    </form>
    <div class="vault-recovery-show" data-vault-recovery-show<?php if ($code === ''): ?> hidden<?php endif ?>>
        <p><?= t('Write this down and keep it offline. It won\'t be shown again.') ?></p>
        <p><code class="vault-recovery-code" data-vault-recovery-code><?= $this->text->e($code) ?></code></p>
        <label for="vault-recovery-group3"><?= t('To confirm, type group 3 of the code') ?></label>
        <input type="text" id="vault-recovery-group3" data-vault-recovery-confirm maxlength="4" autocomplete="off" spellcheck="false">
        <div class="form-actions"><button type="button" class="btn" data-vault-action="recovery-confirm"><?= t('I wrote it down') ?></button></div>
    </div>
    <p class="vault-status" data-vault-recovery-status role="status" hidden></p>
</section>
<?php endif ?>
<p class="vault-toast" data-vault-toast role="status" hidden></p>
