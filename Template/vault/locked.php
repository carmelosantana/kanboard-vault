<?php
// The locked vault: the passphrase unlock form (posts natively too, fix C1), plus the hardware-key unlock when the user
// has keys (vault-webauthn.js; it uses the same passphrase field), and, when the policy allows recovery codes, the
// "Forgot passphrase?" flow (R52): ?recover=1 shows a form that posts {code, passphrase, confirm} to vault/recover,
// natively too, so no secret ever reaches a URL. No inline JS.
?>
<div class="page-header"><h2><?= t('Vault') ?></h2></div>
<?= $this->render('Vault:vault/app', ['state' => 'locked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<?php if (! empty($hw_keys)): ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-webauthn.js') ?>
<?php endif ?>
<?php if (! empty($notice)): ?>
<p class="alert alert-success vault-banner" role="status"><?= $this->text->e($notice) ?></p>
<?php endif ?>
<section class="vault-card">
    <?php if ($https_ok && ! empty($recover)): ?>
    <form class="vault-form" data-vault-form="recover" method="post" action="<?= $this->url->href('VaultController', 'recover', ['plugin' => 'Vault']) ?>"
          data-vault-done="<?= $this->url->href('VaultController', 'index', ['plugin' => 'Vault', 'vault_notice' => 'recovered']) ?>"
          data-vault-done-pending="<?= $this->url->href('VaultController', 'index', ['plugin' => 'Vault', 'vault_notice' => 'recovered_pending']) ?>">
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
        <p><?= t('Your recovery code resets your passphrase. It also removes your hardware keys, and the code can\'t be used again.') ?></p>
        <label for="vault-recovery-code"><?= t('Recovery code') ?></label>
        <input type="text" id="vault-recovery-code" name="code" required autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore spellcheck="false">
        <label for="vault-new-passphrase"><?= t('New passphrase') ?></label>
        <input type="password" id="vault-new-passphrase" name="passphrase" required minlength="<?= \Kanboard\Plugin\Vault\Model\PrincipalModel::MIN_PASSPHRASE_CHARS ?>" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <label for="vault-new-confirm"><?= t('Type it again') ?></label>
        <input type="password" id="vault-new-confirm" name="confirm" required autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <?php if ($error !== ''): ?>
        <p class="vault-error" role="alert"><?= $this->text->e($error) ?></p>
        <?php else: ?>
        <p class="vault-error" role="alert" hidden></p>
        <?php endif ?>
        <div class="form-actions">
            <button type="submit" class="btn btn-blue"><?= t('Reset passphrase') ?></button>
            <?= $this->url->link(t('Back to unlock'), 'VaultController', 'index', ['plugin' => 'Vault']) ?>
        </div>
    </form>
    <?php elseif ($https_ok): ?>
    <?php // POST to its own endpoint even without vault.js, so the passphrase never goes into a URL (fix C1). ?>
    <form class="vault-form" data-vault-form="unlock" method="post" action="<?= $this->url->href('VaultController', 'unlock', ['plugin' => 'Vault']) ?>">
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
        <label for="vault-passphrase"><?= t('Vault passphrase') ?></label>
        <input type="password" id="vault-passphrase" name="passphrase" required autofocus autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <?php if ($error !== ''): ?>
        <p class="vault-error" role="alert"><?= $this->text->e($error) ?></p>
        <?php else: ?>
        <p class="vault-error" role="alert" hidden></p>
        <?php endif ?>
        <div class="form-actions">
            <?php if (! empty($hw_keys)): ?>
            <button type="button" class="btn btn-blue" data-vault-action="hw-unlock"><i class="fa fa-key" aria-hidden="true"></i> <?= t('Unlock with hardware key') ?></button>
            <?php endif ?>
            <?php if (empty($hw_keys) || $hw_keys < 2): ?>
            <button type="submit" class="btn<?= empty($hw_keys) ? ' btn-blue' : '' ?>"><?= t('Unlock') ?></button>
            <?php endif ?>
        </div>
        <?php if (! empty($codes_allowed)): ?>
        <p class="vault-forgot"><a href="<?= $this->url->href('VaultController', 'index', ['plugin' => 'Vault', 'recover' => '1']) ?>" data-vault-link="recover"><?= t('Forgot passphrase?') ?></a></p>
        <?php endif ?>
    </form>
    <?php endif ?>
</section>
