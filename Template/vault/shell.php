<div class="page-header vault-header">
    <h2><?= t('Vault') ?></h2>
    <ul class="vault-toolbar">
        <li><button type="button" class="btn" data-vault-action="lock"><i class="fa fa-lock" aria-hidden="true"></i> <?= t('Lock') ?></button></li>
    </ul>
</div>
<?= $this->render('Vault:vault/app', ['state' => 'unlocked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<?php if ($failed_attempts >= \Kanboard\Plugin\Vault\Model\PrincipalModel::NOTIFY_AFTER): ?>
<p class="alert alert-error vault-banner"><?= t('There were %d failed attempts to unlock your vault before this unlock. If they weren\'t yours, change your vault passphrase.', $failed_attempts) ?></p>
<?php endif ?>
<?php foreach ($notices as $notice): ?>
    <?php if ($notice === 'org_enabled'): ?>
    <p class="alert alert-info vault-banner"><?= t('Your organisation\'s recovery key can now reset your vault passphrase.') ?></p>
    <?php elseif ($notice === 'recovery_code_reset'): ?>
    <p class="alert alert-info vault-banner" data-vault-offer="recovery-code"><?= t('Your old recovery code no longer works. Create a new one if you want one.') ?></p>
    <?php elseif ($notice === 'org_recovered'): ?>
    <p class="alert alert-error vault-banner"><?= t('Your vault passphrase was reset with your organisation\'s recovery key.') ?></p>
    <?php endif ?>
<?php endforeach ?>
<div class="vault-panes" data-vault-panes>
    <nav class="vault-tree" aria-label="<?= t('Groups') ?>"></nav>
    <section class="vault-list" aria-label="<?= t('Entries') ?>"></section>
    <section class="vault-detail" aria-label="<?= t('Entry') ?>"></section>
</div>
