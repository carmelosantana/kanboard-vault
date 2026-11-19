<div class="page-header vault-header">
    <h2><?= t('Vault') ?></h2>
    <ul class="vault-toolbar">
        <li><input type="search" class="vault-search" data-vault-search placeholder="<?= t('Search…') ?>" aria-label="<?= t('Search') ?>"></li>
        <li><button type="button" class="btn" data-vault-action="new-entry"><i class="fa fa-plus" aria-hidden="true"></i> <?= t('Entry') ?></button></li>
        <li><button type="button" class="btn" data-vault-action="new-group"><i class="fa fa-folder" aria-hidden="true"></i> <?= t('Group') ?></button></li>
        <li><a class="btn" href="<?= $this->url->href('SecurityController', 'index', ['plugin' => 'Vault']) ?>" data-vault-link="security"><i class="fa fa-shield" aria-hidden="true"></i> <?= t('Security') ?></a></li>
        <li><a class="btn" href="<?= $this->url->href('HardwareKeyController', 'index', ['plugin' => 'Vault']) ?>" data-vault-link="hwkeys"><i class="fa fa-key" aria-hidden="true"></i> <?= t('Keys') ?></a></li>
        <?php if (! empty($agents_available)): ?>
        <li><a class="btn" href="<?= $this->url->href('VaultAgentController', 'index', ['plugin' => 'Vault']) ?>" data-vault-link="agents"><i class="fa fa-android" aria-hidden="true"></i> <?= t('Agents') ?></a></li>
        <?php endif ?>
        <li><button type="button" class="btn" data-vault-action="lock"><i class="fa fa-lock" aria-hidden="true"></i> <?= t('Lock') ?></button></li>
    </ul>
</div>
<?= $this->render('Vault:vault/app', ['state' => 'unlocked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-browser.js') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-generator.js') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-share.js') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-onetime.js') ?>
<?php if ($failed_attempts >= \Kanboard\Plugin\Vault\Model\PrincipalModel::NOTIFY_AFTER): ?>
<p class="alert alert-error vault-banner"><?= t('There were %d failed attempts to unlock your vault before this unlock. If they weren\'t yours, change your vault passphrase.', $failed_attempts) ?></p>
<?php endif ?>
<?php if (! empty($hw_rotate)): ?>
<p class="alert alert-info vault-banner" data-vault-offer="hw-rotate"><?= t('Your vault needs new keys, and your hardware keys must take part.') ?> <?= $this->url->link(t('Rotate with my keys'), 'HardwareKeyController', 'index', ['plugin' => 'Vault']) ?></p>
<?php endif ?>
<?php foreach ($notices as $notice): ?>
    <?php if ($notice === 'org_enabled'): ?>
    <p class="alert alert-info vault-banner"><?= t('Your organisation\'s recovery key can now reset your vault passphrase.') ?></p>
    <?php elseif ($notice === 'recovery_code_reset'): ?>
    <p class="alert alert-info vault-banner" data-vault-offer="recovery-code"><?= t('Your old recovery code no longer works. Create a new one if you want one.') ?> <?= $this->url->link(t('Create a new recovery code'), 'SecurityController', 'index', ['plugin' => 'Vault'], false, '', '', false, 'vault-recovery') ?></p>
    <?php elseif ($notice === 'org_recovered'): ?>
    <p class="alert alert-error vault-banner"><?= t('Your vault passphrase was reset with your organisation\'s recovery key.') ?></p>
    <?php endif ?>
<?php endforeach ?>
<div class="vault-panes" data-vault-panes>
    <?= $this->render('Vault:vault/tree') ?>
    <?= $this->render('Vault:vault/list') ?>
    <section class="vault-detail" aria-label="<?= t('Entry') ?>">
        <?= $this->render('Vault:vault/detail') ?>
        <?= $this->render('Vault:vault/edit', ['client' => $client]) ?>
    </section>
</div>
<?= $this->render('Vault:vault/share_dialog', ['client' => $client]) ?>
<?= $this->render('Vault:vault/onetime_dialog', ['share_expiries' => $share_expiries ?? ['1h', '1d', '7d']]) ?>
<?= $this->render('Vault:vault/activity') ?>
<p class="vault-toast" data-vault-toast role="status" hidden></p>
