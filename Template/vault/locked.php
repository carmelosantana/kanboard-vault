<div class="page-header"><h2><?= t('Vault') ?></h2></div>
<?= $this->render('Vault:vault/app', ['state' => 'locked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<section class="vault-card">
    <?php if ($https_ok): ?>
    <?php // POST to its own endpoint even without vault.js, so the passphrase never goes into a URL (fix C1). ?>
    <form class="vault-form" data-vault-form="unlock" method="post" action="<?= $this->url->href('VaultController', 'unlock', ['plugin' => 'Vault']) ?>">
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
        <label for="vault-passphrase"><?= t('Vault passphrase') ?></label>
        <input type="password" id="vault-passphrase" name="passphrase" required autofocus autocomplete="current-password">
        <?php if ($error !== ''): ?>
        <p class="vault-error" role="alert"><?= $this->text->e($error) ?></p>
        <?php else: ?>
        <p class="vault-error" role="alert" hidden></p>
        <?php endif ?>
        <div class="form-actions"><button type="submit" class="btn btn-blue"><?= t('Unlock') ?></button></div>
    </form>
    <?php endif ?>
</section>
