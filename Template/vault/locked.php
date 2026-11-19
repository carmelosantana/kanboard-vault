<div class="page-header"><h2><?= t('Vault') ?></h2></div>
<?= $this->render('Vault:vault/app', ['state' => 'locked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<section class="vault-card">
    <?php if ($https_ok): ?>
    <form class="vault-form" data-vault-form="unlock" autocomplete="off">
        <label for="vault-passphrase"><?= t('Vault passphrase') ?></label>
        <input type="password" id="vault-passphrase" name="passphrase" required autofocus autocomplete="current-password">
        <p class="vault-error" role="alert" hidden></p>
        <div class="form-actions"><button type="submit" class="btn btn-blue"><?= t('Unlock') ?></button></div>
    </form>
    <?php endif ?>
</section>
