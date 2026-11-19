<div class="page-header"><h2><?= t('Set up your vault') ?></h2></div>
<?= $this->render('Vault:vault/app', ['state' => 'enrol', 'client' => $client, 'https_ok' => $https_ok]) ?>
<section class="vault-card">
    <p><?= t('Your vault has its own passphrase, separate from your Kanboard password. Only you can unlock it: a Kanboard login, a password reset or an administrator can\'t.') ?></p>
    <?php if ($policy === 'none'): ?>
    <p class="alert alert-info vault-policy"><?= t('There is no recovery. If you forget this passphrase, nobody can open your vault, and its contents are lost.') ?></p>
    <?php elseif ($policy === 'code'): ?>
    <p class="alert alert-info vault-policy"><?= t('You can create a personal recovery code after setup. Without one, a forgotten passphrase means a lost vault.') ?></p>
    <?php else: ?>
    <p class="alert alert-info vault-policy"><?= t('You can create a personal recovery code after setup, and your organisation holds a recovery key that can reset your passphrase.') ?></p>
    <?php endif ?>
    <?php if ($https_ok): ?>
    <?php // POST to its own endpoint even without vault.js, so the passphrase never goes into a URL (fix C1). ?>
    <form class="vault-form" data-vault-form="enrol" method="post" action="<?= $this->url->href('VaultController', 'enrol', ['plugin' => 'Vault']) ?>">
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
        <label for="vault-passphrase"><?= t('Vault passphrase') ?></label>
        <input type="password" id="vault-passphrase" name="passphrase" required minlength="<?= \Kanboard\Plugin\Vault\Model\PrincipalModel::MIN_PASSPHRASE_CHARS ?>" autocomplete="new-password">
        <label for="vault-confirm"><?= t('Type it again') ?></label>
        <input type="password" id="vault-confirm" name="confirm" required autocomplete="new-password">
        <p class="form-help"><?= t('At least %d characters. A few unrelated words work well.', \Kanboard\Plugin\Vault\Model\PrincipalModel::MIN_PASSPHRASE_CHARS) ?></p>
        <?php if ($error !== ''): ?>
        <p class="vault-error" role="alert"><?= $this->text->e($error) ?></p>
        <?php else: ?>
        <p class="vault-error" role="alert" hidden></p>
        <?php endif ?>
        <div class="form-actions"><button type="submit" class="btn btn-blue"><?= t('Create my vault') ?></button></div>
    </form>
    <?php endif ?>
</section>
