<?php
// KeePassXC export (spec: KeePassXC import and export → Export). vault-export.js re-proves the vault passphrase (and,
// with hardware keys, a fresh assertion through vault-webauthn.js) to vault/export, a POST with the CSRF token through
// KBVault.api, then builds the KDBX 4.0 file in the browser with the export password chosen here and downloads it: the
// file never goes through the server. The inputs have no name and the form no action, so without JavaScript nothing is
// submitted. The export scripts load on this page only, kdbxweb first. No inline JS.
?>
<div class="page-header vault-header">
    <h2><?= t('Export to KeePassXC') ?></h2>
    <ul class="vault-toolbar">
        <li><a class="btn" href="<?= $this->url->href('VaultController', 'index', ['plugin' => 'Vault']) ?>"><i class="fa fa-arrow-left" aria-hidden="true"></i> <?= t('Back to the vault') ?></a></li>
        <li><button type="button" class="btn" data-vault-action="lock"><i class="fa fa-lock" aria-hidden="true"></i> <?= t('Lock') ?></button></li>
    </ul>
</div>
<?= $this->render('Vault:vault/app', ['state' => 'unlocked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<?= $this->asset->js('plugins/Vault/Assets/vendor/kdbxweb/kdbxweb.js') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-kdbx.js') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-generator.js') ?>
<?php if (! empty($hw_keys)): ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-webauthn.js') ?>
<?php endif ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-export.js') ?>
<noscript><p class="alert alert-error"><?= t('Exporting needs JavaScript: the KeePass file is built in your browser.') ?></p></noscript>

<section class="vault-card vault-section" data-vault-export>
    <h3><?= t('KeePass database') ?></h3>
    <p><?= t('Your entries are decrypted for this page only, then written into a KeePass database (KDBX 4) protected by the export password you choose here. KeePassXC and other KeePass apps open it. The file is built in your browser and never goes through the server.') ?></p>
    <form class="vault-form" data-vault-export-form autocomplete="off" <?= empty($hw_keys) ? '' : 'data-vault-hw="1"' ?>>
        <label for="vault-export-passphrase"><?= t('Your vault passphrase') ?></label>
        <input type="password" id="vault-export-passphrase" autocomplete="current-password" required data-vault-export-passphrase>
        <label><input type="checkbox" data-vault-export-shared> <?= t('Also export the entries other people shared with me') ?></label>
        <label for="vault-new-passphrase"><?= t('Export password') ?></label>
        <input type="password" id="vault-new-passphrase" autocomplete="new-password" data-vault-export-password>
        <label for="vault-new-confirm"><?= t('Type it again') ?></label>
        <input type="password" id="vault-new-confirm" autocomplete="new-password" data-vault-export-confirm>
        <?= $this->render('Vault:vault/passphrase_generator') ?>
        <p class="form-help"><?= t('Anyone with the file and this password can read every exported entry. Keep the file somewhere safe, and delete it when you no longer need it.') ?></p>
        <progress data-vault-export-progress hidden></progress>
        <p class="vault-status" data-vault-export-status role="status" hidden></p>
        <div class="form-actions">
            <button type="submit" class="btn btn-blue" data-vault-export-submit><?= t('Export') ?></button>
            <button type="button" class="btn" data-vault-export-cancel hidden><?= t('Cancel') ?></button>
        </div>
    </form>
    <dl class="vault-import-report" data-vault-export-report hidden>
        <dt><?= t('Entries exported') ?></dt><dd data-field="entries"></dd>
    </dl>
</section>
