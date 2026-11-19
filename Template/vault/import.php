<?php
// KeePassXC import (spec: KeePassXC import and export → Import). The file is opened in the browser by
// vault-import.js; only Vault entry payloads reach the server (vault/import/start and vault/import/batch, POST with
// the CSRF token, through KBVault.api). The inputs have no name and the form no action, so without JavaScript nothing
// is submitted: no password or file name can reach a URL. The import scripts load on this page only, kdbxweb first.
// No inline JS.
?>
<div class="page-header vault-header">
    <h2><?= t('Import from KeePassXC') ?></h2>
    <ul class="vault-toolbar">
        <li><a class="btn" href="<?= $this->url->href('VaultController', 'index', ['plugin' => 'Vault']) ?>"><i class="fa fa-arrow-left" aria-hidden="true"></i> <?= t('Back to the vault') ?></a></li>
        <li><button type="button" class="btn" data-vault-action="lock"><i class="fa fa-lock" aria-hidden="true"></i> <?= t('Lock') ?></button></li>
    </ul>
</div>
<?= $this->render('Vault:vault/app', ['state' => 'unlocked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<?= $this->asset->js('plugins/Vault/Assets/vendor/kdbxweb/kdbxweb.js') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-kdbx.js') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-kdbx-header.js') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-import.js') ?>
<noscript><p class="alert alert-error"><?= t('Importing needs JavaScript: the database is opened in your browser.') ?></p></noscript>

<section class="vault-card vault-section" data-vault-import>
    <h3><?= t('KeePass database') ?></h3>
    <p><?= t('The database is opened in your browser. Its entries go into a new group, "Imported" and today\'s date, that only you can see. The file and its name are never sent.') ?></p>
    <form class="vault-form" data-vault-import-form autocomplete="off">
        <label for="vault-import-file"><?= t('Database file (.kdbx)') ?></label>
        <input type="file" id="vault-import-file" accept=".kdbx" required data-vault-import-file>
        <label for="vault-import-password"><?= t('Master password') ?></label>
        <input type="password" id="vault-import-password" autocomplete="off" data-vault-import-password>
        <label for="vault-import-keyfile"><?= t('Key file (optional)') ?></label>
        <input type="file" id="vault-import-keyfile" data-vault-import-keyfile>
        <p class="form-help"><?= t('Databases that use Argon2 take 10–20 seconds to open. Attachments are not imported; history, icons and auto-type are dropped.') ?></p>
        <progress data-vault-import-progress hidden></progress>
        <p class="vault-status" data-vault-import-status role="status" hidden></p>
        <div class="form-actions">
            <button type="submit" class="btn btn-blue" data-vault-import-submit><?= t('Import') ?></button>
            <button type="button" class="btn" data-vault-import-cancel hidden><?= t('Cancel') ?></button>
        </div>
    </form>
    <dl class="vault-import-report" data-vault-import-report hidden>
        <dt><?= t('Entries imported') ?></dt><dd data-field="created"></dd>
        <dt><?= t('Groups') ?></dt><dd data-field="groups"></dd>
        <dt><?= t('Attachments skipped') ?></dt><dd data-field="skipped_attachments"></dd>
    </dl>
</section>
