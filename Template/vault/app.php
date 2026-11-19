<?php
// The page-scoped assets and the data vault.js reads (no inline script: Kanboard's CSP forbids it). Every Vault
// state template starts with this; nothing of Vault's loads on any other page.
?>
<?= $this->asset->css('plugins/Vault/Assets/css/vault.css') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault.js') ?>
<div id="vault-app" class="vault" data-vault-state="<?= $this->text->e($state) ?>"
     data-csrf="<?= $this->text->e($client['csrf']) ?>"
     data-endpoints="<?= $this->text->e(json_encode($client['endpoints'])) ?>"
     data-messages="<?= $this->text->e(json_encode($client['messages'])) ?>"
     data-idle-ms="<?= (int) $client['idle_ms'] ?>"></div>
<?php if (! $https_ok): ?>
<p class="alert alert-error vault-https"><?= t('Vault needs HTTPS. Open Kanboard over https:// to set up or unlock your vault.') ?></p>
<?php endif ?>
