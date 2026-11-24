<li <?= $this->app->checkMenuSelection('VaultSettingsController', 'index', 'Vault') ?>>
    <?= $this->url->link(t('Vault'), 'VaultSettingsController', 'index', ['plugin' => 'Vault']) ?>
</li>
