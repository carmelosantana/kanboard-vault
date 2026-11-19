<li <?= $this->app->checkMenuSelection('VaultController', 'index', 'Vault') ?>>
    <?= $this->url->link(t('Vault'), 'VaultController', 'index', ['plugin' => 'Vault']) ?>
</li>
