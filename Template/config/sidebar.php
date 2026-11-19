<li <?= $this->app->checkMenuSelection('SettingsController', 'index', 'Vault') ?>>
    <?= $this->url->link(t('Vault'), 'SettingsController', 'index', ['plugin' => 'Vault']) ?>
</li>
