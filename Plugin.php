<?php
namespace Kanboard\Plugin\Vault;

use Kanboard\Core\Plugin\Base;
use Kanboard\Core\Security\AuthenticationManager;
use Kanboard\Core\Session\SessionManager;
use Kanboard\Plugin\Vault\Console\OrgKeygenCommand;
use Kanboard\Plugin\Vault\Console\OrgRecoverCommand;
use Kanboard\Plugin\Vault\Console\PurgeCommand;
use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\Notifier;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultSession;
use Kanboard\Plugin\Vault\Subscriber\AuthSubscriber;

class Plugin extends Base
{
    public function initialize(): void
    {
        // Without libsodium there is no safe crypto: register only the admin notice, no routes.
        if (! $this->isSupported()) {
            $this->hook->on('template:layout:top', ['template' => 'Vault:layout/sodium_notice']);
            return;
        }

        // The audit log and the email notices every service uses (AuditModel::of, Notifier::of).
        $this->container['vaultAudit'] = static fn ($c): AuditModel => new AuditModel($c);
        $this->container['vaultNotifier'] = static fn ($c): Notifier => new Notifier($c);
        // The services the controllers use (tests swap in a fast Argon2 stand-in).
        $this->container['vaultSession'] = static fn ($c): VaultSession => new VaultSession($c);
        $this->container['vaultUnlock'] = static fn ($c): UnlockService => new UnlockService($c);
        $this->container['vaultPrincipals'] = static fn ($c): PrincipalModel => new PrincipalModel($c);
        $this->container['vaultHousekeeping'] = static fn ($c): Housekeeping => new Housekeeping($c);
        $this->container['vaultStore'] = static fn ($c): ObjectStore => new ObjectStore($c);
        $this->container['vaultGrants'] = static fn ($c): GrantModel => new GrantModel($c);

        // The page and its POST endpoints (spec: UI). No template:layout:js or :css: Vault's own templates load
        // vault.js and vault.css, so nothing of Vault's runs on other pages.
        $this->route->addRoute('vault', 'VaultController', 'index', 'Vault');
        $this->route->addRoute('vault/unlock', 'VaultController', 'unlock', 'Vault');
        $this->route->addRoute('vault/lock', 'VaultController', 'lock', 'Vault');
        $this->route->addRoute('vault/enrol', 'VaultController', 'enrol', 'Vault');
        foreach (['tree', 'list', 'entry', 'field', 'save', 'move', 'delete'] as $action) {
            $this->route->addRoute('vault/'.$action, 'EntryController', $action, 'Vault');
        }
        $this->hook->on('template:header:dropdown', ['template' => 'Vault:header/dropdown']);
        $this->hook->on('template:dashboard:sidebar', ['template' => 'Vault:dashboard/sidebar']);

        $subscriber = new AuthSubscriber($this->container);
        $this->container['dispatcher']->addListener(AuthenticationManager::EVENT_SUCCESS, [$subscriber, 'onAuthSuccess']);
        $this->container['dispatcher']->addListener(SessionManager::EVENT_DESTROY, [$subscriber, 'onSessionDestroy']);

        $this->cli->add(new OrgKeygenCommand($this->container));
        $this->cli->add(new OrgRecoverCommand($this->container));
        $this->cli->add(new PurgeCommand($this->container));
    }

    public function isSupported(): bool
    {
        return function_exists('sodium_crypto_pwhash');
    }

    public function getPluginName(): string        { return 'Vault'; }
    public function getPluginDescription(): string { return t('End-to-end encrypted password store with shared groups, agent access and one-time share links.'); }
    public function getPluginAuthor(): string      { return 'Carmelo Santana'; }
    public function getPluginVersion(): string     { return '1.0.0'; }
    public function getPluginHomepage(): string    { return 'https://github.com/carmelosantana/kanboard-vault'; }
    public function getCompatibleVersion(): string { return '>=1.2.47'; }
}
