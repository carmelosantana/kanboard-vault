<?php
namespace Kanboard\Plugin\Vault;

use Kanboard\Core\Plugin\Base;
use Kanboard\Core\Security\AuthenticationManager;
use Kanboard\Core\Security\Role;
use Kanboard\Core\Session\SessionManager;
use Kanboard\Plugin\Vault\Api\VaultAgentProcedure;
use Kanboard\Plugin\Vault\Console\OrgKeygenCommand;
use Kanboard\Plugin\Vault\Console\OrgRecoverCommand;
use Kanboard\Plugin\Vault\Console\PurgeCommand;
use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\FileKeyProvider;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\HardwareKeys;
use Kanboard\Plugin\Vault\Model\Importer;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\Notifier;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\ServerKeyFile;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Model\ServerSecrets;
use Kanboard\Plugin\Vault\Model\ShareModel;
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
        $this->container['vaultRotation'] = static fn ($c): RotationService => new RotationService($c);
        $this->container['vaultRecovery'] = static fn ($c): RecoveryService => new RecoveryService($c);
        $this->container['vaultShares'] = static fn ($c): ShareModel => new ShareModel($c);
        $this->container['vaultHardwareKeys'] = static fn ($c): HardwareKeys => new HardwareKeys($c);
        $this->container['vaultImporter'] = static fn ($c): Importer => new Importer($c);
        // The Server principal (spec amendment): its key file (VAULT_SERVER_KEY_FILE, a path), the provider that opens
        // what is sealed to it, and on/off.
        $this->container['vaultServerKeyFile'] = static fn (): ServerKeyFile => new ServerKeyFile(ServerKeyFile::configuredPath());
        $this->container['vaultKeyProvider'] = static fn ($c): FileKeyProvider => new FileKeyProvider($c, $c['vaultServerKeyFile']);
        $this->container['vaultServerPrincipal'] = static fn ($c): ServerPrincipal => new ServerPrincipal($c, $c['vaultServerKeyFile'], $c['vaultKeyProvider']);
        // The consumer API, only while Server sharing is on. Before the first migration vault_principals may not exist
        // yet, so a database error here means "off".
        try {
            if (ServerPrincipal::of($this->container)->isOn()) {
                $this->container['vaultSecrets'] = static fn ($c): ServerSecrets => new ServerSecrets($c, $c['vaultKeyProvider']);
            }
        } catch (\PDOException) {
        }

        // The page and its POST endpoints (spec: UI). No template:layout:js or :css: Vault's own templates load
        // vault.js and vault.css, so nothing of Vault's runs on other pages.
        $this->route->addRoute('vault', 'VaultController', 'index', 'Vault');
        $this->route->addRoute('vault/unlock', 'VaultController', 'unlock', 'Vault');
        $this->route->addRoute('vault/lock', 'VaultController', 'lock', 'Vault');
        $this->route->addRoute('vault/enrol', 'VaultController', 'enrol', 'Vault');
        // The locked page's "Forgot passphrase?" flow (R52).
        $this->route->addRoute('vault/recover', 'VaultController', 'recover', 'Vault');
        // Hardware keys (WebAuthn PRF): the page, challenges, add, remove, rotate with every key, unlock with a key.
        $this->route->addRoute('vault/hwkeys', 'HardwareKeyController', 'index', 'Vault');
        foreach (['challenge', 'register', 'remove', 'rotate', 'unlock'] as $action) {
            $this->route->addRoute('vault/hwkeys/'.$action, 'HardwareKeyController', $action, 'Vault');
        }
        foreach (['tree', 'list', 'entry', 'field', 'save', 'move', 'delete'] as $action) {
            $this->route->addRoute('vault/'.$action, 'EntryController', $action, 'Vault');
        }
        foreach (['sharing', 'grant', 'revoke', 'activity'] as $action) {
            $this->route->addRoute('vault/'.$action, 'ShareGrantController', $action, 'Vault');
        }
        $this->route->addRoute('vault/grant-server', 'ShareGrantController', 'grantServer', 'Vault');
        // KeePassXC import (spec: KeePassXC import and export → Import): the page, then start and batch.
        $this->route->addRoute('vault/import', 'ImportController', 'index', 'Vault');
        $this->route->addRoute('vault/import/start', 'ImportController', 'start', 'Vault');
        $this->route->addRoute('vault/import/batch', 'ImportController', 'batch', 'Vault');
        $this->route->addRoute('vault/export/kdbx', 'ExportController', 'index', 'Vault');
        $this->route->addRoute('vault/export', 'ExportController', 'export', 'Vault');
        // "My vault security" (R40): passphrase change, Rotate my keys, a personal recovery code.
        $this->route->addRoute('vault/security', 'SecurityController', 'index', 'Vault');
        $this->route->addRoute('vault/passphrase', 'SecurityController', 'passphrase', 'Vault');
        $this->route->addRoute('vault/rotate', 'SecurityController', 'rotate', 'Vault');
        $this->route->addRoute('vault/recovery-code', 'SecurityController', 'recoveryCode', 'Vault');
        // The owner's agents (spec: Agents → Enrolment): enable vault access, re-enrol, the read cap.
        $this->route->addRoute('vault/agents', 'VaultAgentController', 'index', 'Vault');
        foreach (['enrol', 'reenrol', 'cap'] as $action) {
            $this->route->addRoute('vault/agents/'.$action, 'VaultAgentController', $action, 'Vault');
        }
        // One-time shares (spec: One-time shares). Only the page and Reveal are open to anyone with the link; they have
        // no route, so the link keeps the spec's ?controller=VaultShareController&action=show&plugin=Vault&id= form.
        // Creating, listing and revoking links need a login (the default APP_USER) and an unlocked vault.
        $this->applicationAccessMap->add('VaultShareController', ['show', 'reveal'], Role::APP_PUBLIC);
        foreach (['reserve', 'create', 'revoke', 'mine'] as $action) {
            $this->route->addRoute('vault/share/'.$action, 'VaultShareController', $action, 'Vault');
        }
        // Settings → Vault (admins only; SettingsController checks): the settings and the deployment checks.
        $this->route->addRoute('vault/settings', 'SettingsController', 'index', 'Vault');
        $this->route->addRoute('vault/settings/save', 'SettingsController', 'save', 'Vault');
        $this->route->addRoute('vault/settings/server', 'SettingsController', 'server', 'Vault');
        $this->route->addRoute('vault/orphans/claim', 'OrphanController', 'claim', 'Vault');
        $this->route->addRoute('vault/orphans/destroy', 'OrphanController', 'destroy', 'Vault');
        $this->hook->on('template:config:sidebar', ['template' => 'Vault:config/sidebar']);
        $this->hook->on('template:header:dropdown', ['template' => 'Vault:header/dropdown']);
        $this->hook->on('template:dashboard:sidebar', ['template' => 'Vault:dashboard/sidebar']);

        // The agent API (spec: Agents → Methods). withObject, as Agents does: core wins any name clash, and the API ACL
        // keys on the short class name, hence the Vault prefix. Registered even without Agents, so it can answer
        // agents_unavailable. Kanboard always has its JSON-RPC server; only a bare test container lacks one.
        if (isset($this->container['api'])) {
            $this->api->getProcedureHandler()->withObject(new VaultAgentProcedure($this->container));
        }

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
    public function getPluginDescription(): string { return t('Encrypted password store with per-user keys behind a separate vault passphrase, shared groups, agent access and one-time share links.'); }
    public function getPluginAuthor(): string      { return 'Carmelo Santana'; }
    public function getPluginVersion(): string     { return '1.0.0'; }
    public function getPluginHomepage(): string    { return 'https://github.com/carmelosantana/kanboard-vault'; }
    public function getCompatibleVersion(): string { return '>=1.2.47'; }
}
