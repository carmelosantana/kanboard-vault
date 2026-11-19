<?php
namespace Kanboard\Plugin\Vault;

use Kanboard\Core\Plugin\Base;
use Kanboard\Core\Security\AuthenticationManager;
use Kanboard\Core\Session\SessionManager;
use Kanboard\Plugin\Vault\Console\OrgKeygenCommand;
use Kanboard\Plugin\Vault\Console\OrgRecoverCommand;
use Kanboard\Plugin\Vault\Console\PurgeCommand;
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
