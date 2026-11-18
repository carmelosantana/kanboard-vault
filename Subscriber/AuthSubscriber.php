<?php
namespace Kanboard\Plugin\Vault\Subscriber;

use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Model\VaultSession;

// Locks the vault on Kanboard's login and logout events (spec: Unlocked sessions, Locking).
class AuthSubscriber extends Base
{
    // auth.success: Kanboard keeps the old PHP session when it regenerates the id at login
    // (session_regenerate_id(false)), so every vault session of the user goes, not just this one.
    // The API middleware fires it on every JSON-RPC call too; API requests never touch vault_sessions.
    public function onAuthSuccess(): void
    {
        $session = $this->vaultSession();
        $userId = (int) $this->userSession->getId();
        if ($userId > 0 && ! $session->isApiRequest()) {
            $session->lock($userId);
        }
    }

    // session.destroy (logout) fires before the PHP session is destroyed: lock this session's row.
    public function onSessionDestroy(): void
    {
        $session = $this->vaultSession();
        $userId = (int) $this->userSession->getId();
        $sidHash = $session->sidHash();
        if ($userId > 0 && $sidHash !== null) {
            $session->lock($userId, $sidHash);
        }
    }

    private function vaultSession(): VaultSession
    {
        return isset($this->container['vaultSession']) ? $this->container['vaultSession'] : new VaultSession($this->container);
    }
}
