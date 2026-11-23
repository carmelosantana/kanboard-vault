<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\OrphanService;

// The admin's two answers to an orphan (spec amendment: security requirement 14 with Codex NEW-02), listed on
// Settings → Vault. Both are app-admin only (forbidden otherwise), POST with the CSRF token, from an unlocked vault.
//
//   POST vault/orphans/claim    {entry_id, group_id}              → {ok, key_epoch}: OrphanService::claim with the
//                               admin's key from the unlocked session (withKey), never from the request.
//   POST vault/orphans/destroy  {entry_id, passphrase[, assertion]} → {ok}: step-up first (requireFreshReauth: the
//                               vault passphrase through the throttled check, plus a fresh assertion for a user with
//                               hardware keys), then OrphanService::destroy.
//
// OrphanService's refusals (not_found, not_allowed) come back through handle()'s generic mapping. A native form POST
// returns to Settings → Vault with only a fixed code (succeed()/fail()).
class OrphanController extends BaseVaultController
{
    public function claim(): void
    {
        $this->adminWithKey(function (int $userId, string $sk): void {
            $epoch = $this->orphans()->claim($userId, $this->intParam('entry_id') ?? 0, $this->intParam('group_id') ?? 0, $sk);
            $this->succeed(['key_epoch' => $epoch], 'orphan_claimed');
        });
    }

    public function destroy(): void
    {
        $this->adminWithKey(function (int $userId, string $sk): void {
            $this->requireTransport();
            $this->requireFreshReauth($userId, $sk);
            $this->orphans()->destroy($userId, $this->intParam('entry_id') ?? 0);
            $this->succeed([], 'orphan_destroyed');
        });
    }

    // withKey with the admin check first, so a non-admin is refused before anything else is looked at.
    private function adminWithKey(callable $action): void
    {
        $this->handle(function () use ($action): void {
            $this->requireAdmin();
            $this->requirePostCsrf();
            $sk = $this->requireUnlocked();
            try {
                $action($this->userId(), $sk);
            } finally {
                sodium_memzero($sk);
            }
        });
    }

    private function orphans(): OrphanService
    {
        return isset($this->container['vaultOrphans']) ? $this->container['vaultOrphans'] : new OrphanService($this->container);
    }

    protected function returnRoute(): array
    {
        return ['SettingsController', 'index'];
    }
}
