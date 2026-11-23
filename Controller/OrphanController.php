<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\OrphanService;
use Kanboard\Plugin\Vault\Model\VaultException;

// The admin's two answers to an orphan (spec amendment: security requirement 14 with Codex NEW-02), listed on
// Settings → Vault. Both are POST with the CSRF token, app-admin only (forbidden otherwise), from an unlocked vault.
//
//   POST vault/orphans/claim    {entry_id, group_id}              → {ok, key_epoch}: OrphanService::claim with the
//                               admin's key from the unlocked session (withKey), never from the request.
//   POST vault/orphans/destroy  {entry_id, passphrase}            → {ok}: step-up first (the vault passphrase through
//                               the passphrase change's throttled check, RotationService::confirmPassphrase, as for
//                               turning Server on, also for a user with hardware keys), then OrphanService::destroy.
//
// OrphanService's refusals (not_found, not_allowed) come back through handle()'s generic mapping. Every refusal is
// audited (requirement 18): OrphanService's own, and here a non-admin, a locked vault or a failed step-up. A native form POST
// returns to Settings → Vault with only a fixed code (succeed()/fail()).
class OrphanController extends BaseVaultController
{
    public function claim(): void
    {
        $this->adminWithKey('orphan_claim_denied', function (int $userId, #[\SensitiveParameter] string $sk): void {
            $epoch = $this->orphans()->claim($userId, $this->intParam('entry_id') ?? 0, $this->intParam('group_id') ?? 0, $sk);
            $this->succeed(['key_epoch' => $epoch], 'orphan_claimed');
        });
    }

    public function destroy(): void
    {
        $this->adminWithKey('orphan_destroy_denied', function (int $userId, #[\SensitiveParameter] string $sk): void {
            $this->requireTransport();
            try {
                // Final-wave step-up ruling: the vault passphrase again, as for turning Server on (no hardware-key
                // assertion in P1; WebAuthn step-up for both is P2).
                $this->rotationService()->confirmPassphrase($userId, $sk, (string) $this->request->getRawValue('passphrase'), $this->clientIp());
            } catch (VaultException $e) {
                $this->orphans()->recordDenied('orphan_destroy_denied', $userId, $this->intParam('entry_id') ?? 0, $e);
                throw $e;
            }
            $this->orphans()->destroy($userId, $this->intParam('entry_id') ?? 0);
            $this->succeed([], 'orphan_destroyed');
        });
    }

    // POST + CSRF, then the admin check, then the unlocked session's key, wiped whatever happens. Requirement 18: a
    // non-admin (not_allowed) and a locked vault (locked) are recorded as $denied before the refusal; CSRF comes first
    // so a forged request writes nothing.
    private function adminWithKey(string $denied, callable $action): void
    {
        $this->handle(function () use ($denied, $action): void {
            $this->requirePostCsrf();
            $entryId = $this->intParam('entry_id') ?? 0;
            if (! $this->userSession->isAdmin()) {
                $this->orphans()->recordDenied($denied, $this->userId(), $entryId, 'not_allowed');
            }
            $this->requireAdmin();
            try {
                $sk = $this->requireUnlocked();
            } catch (ResponseSent $e) {
                $this->orphans()->recordDenied($denied, $this->userId(), $entryId, 'locked');
                throw $e;
            } catch (VaultException $e) {
                $this->orphans()->recordDenied($denied, $this->userId(), $entryId, $e);
                throw $e;
            }
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
