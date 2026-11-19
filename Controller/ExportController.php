<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\VaultException;

// KeePassXC export (spec: KeePassXC import and export → Export). The browser builds the KDBX file (vault-export.js);
// the server only answers the decrypted entries, once the user has proved it is them again.
//
//   GET  vault/export/kdbx    the page, for an unlocked vault; it loads kdbxweb.js, vault-kdbx.js, vault-generator.js,
//                             vault-webauthn.js (with hardware keys) and vault-export.js, on this page only. Locked:
//                             the vault page.
//   POST vault/export         {passphrase[, assertion][, include_shared]} → {groups, entries, skipped}
//                             (ObjectStore::exportFor). A fresh re-authentication first (requireFreshReauth: the
//                             passphrase through the unlock throttle, and with hardware keys a fresh assertion), then
//                             one export audit row {actor_user_id, count}.
//
// The POST carries the CSRF token, needs HTTPS (or the opted-in dev localhost) and an unlocked session, runs in the
// hardened handler with the session's key (withKey: fetched before any vault lock, wiped after) and answers no-store.
// It answers vault.js only: a native form POST gets the usual redirect with a reason code, never a page of secrets.
class ExportController extends BaseVaultController
{
    public function index(): void
    {
        $this->handle(function (): void {
            $sk = $this->requireUnlocked();
            sodium_memzero($sk);
            $this->respond()->html($this->helper->layout->app('Vault:vault/export', [
                'title' => t('Export to KeePassXC'),
                'client' => $this->clientConfig(),
                'https_ok' => $this->vaultSession()->transportAllowed(),
                'hw_keys' => $this->hardwareKeys()->count($this->userId()),
            ]));
        });
    }

    public function export(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $this->requireTransport();
            if (! $this->request->isAjax()) {
                throw new VaultException('forbidden');
            }
            $this->requireFreshReauth($userId, $sk);
            $includeShared = in_array((string) $this->request->getRawValue('include_shared'), ['1', 'on', 'true'], true);
            $out = $this->store()->exportFor($userId, $sk, $includeShared);
            AuditModel::of($this->container)->record('export', ['actor_user_id' => $userId, 'count' => count($out['entries'])]);
            $this->answer($out);
            unset($out);
        });
    }
}
