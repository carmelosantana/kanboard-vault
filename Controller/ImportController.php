<?php
namespace Kanboard\Plugin\Vault\Controller;

use JsonException;
use Kanboard\Plugin\Vault\Model\Importer;
use Kanboard\Plugin\Vault\Model\VaultException;

// KeePassXC import (spec: KeePassXC import and export → Import). The browser opens the database (vault-import.js);
// the server only ever gets Vault entry payloads, never the file, its name or its master password.
//
//   GET  vault/import         the page, for an unlocked vault; it loads kdbxweb.js, vault-kdbx.js,
//                             vault-kdbx-header.js and vault-import.js, on this page only. Locked: the vault page.
//   POST vault/import/start   {total}: a new owner-only group "Imported <Y-m-d>" → {import_id}. total (1 to
//                             Importer::MAX_ENTRIES) is the ceiling this import may reach.
//   POST vault/import/batch   {import_id, group_path (JSON list of names), entries (JSON list of payloads, at most
//                             Importer::MAX_BATCH)} → {created}. Only this session's current import, and never past
//                             its total; then Housekeeping::afterWrite.
//
// Both POSTs carry the CSRF token, run in the hardened handler with the unlocked session's key (withKey: fetched
// before any vault lock, wiped after) and fail with VaultFailure's fixed reasons; over a limit is import_limit. The
// import's state in the PHP session is {user, root, total, sent}: ids and counts only, no name.
class ImportController extends BaseVaultController
{
    private const SESSION = 'vaultImport';

    public function index(): void
    {
        $this->handle(function (): void {
            $sk = $this->requireUnlocked();
            sodium_memzero($sk);
            $this->respond()->html($this->helper->layout->app('Vault:vault/import', [
                'title' => t('Import from KeePassXC'),
                'client' => $this->clientConfig(),
                'https_ok' => $this->vaultSession()->transportAllowed(),
            ]));
        });
    }

    public function start(): void
    {
        $this->withKey(function (int $userId): void {
            $total = $this->intParam('total');
            if ($total === null || $total < 1 || $total > Importer::MAX_ENTRIES) {
                throw new VaultException('import_limit');
            }
            $root = $this->importer()->start($userId);
            session_set(self::SESSION, ['user' => $userId, 'root' => $root, 'total' => $total, 'sent' => 0]);
            $this->answer(['import_id' => $root]);
        });
    }

    public function batch(): void
    {
        $this->withKey(function (int $userId, #[\SensitiveParameter] string $sk): void {
            $state = session_get(self::SESSION);
            $root = $this->intParam('import_id');
            if (! is_array($state) || ($state['user'] ?? null) !== $userId || ($state['root'] ?? null) !== $root || $root === null) {
                throw new VaultException('not_found');
            }
            $path = $this->jsonList('group_path');
            $entries = $this->jsonList('entries');
            if (count($entries) > Importer::MAX_BATCH || $state['sent'] + count($entries) > $state['total']) {
                throw new VaultException('import_limit');
            }
            $created = $this->importer()->batch($userId, $root, $path, $entries, $sk);
            unset($entries);
            $state['sent'] += $created;
            session_set(self::SESSION, $state);
            $this->housekeeping()->afterWrite($userId, $sk);
            $this->answer(['created' => $created]);
        });
    }

    // A JSON list parameter; anything else is payload_invalid.
    private function jsonList(string $name): array
    {
        $raw = $this->request->getRawValue($name);
        try {
            $v = is_string($raw) ? json_decode($raw, true, 8, JSON_THROW_ON_ERROR) : null;
        } catch (JsonException) {
            throw new VaultException('payload_invalid');
        }
        if (! is_array($v) || ! array_is_list($v)) {
            throw new VaultException('payload_invalid');
        }
        return $v;
    }

    private function importer(): Importer
    {
        return isset($this->container['vaultImporter']) ? $this->container['vaultImporter'] : new Importer($this->container);
    }
}
