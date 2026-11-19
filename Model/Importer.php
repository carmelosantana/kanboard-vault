<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;

// The server half of the KeePassXC import (spec: KeePassXC import and export → Import, steps 4–5). The browser opens
// the file and sends Vault entry payloads; this writes them through ObjectStore, the one write path (its permission
// gate, payload validation and 256 KB limit, sealing to the effective recipients, the create audit rows), under the
// exclusive vault lock (R13).
//
//   start(userId)    a new top-level group "Imported <Y-m-d>", owned by the importer and shared with no one (so
//                    sealed to the importer only). The file name is never asked for, so it can't be stored.
//   batch(userId, root, groupPath, entries, sk)   at most MAX_BATCH entries into the group at groupPath below root
//                    (a list of names, at most MAX_DEPTH; missing groups are created, existing ones of the
//                    importer's reused). All or nothing: one exclusive transaction for the groups, the entries and
//                    one `import` audit row (actor_user_id, count). The target group goes through
//                    ObjectStore::beforeWrite first (expiry reconciliation, write barrier). Returns the entries made.
// The caller (ImportController) keeps the per-import total (MAX_ENTRIES) and calls Housekeeping::afterWrite after.
class Importer extends Base
{
    public const MAX_ENTRIES = 20000;
    public const MAX_BATCH = 100;
    public const MAX_DEPTH = 32;

    private Closure $clock;

    public function __construct($container, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    public function start(int $userId): int
    {
        return $this->store()->createGroup($userId, null, ['name' => 'Imported '.date('Y-m-d', (int) ($this->clock)())]);
    }

    /**
     * @param list<string> $groupPath
     * @param list<array<string,mixed>> $entries
     */
    public function batch(int $userId, int $root, array $groupPath, #[\SensitiveParameter] array $entries, #[\SensitiveParameter] string $sk): int
    {
        if (! array_is_list($groupPath) || count($groupPath) > self::MAX_DEPTH) {
            throw new VaultException('payload_invalid');
        }
        foreach ($groupPath as $name) {
            if (! is_string($name) || $name === '') {
                throw new VaultException('payload_invalid');
            }
        }
        if (! array_is_list($entries)) {
            throw new VaultException('payload_invalid');
        }
        if (count($entries) > self::MAX_BATCH) {
            throw new VaultException('import_limit');
        }
        foreach ($entries as $entry) {
            if (! is_array($entry) || (array_is_list($entry) && $entry !== [])) {
                throw new VaultException('payload_invalid');
            }
        }
        $store = $this->store();
        return $this->lock()->exclusive(function () use ($store, $userId, $root, $groupPath, $entries, $sk): int {
            // Only the importer's own top-level import group: never a group shared with them.
            if ($store->permission($userId, 'group', $root) !== ObjectStore::OWNER) {
                throw new VaultException('not_found');
            }
            $target = $root;
            foreach ($groupPath as $name) {
                $children = $store->childGroupNames($userId, $target, $sk);
                $found = array_search($name, $children, true);
                $target = $found !== false ? (int) $found : $store->createGroup($userId, $target, ['name' => $name]);
            }
            $store->beforeWrite('group', $target, $userId, $sk);
            foreach ($entries as $entry) {
                $store->createEntry($userId, $target, $entry);
            }
            if ($entries !== []) {
                AuditModel::of($this->container, $this->clock)->record('import', ['actor_user_id' => $userId, 'count' => count($entries)]);
            }
            return count($entries);
        });
    }

    private function store(): ObjectStore
    {
        return isset($this->container['vaultStore']) ? $this->container['vaultStore'] : new ObjectStore($this->container, $this->clock);
    }

    private function lock(): VaultLock
    {
        return new VaultLock($this->container);
    }
}
