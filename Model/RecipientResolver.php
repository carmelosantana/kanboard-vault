<?php
namespace Kanboard\Plugin\Vault\Model;

use InvalidArgumentException;
use Kanboard\Core\Base;

// The single source of effective permission and effective recipients (spec: Entries, groups and grants).
// An object's effective recipients are its owner, plus the grantee of every unexpired direct grant, plus the
// grantee of every unexpired grant on any ancestor group; each recipient's permission is the highest among
// their live sources, an agent principal's capped at Read (R47). An agent principal's ownership counts only inside its
// own Agent-created group (that group and everything below it); anywhere else owner_id gives it nothing (Codex security
// round 1: a converted human must not keep its former vault). A grant is expired once expires_at <= now. Grant
// rows whose subject is missing never reach here (only existing objects and their existing ancestors are looked up),
// so they are ignored (R8). An object whose owner is gone (ownerGone) has no recipients at all.
//
// Read-only. Callers run it inside the vault lock, against the rows of that transaction; all SQL goes
// through VaultDb (R13).
class RecipientResolver extends Base
{
    public const TABLES = ['entry' => 'vault_entries', 'group' => 'vault_groups'];
    private const RANK = [ObjectStore::READ => 1, ObjectStore::EDIT => 2, ObjectStore::OWNER => 3];
    private const CHUNK = 500;

    /**
     * @param array|null $row the object's row when the caller already has it (saves a fetch)
     * @param int|null $excludeGrantId a source to leave out (removeSource computes "after" with it)
     * @return array<int, 'owner'|'edit'|'read'>
     */
    public function effective(string $type, int $id, int $now, ?array $row = null, ?int $excludeGrantId = null): array
    {
        $row ??= $this->object($type, $id);
        if ($row === null) {
            return [];
        }
        $db = $this->vdb();
        if ($this->ownerGone($db, $row)) {
            return [];
        }
        $ancestors = $this->ancestors($type, $row);
        $ownerId = (int) $row['owner_id'];
        $out = $this->ownsHere($db, $type, $row, $ancestors) ? [$ownerId => ObjectStore::OWNER] : [];
        $subjects = [[$type, $id]];
        foreach ($ancestors as $groupId) {
            $subjects[] = ['group', $groupId];
        }
        foreach ($subjects as [$subjectType, $subjectId]) {
            $grants = $db->fetchAll(
                'SELECT g.id, g.grantee_id, g.permission, g.expires_at, p.kind FROM vault_grants g
                 LEFT JOIN vault_principals p ON p.user_id = g.grantee_id
                 WHERE g.subject_type = ? AND g.subject_id = ?',
                [$subjectType, $subjectId]
            );
            foreach ($grants as $g) {
                $perm = (string) $g['permission'];
                if ((int) $g['id'] === $excludeGrantId || ! in_array($perm, [ObjectStore::READ, ObjectStore::EDIT], true)) {
                    continue;
                }
                // R47/A8, held here as well as at grant time: an agent principal never holds more than Read.
                if ($g['kind'] === 'agent') {
                    $perm = ObjectStore::READ;
                }
                if ($g['expires_at'] !== null && (int) $g['expires_at'] <= $now) {
                    continue;
                }
                $grantee = (int) $g['grantee_id'];
                if (! isset($out[$grantee]) || self::RANK[$perm] > self::RANK[$out[$grantee]]) {
                    $out[$grantee] = $perm;
                }
            }
        }
        return $out;
    }

    // v5: an object follows its owner's principal, not the Kanboard user row, so a deleted owner's objects outlive the
    // user until the purge sweeps them. Until then nobody reads them, as if the old users cascade had removed them:
    // true when the owner's principal is missing or its Kanboard user is gone (live_user_id NULL).
    public function ownerGone(VaultDb $db, array $row): bool
    {
        $p = $db->fetchOne('SELECT live_user_id FROM vault_principals WHERE user_id = ?', [(int) $row['owner_id']]);
        return $p === null || $p['live_user_id'] === null;
    }

    // Whether owner_id makes its principal the owner here: always for a human; for an agent only on its Agent-created
    // group and below it.
    /** @param list<int> $ancestors */
    private function ownsHere(VaultDb $db, string $type, array $row, array $ancestors): bool
    {
        $ownerId = (int) $row['owner_id'];
        $p = $db->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ?', [$ownerId]);
        if ($p === null || $p['kind'] !== 'agent') {
            return true;
        }
        $group = $db->fetchOne('SELECT id FROM vault_groups WHERE owner_id = ? AND kind = ? ORDER BY id LIMIT 1', [$ownerId, AgentVault::KIND]);
        if ($group === null) {
            return false;
        }
        $groupId = (int) $group['id'];
        return ($type === 'group' && (int) $row['id'] === $groupId) || in_array($groupId, $ancestors, true);
    }

    public function object(string $type, int $id): ?array
    {
        if (! isset(self::TABLES[$type])) {
            throw new InvalidArgumentException('Vault: unknown object type');
        }
        return $this->vdb()->fetchOne('SELECT * FROM '.self::TABLES[$type].' WHERE id = ?', [$id]);
    }

    // The existing groups above an object, nearest first. Stops at a missing group; guards against cycles.
    /** @return list<int> */
    public function ancestors(string $type, array $row): array
    {
        $next = $type === 'entry' ? $row['group_id'] : $row['parent_id'];
        $seen = $type === 'group' ? [(int) $row['id'] => true] : [];
        $out = [];
        while ($next !== null && ! isset($seen[(int) $next])) {
            $group = $this->object('group', (int) $next);
            if ($group === null) {
                break;
            }
            $seen[(int) $next] = true;
            $out[] = (int) $next;
            $next = $group['parent_id'];
        }
        return $out;
    }

    // Every object a source on ($type, $id) covers: the object itself and, for a group, every group and entry
    // below it. Groups come first, top down, then entries. Empty when the object is missing.
    /** @return list<array{0:string,1:int}> */
    public function subtree(string $type, int $id): array
    {
        if ($this->object($type, $id) === null) {
            return [];
        }
        if ($type === 'entry') {
            return [['entry', $id]];
        }
        $groupIds = array_merge(...$this->subtreeLevels($id));
        $out = array_map(static fn (int $g): array => ['group', $g], $groupIds);
        foreach ($this->entriesIn($groupIds) as $entryId) {
            $out[] = ['entry', $entryId];
        }
        return $out;
    }

    // Group ids of the subtree rooted at $rootId, one list per depth (root first). Guards against cycles.
    /** @return list<list<int>> */
    public function subtreeLevels(int $rootId): array
    {
        $db = $this->vdb();
        $levels = [[$rootId]];
        $seen = [$rootId => true];
        $current = [$rootId];
        while ($current !== []) {
            $next = [];
            foreach (array_chunk($current, self::CHUNK) as $chunk) {
                foreach ($db->fetchAll('SELECT id FROM vault_groups WHERE parent_id IN ('.self::marks($chunk).') ORDER BY id', $chunk) as $r) {
                    $child = (int) $r['id'];
                    if (! isset($seen[$child])) {
                        $seen[$child] = true;
                        $next[] = $child;
                    }
                }
            }
            if ($next !== []) {
                $levels[] = $next;
            }
            $current = $next;
        }
        return $levels;
    }

    /** @param list<int> $groupIds @return list<int> */
    public function entriesIn(array $groupIds): array
    {
        $db = $this->vdb();
        $out = [];
        foreach (array_chunk($groupIds, self::CHUNK) as $chunk) {
            foreach ($db->fetchAll('SELECT id FROM vault_entries WHERE group_id IN ('.self::marks($chunk).') ORDER BY id', $chunk) as $e) {
                $out[] = (int) $e['id'];
            }
        }
        return $out;
    }

    public static function marks(array $ids): string
    {
        return implode(', ', array_fill(0, count($ids), '?'));
    }

    private function vdb(): VaultDb
    {
        return new VaultDb($this->container);
    }
}
