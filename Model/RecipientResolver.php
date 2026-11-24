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
// so they are ignored (R8). An object whose owner, or any ancestor group's owner, is gone (ownerGone) has no
// recipients at all.
//
// Read-only. Callers run it inside the vault lock, against the rows of that transaction; all SQL goes
// through VaultDb (R13).
class RecipientResolver extends Base
{
    public const TABLES = ['entry' => 'vault_entries', 'group' => 'vault_groups'];
    private const RANK = [ObjectStore::READ => 1, ObjectStore::EDIT => 2, ObjectStore::OWNER => 3];
    private const CHUNK = 500;
    private const READ_ONLY_KINDS = ['agent', 'server', 'host'];

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
        $chain = $this->ancestorOwners($type, $row);
        $ancestors = array_keys($chain);
        if ($this->anyGone($db, array_merge([(int) $row['owner_id']], array_values($chain)))) {
            return [];
        }
        $ownerId = (int) $row['owner_id'];
        $out = $this->ownsHere($db, $type, $row, $ancestors) ? [$ownerId => ObjectStore::OWNER] : [];
        foreach ($this->grantSources($db, $type, $id, $ancestors, $now, $excludeGrantId) as $grantee => $perm) {
            $out[$grantee] ??= $perm;
        }
        return $out;
    }

    // The live grant holders of an object, from its direct and ancestor grants: principal id => 'edit'|'read'. The owner
    // and whether any owner is gone are ignored (an orphan's grantees are who may claim it).
    /** @return array<int, 'edit'|'read'> */
    public function grantees(string $type, int $id, int $now, ?array $row = null, ?int $excludeGrantId = null): array
    {
        $row ??= $this->object($type, $id);
        if ($row === null) {
            return [];
        }
        return $this->grantSources($this->vdb(), $type, $id, $this->ancestors($type, $row), $now, $excludeGrantId);
    }

    // The principals entitled to key rows on an object, for the paths that drop losers' rows: its effective recipients;
    // for an object whose chain is gone, readable by nobody (a quarantined orphan until it is claimed or destroyed, or
    // the purge takes it), its live grant holders, so the Server key row and a claiming admin's row survive.
    /** @return array<int, 'owner'|'edit'|'read'> */
    public function keyHolders(string $type, int $id, int $now, ?array $row = null, ?int $excludeGrantId = null): array
    {
        $row ??= $this->object($type, $id);
        if ($row === null) {
            return [];
        }
        return $this->chainGone($this->vdb(), $type, $row)
            ? $this->grantees($type, $id, $now, $row, $excludeGrantId)
            : $this->effective($type, $id, $now, $row, $excludeGrantId);
    }

    // Each grantee's highest permission among the live grants on ($type, $id) and on each ancestor group.
    /** @param list<int> $ancestors @return array<int, 'edit'|'read'> */
    private function grantSources(VaultDb $db, string $type, int $id, array $ancestors, int $now, ?int $excludeGrantId): array
    {
        $out = [];
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
                // R47/A8, held here as well as at grant time: an agent principal never holds more than Read; nor do
                // Server and host, whose grants are read-only by schema.
                if (in_array($g['kind'], self::READ_ONLY_KINDS, true)) {
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
    // true when the owner's principal is missing, its Kanboard user is gone (live_user_id NULL) or it is an orphan's
    // tombstone (state 'orphaned'). effective() applies the same test to every ancestor group's owner too, as the
    // group_id and parent_id cascades took those objects.
    public function ownerGone(VaultDb $db, array $row): bool
    {
        return $this->anyGone($db, [(int) $row['owner_id']]);
    }

    // An object whose owner, or any ancestor group's owner, is gone: what effective() gives no recipients. The Server read
    // path refuses it as orphaned (spec amendment: an orphan is quarantined until it is claimed).
    public function chainGone(VaultDb $db, string $type, array $row): bool
    {
        return $this->anyGone($db, array_merge([(int) $row['owner_id']], array_values($this->ancestorOwners($type, $row))));
    }

    // Whether any of these owner principals is missing, has live_user_id NULL or is a tombstone. One query: the one
    // owner-liveness predicate, shared by ownerGone, chainGone and effective().
    /** @param list<int> $ownerIds */
    private function anyGone(VaultDb $db, array $ownerIds): bool
    {
        $ids = array_values(array_unique($ownerIds));
        $live = $db->fetchOne(
            "SELECT COUNT(*) AS n FROM vault_principals WHERE live_user_id IS NOT NULL AND state <> 'orphaned' AND user_id IN (".self::marks($ids).')',
            $ids
        );
        return (int) ($live['n'] ?? 0) !== count($ids);
    }

    // Whether owner_id makes its principal the owner here: always for a human; for an agent only on its Agent-created
    // group and below it; never for Server or host.
    /** @param list<int> $ancestors */
    private function ownsHere(VaultDb $db, string $type, array $row, array $ancestors): bool
    {
        $ownerId = (int) $row['owner_id'];
        $p = $db->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ?', [$ownerId]);
        if ($p !== null && in_array($p['kind'], ['server', 'host'], true)) {
            return false;
        }
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
        return array_keys($this->ancestorOwners($type, $row));
    }

    // ancestors() with each group's owner_id, in the same order: group id => owner id.
    /** @return array<int,int> */
    private function ancestorOwners(string $type, array $row): array
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
            $out[(int) $next] = (int) $group['owner_id'];
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
