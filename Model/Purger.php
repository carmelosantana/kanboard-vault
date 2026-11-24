<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;

// The purge (spec: Data model → Purge), at most once a minute on vault requests and unconditionally from
// `php cli vault:purge`. Each step is its own exclusive transaction, all SQL through VaultDb (R13):
//
//   orphan principals  R26 + v5. A Kanboard user deletion leaves the principal behind with live_user_id NULL (its
//                      grants, key rows and, since v5, the objects it owns reference vault_principals, not users).
//                      Only human and agent principals are swept: server and host have live_user_id NULL by design.
//                      For each such principal: every grant it holds is removed with GrantModel::removeSource (which
//                      drops the losers' key rows and queues every covered object, the whole subtree for a group),
//                      every object it still holds a key row for is queued at its current epoch, every object it
//                      owns is deleted with its subtree and its grant, key and queue rows
//                      (ObjectStore::deleteOwnedBy, as the old users cascade did; nobody reads them in the meantime,
//                      RecipientResolver::ownerGone), and then the principal is deleted. The write barrier covers the
//                      queued objects until a holder re-keys them. ObjectStore::beforeWrite runs the same sweep, so a
//                      write can't beat the purge. Task 11: owned entries shared with Server are quarantined instead
//                      (kept with their owned ancestor groups, the principal kept as a tombstone, state 'orphaned',
//                      audited orphan_quarantine) until OrphanService claims or destroys them; a tombstone left owning
//                      no entry is deleted with its remaining groups.
//   disabled agents    T7: every grant to a disabled agent, through GrantModel::removeSource (also before writes).
//   expired grants     the removal procedure (GrantModel::removeSource), never a bare DELETE.
//   orphaned rows      R8(b): grants (through removeSource), key rows and re-key queue rows whose object is gone.
//   sessions, challenges, share reservations and shares past their expiry (each share expiry is audited for its
//                      creator), and audit rows past the retention setting. Also every session of a disabled user.
//   rate-limit windows R39: the rate_limited row of every closed window (RateLimitAudit::flush).
//   policy wraps       T9 minor: recovery and org wraps the stored policy doesn't allow (a policy written through
//                      Kanboard's generic settings form, around setPolicy) are deleted and their rotation queued.
class Purger extends Base
{
    public const INTERVAL = 60;
    private const GRANT_BATCH = 100;
    private const CHUNK = 500;

    private Closure $audit;

    // $audit is called as ($action, $columns) inside the change's transaction; by default it is the audit log.
    // Grant removals are audited by GrantModel::removeSource itself.
    public function __construct($container, ?callable $audit = null)
    {
        parent::__construct($container);
        $this->audit = $audit !== null ? Closure::fromCallable($audit) : static fn (string $action, array $cols) => AuditModel::of($container)->record($action, $cols);
    }

    // ['ran' => false] when a purge ran less than INTERVAL seconds ago (unless $force), else 'ran' => true and a
    // count per step. The throttle is claimed atomically on the vault_meta lock row.
    /** @return array<string,bool|int> */
    public function run(int $now, bool $force = false): array
    {
        $claimed = $this->lock()->exclusive(function () use ($now, $force): bool {
            if ($force) {
                $this->vdb()->execute('UPDATE vault_meta SET last_purge_at = ? WHERE id = 1', [$now]);
                return true;
            }
            return $this->vdb()->execute(
                'UPDATE vault_meta SET last_purge_at = ? WHERE id = 1 AND (last_purge_at IS NULL OR last_purge_at <= ?)',
                [$now, $now - self::INTERVAL]
            ) === 1;
        });
        if (! $claimed) {
            return ['ran' => false];
        }
        $counts = ['ran' => true];
        $counts['orphan_principals'] = $this->sweepOrphans($now);
        $counts['disabled_agents'] = $this->sweepDisabledAgents($now);
        $counts['policy_wraps'] = (new RecoveryService($this->container))->pruneForPolicy();
        $counts['expired_grants'] = $this->expiredGrants($now);
        $counts['orphan_rows'] = $this->orphanRows($now);
        $counts += $this->expiredRows($now);
        $counts['shares'] = $this->expiredShares($now);
        $counts['audit'] = $this->auditPastRetention($now);
        $counts['rate_limited'] = (new RateLimitAudit($this->container, static fn (): int => $now))->flush();
        return $counts;
    }

    // R26: sweeps every human or agent principal whose Kanboard user was deleted into re-keys, deletes what it owns
    // (v5), then deletes it. Task 11: the entries it owns that are shared with Server are quarantined instead, with
    // their ancestor groups it owns, and the principal stays as their tombstone (state 'orphaned'); a tombstone that owns
    // no entry any more (each claimed or destroyed) is deleted with its remaining groups. Runs in the caller's exclusive
    // transaction (ObjectStore::beforeWrite) or its own. Returns how many principals were swept or released.
    public function sweepOrphans(int $now): int
    {
        return $this->lock()->exclusive(function () use ($now): int {
            $db = $this->vdb();
            $rows = $db->fetchAll("SELECT user_id, state FROM vault_principals WHERE live_user_id IS NULL AND kind IN ('human', 'agent') ORDER BY user_id");
            if ($rows === []) {
                return 0;
            }
            $grants = new GrantModel($this->container, static fn (): int => $now);
            $rekeyer = new Rekeyer($this->container, static fn (): int => $now);
            $resolver = new RecipientResolver($this->container);
            $store = new ObjectStore($this->container);
            $swept = 0;
            foreach ($rows as $r) {
                $principalId = (int) $r['user_id'];
                if ($r['state'] === 'orphaned') {
                    if ($db->fetchOne('SELECT id FROM vault_entries WHERE owner_id = ? LIMIT 1', [$principalId]) === null) {
                        $store->deleteOwnedBy($db, $principalId);
                        $this->deletePrincipal($db, $principalId);
                        $swept++;
                    }
                    continue;
                }
                foreach ($db->fetchAll('SELECT id FROM vault_grants WHERE grantee_id = ? ORDER BY id', [$principalId]) as $g) {
                    $grants->removeSource((int) $g['id']);
                }
                foreach ($db->fetchAll('SELECT DISTINCT object_type, object_id FROM vault_keys WHERE principal_id = ? ORDER BY object_type, object_id', [$principalId]) as $k) {
                    $type = (string) $k['object_type'];
                    $row = isset(RecipientResolver::TABLES[$type]) ? $resolver->object($type, (int) $k['object_id']) : null;
                    if ($row !== null) {
                        $rekeyer->enqueue($db, $type, (int) $row['id'], (int) $row['key_epoch']);
                    }
                }
                // Explicit as well as cascaded: the key rows must not outlive the principal even without FK enforcement.
                $db->execute('DELETE FROM vault_keys WHERE principal_id = ?', [$principalId]);
                [$quarantine, $keptGroups] = $this->quarantineSet($db, $resolver, $principalId);
                $store->deleteOwnedBy($db, $principalId, $quarantine, $keptGroups);
                if ($quarantine === []) {
                    $this->deletePrincipal($db, $principalId);
                } else {
                    $db->execute("UPDATE vault_principals SET state = 'orphaned' WHERE user_id = ?", [$principalId]);
                    foreach ($quarantine as $entryId) {
                        ($this->audit)('orphan_quarantine', ['actor_kind' => 'system', 'object_type' => 'entry', 'object_id' => $entryId, 'old_owner_id' => $principalId]);
                    }
                }
                $swept++;
            }
            return $swept;
        });
    }

    // The entries the principal owns that have a Server grant (Q), and the ancestor groups of those it owns (K).
    /** @return array{0: list<int>, 1: list<int>} */
    private function quarantineSet(VaultDb $db, RecipientResolver $resolver, int $principalId): array
    {
        $entries = $db->fetchAll(
            "SELECT e.id, e.group_id FROM vault_entries e WHERE e.owner_id = ? AND EXISTS (SELECT 1 FROM vault_grants g WHERE g.subject_type = 'entry' AND g.subject_id = e.id AND g.grantee_id = ?) ORDER BY e.id",
            [$principalId, ServerPrincipal::ID]
        );
        $groups = [];
        foreach ($entries as $e) {
            foreach ($resolver->ancestors('entry', $e) as $groupId) {
                $groups[$groupId] = true;
            }
        }
        $owned = [];
        foreach (array_chunk(array_keys($groups), self::CHUNK) as $chunk) {
            foreach ($db->fetchAll('SELECT id FROM vault_groups WHERE owner_id = ? AND id IN ('.RecipientResolver::marks($chunk).') ORDER BY id', array_merge([$principalId], $chunk)) as $g) {
                $owned[] = (int) $g['id'];
            }
        }
        return [array_map('intval', array_column($entries, 'id')), $owned];
    }

    private function deletePrincipal(VaultDb $db, int $principalId): void
    {
        $db->execute("DELETE FROM vault_principals WHERE user_id = ? AND live_user_id IS NULL AND kind IN ('human', 'agent')", [$principalId]);
    }

    // T7 carry / spec "Removals while nobody is unlocked": a disabled agent loses every grant source it holds, each
    // through GrantModel::removeSource (its key rows go, every covered object is queued, a revoke is audited). What it
    // owns, its Agent-created group, stays with the owner's Edit grant. Runs in the caller's exclusive transaction
    // (ObjectStore::beforeWrite) or its own. Returns how many grants were removed.
    public function sweepDisabledAgents(int $now): int
    {
        return $this->lock()->exclusive(function () use ($now): int {
            $ids = array_map('intval', array_column($this->vdb()->fetchAll(
                "SELECT g.id FROM vault_grants g JOIN vault_principals p ON p.user_id = g.grantee_id JOIN users u ON u.id = p.live_user_id
                 WHERE p.kind = 'agent' AND u.is_active <> ? ORDER BY g.id",
                [1]
            ), 'id'));
            $grants = new GrantModel($this->container, static fn (): int => $now);
            foreach ($ids as $id) {
                $grants->removeSource($id);
            }
            return count($ids);
        });
    }

    private function expiredGrants(int $now): int
    {
        $grants = new GrantModel($this->container, static fn (): int => $now);
        $total = 0;
        do {
            $n = $this->lock()->exclusive(function () use ($now, $grants): int {
                $rows = $this->vdb()->fetchAll(
                    'SELECT id FROM vault_grants WHERE expires_at IS NOT NULL AND expires_at <= ? ORDER BY id LIMIT '.self::GRANT_BATCH,
                    [$now]
                );
                foreach ($rows as $g) {
                    $grants->removeSource((int) $g['id']);
                }
                return count($rows);
            });
            $total += $n;
        } while ($n === self::GRANT_BATCH);
        return $total;
    }

    private function orphanRows(int $now): int
    {
        return $this->lock()->exclusive(function () use ($now): int {
            $db = $this->vdb();
            $grants = new GrantModel($this->container, static fn (): int => $now);
            $orphans = $db->fetchAll(
                "SELECT id FROM vault_grants WHERE NOT ((subject_type = 'entry' AND subject_id IN (SELECT id FROM vault_entries))"
                ." OR (subject_type = 'group' AND subject_id IN (SELECT id FROM vault_groups))) ORDER BY id"
            );
            foreach ($orphans as $g) {
                $grants->removeSource((int) $g['id']);
            }
            $n = count($orphans);
            foreach (['vault_keys', 'vault_rekey_queue'] as $table) {
                $n += $db->execute(
                    'DELETE FROM '.$table." WHERE NOT ((object_type = 'entry' AND object_id IN (SELECT id FROM vault_entries))"
                    ." OR (object_type = 'group' AND object_id IN (SELECT id FROM vault_groups)))"
                );
            }
            return $n;
        });
    }

    /** @return array{sessions:int,challenges:int,reservations:int} */
    private function expiredRows(int $now): array
    {
        return $this->lock()->exclusive(function () use ($now): array {
            $db = $this->vdb();
            return [
                // A disabled user's sessions too: Kanboard flushes their PHP session on their next request without a
                // logout event, so VaultSession's own disabled check never sees it (T24, Review Focus 4).
                'sessions' => $db->execute(
                    'DELETE FROM vault_sessions WHERE idle_expires_at <= ? OR abs_expires_at <= ? OR user_id IN (SELECT id FROM users WHERE is_active <> ?)',
                    [$now, $now, 1]
                ),
                'challenges' => $db->execute('DELETE FROM vault_challenges WHERE expires_at <= ?', [$now]),
                'reservations' => $db->execute('DELETE FROM vault_share_reservations WHERE expires_at <= ?', [$now]),
            ];
        });
    }

    private function expiredShares(int $now): int
    {
        $expired = $this->lock()->exclusive(function () use ($now): array {
            $db = $this->vdb();
            $rows = $db->fetchAll('SELECT id_hash, creator_id FROM vault_shares WHERE expires_at <= ? ORDER BY id_hash', [$now]);
            foreach ($rows as $r) {
                $db->execute('DELETE FROM vault_shares WHERE id_hash = ?', [$r['id_hash']]);
                ($this->audit)('share_expire', ['target_user_id' => (int) $r['creator_id'], 'share_hash' => (string) $r['id_hash']]);
            }
            return $rows;
        });
        return count($expired);
    }

    private function auditPastRetention(int $now): int
    {
        $days = (int) (new VaultSettings($this->container))->get('vault_audit_retention_days');
        return $this->lock()->exclusive(fn (): int => (new AuditModel($this->container, null, null, static fn (): int => $now))->purge($days));
    }

    private function vdb(): VaultDb
    {
        return new VaultDb($this->container);
    }

    private function lock(): VaultLock
    {
        return new VaultLock($this->container);
    }
}
