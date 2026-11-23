<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;
use Kanboard\Core\Security\Role;

// Orphans (spec amendment: security requirement 14 with Codex NEW-02). When an owner's Kanboard user is deleted, the
// purge quarantines their entries that are shared with Server (Purger::sweepOrphans): nobody reads them, Server
// included (refusal orphaned), until an app admin decides.
//
//   claim    an active app admin, unlocked, who holds a live grant on the entry takes it over by a full re-key
//            (Rekeyer::transferRow): a fresh DEK at key_epoch + 1 under the admin's AD, moved into a group the admin
//            owns, sealed to the recipients effective there (Server again, while its grant lives). The admin's direct
//            grant goes in the same transaction, since ownership replaces it.
//   destroy  an active app admin deletes the entry and its refs; the caller has done step-up.
//   atRisk   live entries shared with Server that would be orphaned with nobody to claim them, or whose owner is
//            disabled.
//
// A refused claim or destroy is audited (orphan_claim_denied / orphan_destroy_denied, reason the code) in its own
// transaction after the rollback, then thrown as a VaultException with the same code: not_found for a live or
// missing entry, an entry that isn't quarantined, a bad group or a locked admin; not_allowed for a non-admin or an
// admin without a grant. Both run the purge's orphan sweep first, inside their lock, and act only on a quarantined
// entry (its owner a tombstone), so a deleted owner's private entry can't be claimed in the minute before the purge:
// the sweep deletes it, and that sweep is committed even when the action is then refused.
//
// An admin who rotates their own key keeps their claim: RotationService re-seals the same DEK to the new key on a
// quarantined orphan they hold a grant on.
final class OrphanService extends Base
{
    private Closure $clock;

    public function __construct($container, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->clock = Closure::fromCallable($clock ?? time(...));
    }

    // Every entry whose owner is gone and that is quarantined (its owner a tombstone) or still shared with Server (the
    // purge will quarantine it), with the Server grant's consumers and can_claim: whether this admin holds a live grant
    // on it (the claim's own test). [] for anyone but an active app admin.
    /** @return list<array{entry_id:int, old_owner_id:int, consumers:list<string>, can_claim:bool}> */
    public function orphans(int $adminId): array
    {
        return $this->lock()->shared(function () use ($adminId): array {
            $db = $this->vdb();
            if (! $this->isAdmin($db, $adminId)) {
                return [];
            }
            $rows = $db->fetchAll(
                "SELECT e.*, g.consumers AS server_consumers FROM vault_entries e
                 JOIN vault_principals p ON p.user_id = e.owner_id
                 LEFT JOIN vault_grants g ON g.subject_type = 'entry' AND g.subject_id = e.id AND g.grantee_id = ?
                 WHERE p.kind IN ('human', 'agent') AND (p.state = 'orphaned' OR (p.live_user_id IS NULL AND g.id IS NOT NULL))
                 ORDER BY e.id",
                [ServerPrincipal::ID]
            );
            $out = [];
            foreach ($rows as $r) {
                if (! $this->resolver()->ownerGone($db, $r)) {
                    continue;
                }
                $out[] = [
                    'entry_id' => (int) $r['id'],
                    'old_owner_id' => (int) $r['owner_id'],
                    'consumers' => $r['server_consumers'] === null ? [] : ServerGrant::decodeList((string) $r['server_consumers']),
                    'can_claim' => isset($this->resolver()->grantees('entry', (int) $r['id'], $this->now(), $r)[$adminId]),
                ];
            }
            return $out;
        });
    }

    // Important 4: the Kanboard user ids a tombstone still holds although a live user has that id again (SQLite reuses
    // the newest deleted id). That user can't enrol (id_held_by_orphans) until the dead owner's orphans are claimed
    // or destroyed and the purge releases the tombstone. [] for anyone but an active app admin.
    /** @return list<int> */
    public function blockedUserIds(int $adminId): array
    {
        return $this->lock()->shared(function () use ($adminId): array {
            $db = $this->vdb();
            if (! $this->isAdmin($db, $adminId)) {
                return [];
            }
            return array_map('intval', array_column($db->fetchAll(
                "SELECT p.user_id FROM vault_principals p JOIN users u ON u.id = p.user_id
                 WHERE p.state = 'orphaned' AND p.live_user_id IS NULL ORDER BY p.user_id"
            ), 'user_id'));
        });
    }

    // Returns the entry's new key_epoch. See the class comment.
    public function claim(int $adminId, int $entryId, int $groupId, #[\SensitiveParameter] string $adminSk): int
    {
        try {
            $result = $this->lock()->exclusive(function () use ($adminId, $entryId, $groupId, $adminSk): int|VaultException {
                $db = $this->vdb();
                $now = $this->now();
                $rekeyer = new Rekeyer($this->container, $this->clock);
                $resolver = $this->resolver();
                try {
                    $row = $this->eligible($db, $adminId, $entryId);
                    $admin = $rekeyer->currentPrincipal($db, $adminId, $adminSk);
                    if ($admin === null || $admin['kind'] !== 'human') {
                        throw new VaultException('not_found');
                    }
                    if (! isset($resolver->grantees('entry', $entryId, $now, $row)[$adminId])) {
                        throw new VaultException('not_allowed');
                    }
                    $group = $resolver->object('group', $groupId);
                    if ($group === null || (int) $group['owner_id'] !== $adminId || $resolver->chainGone($db, 'group', $group)) {
                        throw new VaultException('not_found');
                    }
                } catch (VaultException $e) {
                    return $e; // nothing written but the sweep: commit it, then refuse
                }
                // Ownership replaces the admin's own grant. A plain delete, not removeSource: the admin's key row must
                // stay to open the DEK, and transferRow replaces every key row anyway.
                $db->execute("DELETE FROM vault_grants WHERE subject_type = 'entry' AND subject_id = ? AND grantee_id = ?", [$entryId, $adminId]);
                if (! $rekeyer->transferRow($db, $row, $adminId, $adminSk, $adminId, $groupId)) {
                    throw new VaultException('not_allowed');
                }
                $epoch = (int) $row['key_epoch'] + 1;
                AuditModel::of($this->container, $this->clock)->record('orphan_claim', [
                    'actor_user_id' => $adminId,
                    'object_type' => 'entry',
                    'object_id' => $entryId,
                    'old_owner_id' => (int) $row['owner_id'],
                    'new_owner_id' => $adminId,
                    'key_epoch' => $epoch,
                ]);
                return $epoch;
            });
            if ($result instanceof VaultException) {
                throw $result;
            }
            return $result;
        } catch (VaultException $e) {
            $this->recordDenied('orphan_claim_denied', $adminId, $entryId, $e);
            throw $e;
        }
    }

    // See the class comment. The caller has done step-up.
    public function destroy(int $adminId, int $entryId): void
    {
        try {
            $refused = $this->lock()->exclusive(function () use ($adminId, $entryId): ?VaultException {
                $db = $this->vdb();
                try {
                    $row = $this->eligible($db, $adminId, $entryId);
                } catch (VaultException $e) {
                    return $e; // nothing written but the sweep: commit it, then refuse
                }
                (new ObjectStore($this->container, $this->clock))->purgeEntry($db, $entryId);
                AuditModel::of($this->container, $this->clock)->record('orphan_destroy', [
                    'actor_user_id' => $adminId,
                    'object_type' => 'entry',
                    'object_id' => $entryId,
                    'old_owner_id' => (int) $row['owner_id'],
                ]);
                return null;
            });
            if ($refused !== null) {
                throw $refused;
            }
        } catch (VaultException $e) {
            $this->recordDenied('orphan_destroy_denied', $adminId, $entryId, $e);
            throw $e;
        }
    }

    // Inside the claim's or destroy's exclusive lock: an active app admin (not_allowed), then the purge's orphan sweep
    // (Purger::sweepOrphans, as ObjectStore::beforeWrite runs it), so a deleted owner's entries are quarantined or
    // deleted first; then the entry must be quarantined, its owner a tombstone (state 'orphaned'), else not_found. A
    // deleted owner's private entry is never an orphan: the sweep has deleted it.
    /** @return array<string,mixed> the entry row */
    private function eligible(VaultDb $db, int $adminId, int $entryId): array
    {
        if (! $this->isAdmin($db, $adminId)) {
            throw new VaultException('not_allowed');
        }
        (new Purger($this->container, fn (string $action, array $cols) => AuditModel::of($this->container, $this->clock)->record($action, $cols)))->sweepOrphans($this->now());
        $row = $this->resolver()->object('entry', $entryId);
        if ($row === null || ! $this->resolver()->ownerGone($db, $row)
            || $db->fetchOne("SELECT user_id FROM vault_principals WHERE user_id = ? AND state = 'orphaned'", [(int) $row['owner_id']]) === null) {
            throw new VaultException('not_found');
        }
        return $row;
    }

    // Live entries with a live Server grant (of $ownerId's only, when given): owner_disabled when the owner's Kanboard
    // user is disabled; otherwise no_successor when no active, enrolled app admin other than the owner holds a live grant
    // on the entry (directly or through a group), so deleting the owner would leave an orphan nobody can claim.
    /** @return list<array{entry_id:int, owner_id:int, reason:'no_successor'|'owner_disabled'}> */
    public function atRisk(?int $ownerId = null): array
    {
        return $this->lock()->shared(function () use ($ownerId): array {
            $db = $this->vdb();
            $now = $this->now();
            $resolver = $this->resolver();
            $rows = $db->fetchAll(
                "SELECT e.*, u.is_active AS owner_active FROM vault_entries e
                 JOIN vault_grants g ON g.subject_type = 'entry' AND g.subject_id = e.id AND g.grantee_id = ?
                 JOIN vault_principals p ON p.user_id = e.owner_id
                 JOIN users u ON u.id = p.live_user_id
                 WHERE (g.expires_at IS NULL OR g.expires_at > ?)".($ownerId === null ? '' : ' AND e.owner_id = ?').' ORDER BY e.id',
                $ownerId === null ? [ServerPrincipal::ID, $now] : [ServerPrincipal::ID, $now, $ownerId]
            );
            $out = [];
            foreach ($rows as $r) {
                $owner = (int) $r['owner_id'];
                if ($resolver->chainGone($db, 'entry', $r)) {
                    continue;
                }
                $reason = null;
                if ((int) $r['owner_active'] !== 1) {
                    $reason = 'owner_disabled';
                } elseif (! $this->hasSuccessor($db, array_keys($resolver->grantees('entry', (int) $r['id'], $now, $r)), $owner)) {
                    $reason = 'no_successor';
                }
                if ($reason !== null) {
                    $out[] = ['entry_id' => (int) $r['id'], 'owner_id' => $owner, 'reason' => $reason];
                }
            }
            return $out;
        });
    }

    // Whether any of these grantees, other than the owner, is an active app admin with a live human principal.
    /** @param list<int> $grantees */
    private function hasSuccessor(VaultDb $db, array $grantees, int $ownerId): bool
    {
        $ids = array_values(array_diff($grantees, [$ownerId]));
        if ($ids === []) {
            return false;
        }
        return $db->fetchOne(
            "SELECT p.user_id FROM vault_principals p JOIN users u ON u.id = p.live_user_id
             WHERE p.kind = 'human' AND u.role = ? AND u.is_active = ? AND p.user_id IN (".RecipientResolver::marks($ids).') LIMIT 1',
            array_merge([Role::APP_ADMIN, 1], $ids)
        ) !== null;
    }

    // An active app admin (a claim also needs the admin unlocked: Rekeyer::currentPrincipal).
    private function isAdmin(VaultDb $db, int $userId): bool
    {
        return $db->fetchOne('SELECT id FROM users WHERE id = ? AND role = ? AND is_active = ?', [$userId, Role::APP_ADMIN, 1]) !== null;
    }

    // A refused claim or destroy (orphan_claim_denied / orphan_destroy_denied), in its own transaction after the
    // refused one rolled back. Every refusal is recorded (requirement 18), OrphanController's own (a non-admin, a
    // locked vault, a failed step-up) included: a code the audit doesn't list goes in as 'failed'.
    public function recordDenied(string $action, int $actorId, int $entryId, VaultException|string $code): void
    {
        if (! in_array($action, ['orphan_claim_denied', 'orphan_destroy_denied'], true)) {
            throw new \LogicException('Vault: not an orphan denial');
        }
        $reason = AuditModel::deniedReason($code instanceof VaultException ? $code->errorCode() : $code);
        $this->lock()->exclusive(fn () => AuditModel::of($this->container, $this->clock)->record($action, [
            'actor_user_id' => $actorId > 0 ? $actorId : null,
            'object_type' => 'entry',
            'object_id' => $entryId > 0 ? $entryId : null,
            'reason' => $reason,
        ]));
    }

    private function resolver(): RecipientResolver
    {
        return new RecipientResolver($this->container);
    }

    private function vdb(): VaultDb
    {
        return new VaultDb($this->container);
    }

    private function lock(): VaultLock
    {
        return new VaultLock($this->container);
    }

    private function now(): int
    {
        return (int) ($this->clock)();
    }
}
