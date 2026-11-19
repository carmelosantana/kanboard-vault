<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use Kanboard\Core\Base;

// Grant sources and authorisation changes (spec: Entries, groups and grants): grant, revoke, moves, and the
// one procedure for removing a grant source. Every operation runs under the exclusive vault lock, with every
// check and all crypto inside it against current rows; nothing is prepared ahead of time. All SQL goes
// through VaultDb (R13). Only the owner, unlocked (their current sk), may grant, revoke or move.
//
// Effective permission and recipients come from RecipientResolver alone. Key material goes through Rekeyer.
// Callers fetch the owner's sk before calling (R18) and wipe their own copy (R12).
class GrantModel extends Base
{
    public const PERMISSIONS = [ObjectStore::READ, ObjectStore::EDIT];

    private Closure $clock;

    public function __construct($container, ?callable $now = null)
    {
        parent::__construct($container);
        $this->clock = Closure::fromCallable($now ?? time(...));
    }

    // Adds (or updates) one source, then seals the current DEK to every effective recipient that lacks a
    // current key row, over the object and, for a group, its whole subtree. A queued object is re-keyed instead,
    // so a newcomer never receives a DEK a removed principal may still hold. Sealing works while the grantee is
    // offline: it needs only their public key.
    public function grant(int $ownerId, string $type, int $id, int $granteeId, string $perm, ?int $expiresAt, #[\SensitiveParameter] string $ownerSk): void
    {
        self::checkType($type);
        if (! in_array($perm, self::PERMISSIONS, true) || $granteeId === $ownerId) {
            throw new VaultException('payload_invalid');
        }
        $this->lock()->exclusive(function () use ($ownerId, $type, $id, $granteeId, $perm, $expiresAt, $ownerSk): void {
            $db = $this->vdb();
            $now = $this->now();
            $this->requireUnlockedOwner($db, $type, $id, $ownerId, $ownerSk);
            if ($expiresAt !== null && $expiresAt <= $now) {
                throw new VaultException('payload_invalid');
            }
            if ($this->rekeyer()->principal($db, $granteeId) === null) {
                throw new VaultException('not_enrolled');
            }
            $this->checkAgentGrant($db, $granteeId, $perm, $expiresAt);
            $existing = $db->fetchOne(
                'SELECT id FROM vault_grants WHERE subject_type = ? AND subject_id = ? AND grantee_id = ?',
                [$type, $id, $granteeId]
            );
            if ($existing === null) {
                $db->insert('vault_grants', [
                    'subject_type' => $type,
                    'subject_id' => $id,
                    'grantee_id' => $granteeId,
                    'permission' => $perm,
                    'granted_by' => $ownerId,
                    'expires_at' => $expiresAt,
                    'created_at' => $now,
                ]);
            } else {
                $db->execute(
                    'UPDATE vault_grants SET permission = ?, expires_at = ?, granted_by = ? WHERE id = ?',
                    [$perm, $expiresAt, $ownerId, (int) $existing['id']]
                );
            }
            foreach ($this->resolver()->subtree($type, $id) as [$t, $oid]) {
                $this->sealMissing($db, $t, $oid, $ownerId, $ownerSk);
            }
            AuditModel::of($this->container, $this->clock)->record('grant', ['actor_user_id' => $ownerId, 'object_type' => $type, 'object_id' => $id, 'target_user_id' => $granteeId]);
        });
    }

    // The sharing dialog's view of one object, for its owner only (not_found otherwise, like every refusal): the direct
    // grants on it, with each grantee's kind, and for a group the number of entries a grant covers (its whole subtree).
    // Grants inherited from an ancestor group are revoked there, so they are not listed here.
    /** @return array{grants: list<array{grantee_id:int, kind:string, permission:string, expires_at:?int}>, covered_entries?: int} */
    public function sharing(int $ownerId, string $type, int $id): array
    {
        self::checkType($type);
        return $this->lock()->shared(function () use ($ownerId, $type, $id): array {
            $this->requireOwner($type, $id, $ownerId);
            $rows = $this->vdb()->fetchAll(
                'SELECT g.grantee_id, g.permission, g.expires_at, p.kind FROM vault_grants g
                 LEFT JOIN vault_principals p ON p.user_id = g.grantee_id
                 WHERE g.subject_type = ? AND g.subject_id = ? ORDER BY g.id',
                [$type, $id]
            );
            $out = ['grants' => array_map(static fn (array $r): array => [
                'grantee_id' => (int) $r['grantee_id'],
                'kind' => $r['kind'] === 'agent' ? 'agent' : 'human',
                'permission' => (string) $r['permission'],
                'expires_at' => $r['expires_at'] === null ? null : (int) $r['expires_at'],
            ], $rows)];
            if ($type === 'group') {
                $out['covered_entries'] = $this->coveredEntries($id);
            }
            return $out;
        });
    }

    // How many entries a grant on the group covers: every entry in its subtree. Owner only.
    public function coveredCount(int $ownerId, int $groupId): int
    {
        return $this->lock()->shared(function () use ($ownerId, $groupId): int {
            $this->requireOwner('group', $groupId, $ownerId);
            return $this->coveredEntries($groupId);
        });
    }

    // Spec "Revocation": deletes the source and the removed key rows (removeSource, which also queues), then
    // re-keys the object and every object below it with the owner's DEK: a new DEK, the current payload under
    // key_epoch + 1, sealed to the remaining recipients. All in one transaction. An object the owner somehow
    // can't re-key stays queued, so the write barrier still holds for it.
    public function revoke(int $ownerId, string $type, int $id, int $granteeId, #[\SensitiveParameter] string $ownerSk): void
    {
        self::checkType($type);
        $this->lock()->exclusive(function () use ($ownerId, $type, $id, $granteeId, $ownerSk): void {
            $db = $this->vdb();
            $this->requireUnlockedOwner($db, $type, $id, $ownerId, $ownerSk);
            $grant = $db->fetchOne(
                'SELECT id FROM vault_grants WHERE subject_type = ? AND subject_id = ? AND grantee_id = ?',
                [$type, $id, $granteeId]
            ) ?? throw new VaultException('not_found');
            $this->removeSource((int) $grant['id'], $ownerId);
            $resolver = $this->resolver();
            foreach ($resolver->subtree($type, $id) as [$t, $oid]) {
                $row = $resolver->object($t, $oid);
                if ($row !== null) {
                    $this->rekeyer()->rekeyRow($db, $t, $row, $ownerId, $ownerSk);
                }
            }
        });
    }

    // Spec "Removing a grant source", the one procedure for an expiry, an offline removal or a revoke. Runs in
    // the caller's exclusive transaction (nesting) or its own. For EVERY object the source covers (the subject
    // and, for a group, its whole subtree), the principals that lose effective access are worked out: anyone
    // holding a key row, or the source's grantee, who is not an effective recipient once this source is gone.
    // Their key rows are deleted and the object is queued for re-key. Only then is the source deleted. A source
    // whose subject no longer exists is just deleted (R8); a missing grant id is a no-op. Audited as revoke by
    // $actorId, or with no actor for an expiry, a sweep or another system removal; the target is the grantee,
    // unless their Kanboard user is gone (the audit's foreign key).
    public function removeSource(int $grantId, ?int $actorId = null): void
    {
        $this->lock()->exclusive(function () use ($grantId, $actorId): void {
            $db = $this->vdb();
            $grant = $db->fetchOne('SELECT id, subject_type, subject_id, grantee_id FROM vault_grants WHERE id = ?', [$grantId]);
            if ($grant === null) {
                return;
            }
            $now = $this->now();
            $resolver = $this->resolver();
            $type = (string) $grant['subject_type'];
            $objects = isset(RecipientResolver::TABLES[$type]) ? $resolver->subtree($type, (int) $grant['subject_id']) : [];
            foreach ($objects as [$t, $oid]) {
                $row = $resolver->object($t, $oid);
                if ($row === null) {
                    continue;
                }
                $after = $resolver->effective($t, $oid, $now, $row, $grantId);
                $this->dropLosers($db, $t, $row, $after, [(int) $grant['grantee_id']]);
            }
            $db->execute('DELETE FROM vault_grants WHERE id = ?', [$grantId]);
            // live_user_id is NULL once the grantee's Kanboard user is deleted (R26), so it is safe for the FK.
            $live = $db->fetchOne('SELECT live_user_id FROM vault_principals WHERE user_id = ?', [(int) $grant['grantee_id']]);
            AuditModel::of($this->container, $this->clock)->record('revoke', [
                'actor_user_id' => $actorId,
                'object_type' => isset(RecipientResolver::TABLES[$type]) ? $type : null,
                'object_id' => isset(RecipientResolver::TABLES[$type]) ? (int) $grant['subject_id'] : null,
                'target_user_id' => $live === null || $live['live_user_id'] === null ? null : (int) $live['live_user_id'],
            ]);
        });
    }

    // Spec "Expiry reconciliation on write": removes every expired source on the object and its ancestors,
    // each with removeSource (so for its whole subtree). Runs in the caller's exclusive transaction.
    public function reconcileExpired(string $type, int $id): void
    {
        self::checkType($type);
        $this->lock()->exclusive(function () use ($type, $id): void {
            $db = $this->vdb();
            $resolver = $this->resolver();
            $row = $resolver->object($type, $id);
            if ($row === null) {
                return;
            }
            $subjects = [[$type, $id]];
            foreach ($resolver->ancestors($type, $row) as $g) {
                $subjects[] = ['group', $g];
            }
            foreach ($subjects as [$t, $oid]) {
                $expired = $db->fetchAll(
                    'SELECT id FROM vault_grants WHERE subject_type = ? AND subject_id = ? AND expires_at IS NOT NULL AND expires_at <= ? ORDER BY id',
                    [$t, $oid, $this->now()]
                );
                foreach ($expired as $g) {
                    $this->removeSource((int) $g['id']);
                }
            }
        });
    }

    // Spec "Moves": one authorisation change over the moved subtree, in one transaction. For every object in it,
    // the recipients before and after are compared; added recipients get the current DEK sealed to them,
    // removed ones lose their key rows, and every object that lost someone is queued at its current epoch.
    // The owner must own the object and the destination group (so a subtree keeps one owner, which the AD
    // binds). An entry needs a destination group; a group may move to the top level ($newParentId null) but
    // never into itself or its own subtree (invalid_move).
    public function move(int $ownerId, string $type, int $id, ?int $newParentId, #[\SensitiveParameter] string $ownerSk): void
    {
        self::checkType($type);
        $this->lock()->exclusive(function () use ($ownerId, $type, $id, $newParentId, $ownerSk): void {
            $db = $this->vdb();
            $resolver = $this->resolver();
            $now = $this->now();
            $this->requireUnlockedOwner($db, $type, $id, $ownerId, $ownerSk);
            if ($newParentId === null && $type === 'entry') {
                throw new VaultException('invalid_move');
            }
            if ($newParentId !== null) {
                if ($type === 'group' && in_array($newParentId, array_merge(...$resolver->subtreeLevels($id)), true)) {
                    throw new VaultException('invalid_move');
                }
                if (($resolver->effective('group', $newParentId, $now)[$ownerId] ?? null) !== ObjectStore::OWNER) {
                    throw new VaultException('not_found');
                }
            }
            $objects = $resolver->subtree($type, $id);
            $before = [];
            foreach ($objects as [$t, $oid]) {
                $before[$t.':'.$oid] = $resolver->effective($t, $oid, $now);
            }
            $column = $type === 'entry' ? 'group_id' : 'parent_id';
            $db->execute('UPDATE '.RecipientResolver::TABLES[$type].' SET '.$column.' = ? WHERE id = ?', [$newParentId, $id]);
            foreach ($objects as [$t, $oid]) {
                $row = $resolver->object($t, $oid);
                $after = $resolver->effective($t, $oid, $now, $row);
                $this->sealMissing($db, $t, $oid, $ownerId, $ownerSk, $row, $after, false);
                $this->dropLosers($db, $t, $row, $after, array_keys($before[$t.':'.$oid]));
            }
            // The audit table has no move action; a move changes the object's placement, so it is an update.
            AuditModel::of($this->container, $this->clock)->record('update', ['actor_user_id' => $ownerId, 'object_type' => $type, 'object_id' => $id]);
        });
    }

    // Deletes the key rows of everyone who holds one (or is in $alsoCheck) but is not in $after, and queues the
    // object at its current epoch if anyone lost access.
    private function dropLosers(VaultDb $db, string $type, array $row, array $after, array $alsoCheck): void
    {
        $id = (int) $row['id'];
        $holders = array_map(
            'intval',
            array_column($db->fetchAll('SELECT DISTINCT principal_id FROM vault_keys WHERE object_type = ? AND object_id = ?', [$type, $id]), 'principal_id')
        );
        $losers = array_values(array_diff(array_unique(array_merge($holders, array_map('intval', $alsoCheck))), array_keys($after)));
        if ($losers === []) {
            return;
        }
        $db->execute(
            'DELETE FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id IN ('.RecipientResolver::marks($losers).')',
            array_merge([$type, $id], $losers)
        );
        $this->rekeyer()->enqueue($db, $type, $id, (int) $row['key_epoch']);
    }

    // Gives every effective recipient a current key row. With $rekeyQueued (grants), a queued object is
    // re-keyed, which seals to all of them, rather than handing a newcomer the DEK a removed principal may hold.
    // A move seals the current DEK as the spec's move procedure says; the barrier covers later writes.
    // integrity_error if the owner can't open the DEK.
    private function sealMissing(VaultDb $db, string $type, int $id, int $ownerId, #[\SensitiveParameter] string $ownerSk, ?array $row = null, ?array $recipients = null, bool $rekeyQueued = true): void
    {
        $rekeyer = $this->rekeyer();
        $row ??= $this->resolver()->object($type, $id);
        if ($row === null) {
            return;
        }
        if ($rekeyQueued && $rekeyer->isQueued($db, $type, $id)) {
            if (! $rekeyer->processQueued($db, $type, $id, $ownerId, $ownerSk)) {
                throw new VaultException('integrity_error');
            }
            $row = $this->resolver()->object($type, $id);
            $recipients = null;
        }
        $recipients ??= $this->resolver()->effective($type, $id, $this->now(), $row);
        $epoch = (int) $row['key_epoch'];
        $dek = $rekeyer->openDek($db, $type, $id, $epoch, $ownerId, $ownerSk) ?? throw new VaultException('integrity_error');
        try {
            $rekeyer->sealTo($db, $type, $id, $epoch, $dek, array_keys($recipients), true);
        } finally {
            sodium_memzero($dek);
        }
    }

    // Spec, Agents (decision 5): agents read the entries granted to them and never overwrite entries a human shared
    // with them, so a grant to an agent is read only (agent_read_only), whichever path makes it (R47). An agent is a
    // user on the Agents roster (AgentRoster, the spec's definition) or a principal of kind agent, so neither a human
    // principal held by a roster agent nor an unreadable roster lets Edit through. This is the one hook
    // for any further agent limit on grants (T16): $expiresAt is passed for a maximum expiry, which v1 doesn't set.
    private function checkAgentGrant(VaultDb $db, int $granteeId, string $perm, ?int $expiresAt): void
    {
        if ($perm === ObjectStore::READ) {
            return;
        }
        $p = $db->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ?', [$granteeId]);
        if (($p !== null && $p['kind'] === 'agent') || AgentRoster::of($this->container)->isAgent($granteeId)) {
            throw new VaultException('agent_read_only');
        }
    }

    private function coveredEntries(int $groupId): int
    {
        $resolver = $this->resolver();
        return count($resolver->entriesIn(array_merge(...$resolver->subtreeLevels($groupId))));
    }

    private function requireOwner(string $type, int $id, int $ownerId): void
    {
        if (($this->resolver()->effective($type, $id, $this->now())[$ownerId] ?? null) !== ObjectStore::OWNER) {
            throw new VaultException('not_found');
        }
    }

    // Owner only, and the owner must be unlocked: $sk must be their current key. Both failures are not_found.
    private function requireUnlockedOwner(VaultDb $db, string $type, int $id, int $ownerId, #[\SensitiveParameter] string $sk): void
    {
        $this->requireOwner($type, $id, $ownerId);
        if ($this->rekeyer()->currentPrincipal($db, $ownerId, $sk) === null) {
            throw new VaultException('not_found');
        }
    }

    private static function checkType(string $type): void
    {
        if (! isset(RecipientResolver::TABLES[$type])) {
            throw new InvalidArgumentException('Vault: unknown object type');
        }
    }

    private function resolver(): RecipientResolver
    {
        return new RecipientResolver($this->container);
    }

    private function rekeyer(): Rekeyer
    {
        return new Rekeyer($this->container, $this->clock);
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
