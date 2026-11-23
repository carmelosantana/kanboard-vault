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
            // Server and host take only a Server grant (entry, read, no expiry; grantServer), never a human grant.
            $kind = $db->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ?', [$granteeId]);
            if ($kind !== null && in_array($kind['kind'], ['server', 'host'], true)) {
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

    // Spec amendment, Server grants: the owner (unlocked) shares one entry with Server for the named consumers and
    // fields. Entry only, read, no expiry; Server must be on (server_off). The grantee -1 row is upserted with the
    // canonical consumers and fields and the rates clamped to the admin maxima, then the current DEK is sealed to
    // Server (a queued entry is re-keyed first, as grant() does) and server_grant is recorded, all in one transaction.
    //
    // $fields are plain names from the owner. R1: a custom field name is stored (and audited) only as its MAC under the
    // field-MAC key, which is wiped after use; a name that is neither top-level nor a custom field of this entry is
    // payload_invalid. A refusal is recorded as server_grant_denied in its own transaction after the rollback.
    public function grantServer(int $ownerId, int $entryId, array $consumers, #[\SensitiveParameter] array $fields, ?int $ratePerHour, ?int $rateBurst, #[\SensitiveParameter] string $ownerSk): void
    {
        try {
            $consumers = ServerGrant::consumers($consumers);
            if ($fields === [] || array_filter($fields, 'is_string') !== $fields) {
                throw new VaultException('payload_invalid');
            }
            $custom = array_values(array_diff($fields, ServerGrant::TOP_LEVEL));
            if ($custom !== []) {
                $this->warmKeyProvider();
            }
            $this->lock()->exclusive(function () use ($ownerId, $entryId, $consumers, $fields, $custom, $ratePerHour, $rateBurst, $ownerSk): void {
                $db = $this->vdb();
                if (! ServerPrincipal::of($this->container)->isOn()) {
                    throw new VaultException('server_off');
                }
                $this->requireUnlockedOwner($db, 'entry', $entryId, $ownerId, $ownerSk);
                $stored = ServerGrant::fields($custom === [] ? $fields : $this->macFields($entryId, $ownerId, $ownerSk, $fields, $custom));
                $settings = new VaultSettings($this->container, null, $this->clock);
                $cols = [
                    'permission' => ObjectStore::READ,
                    'granted_by' => $ownerId,
                    'expires_at' => null,
                    'consumers' => ServerGrant::encodeList($consumers),
                    'fields' => ServerGrant::encodeList($stored),
                    'rate_per_hour' => ServerGrant::rate($ratePerHour, ServerGrant::DEFAULT_RATE, (int) $settings->get('vault_server_rate_max')),
                    'rate_burst' => ServerGrant::rate($rateBurst, ServerGrant::DEFAULT_BURST, (int) $settings->get('vault_server_burst_max')),
                ];
                $existing = $db->fetchOne(
                    "SELECT id FROM vault_grants WHERE subject_type = 'entry' AND subject_id = ? AND grantee_id = ?",
                    [$entryId, ServerPrincipal::ID]
                );
                if ($existing === null) {
                    $db->insert('vault_grants', ['subject_type' => 'entry', 'subject_id' => $entryId, 'grantee_id' => ServerPrincipal::ID, 'created_at' => $this->now()] + $cols);
                } else {
                    $db->execute(
                        'UPDATE vault_grants SET '.implode(', ', array_map(static fn (string $c): string => $c.' = ?', array_keys($cols))).' WHERE id = ?',
                        [...array_values($cols), (int) $existing['id']]
                    );
                }
                $this->sealMissing($db, 'entry', $entryId, $ownerId, $ownerSk);
                AuditModel::of($this->container, $this->clock)->record('server_grant', [
                    'actor_user_id' => $ownerId, 'object_type' => 'entry', 'object_id' => $entryId,
                    'consumers' => $cols['consumers'], 'fields' => $cols['fields'],
                ]);
            });
        } catch (VaultException $e) {
            $this->recordDenied('server_grant_denied', $ownerId, 'entry', $entryId, $e);
            throw $e;
        }
    }

    // The sharing dialog's view of one object, for its owner only (not_found otherwise, like every refusal): the direct
    // grants on it, with each grantee's kind, and for a group the number of entries a grant covers (its whole subtree).
    // Grants inherited from an ancestor group are revoked there, so they are not listed here. A Server grant (grantee
    // -1) lists its consumers, fields and rates instead of an expiry. With the owner's sk, its custom fields read as
    // the entry's plain names (R1: matched by MACing the entry's own field names); without it, or for a name the entry
    // no longer has, as the stored MAC.
    /** @return array{grants: list<array<string,mixed>>, covered_entries?: int} */
    public function sharing(int $ownerId, string $type, int $id, #[\SensitiveParameter] ?string $ownerSk = null): array
    {
        self::checkType($type);
        if ($ownerSk !== null) {
            $this->warmKeyProvider();
        }
        return $this->lock()->shared(function () use ($ownerId, $type, $id, $ownerSk): array {
            $this->requireOwner($type, $id, $ownerId);
            $rows = $this->vdb()->fetchAll(
                'SELECT g.grantee_id, g.permission, g.expires_at, g.consumers, g.fields, g.rate_per_hour, g.rate_burst, p.kind FROM vault_grants g
                 LEFT JOIN vault_principals p ON p.user_id = g.grantee_id
                 WHERE g.subject_type = ? AND g.subject_id = ? ORDER BY g.id',
                [$type, $id]
            );
            $out = ['grants' => array_map(function (array $r) use ($ownerId, $id, $ownerSk): array {
                if ((int) $r['grantee_id'] === ServerPrincipal::ID) {
                    return [
                        'grantee_id' => ServerPrincipal::ID,
                        'kind' => 'server',
                        'permission' => (string) $r['permission'],
                        'consumers' => ServerGrant::decodeList($r['consumers']),
                        'fields' => $this->plainFields($id, $ownerId, $ownerSk, ServerGrant::decodeList($r['fields'])),
                        'rate_per_hour' => (int) $r['rate_per_hour'],
                        'rate_burst' => (int) $r['rate_burst'],
                    ];
                }
                return [
                    'grantee_id' => (int) $r['grantee_id'],
                    'kind' => $r['kind'] === 'agent' ? 'agent' : 'human',
                    'permission' => (string) $r['permission'],
                    'expires_at' => $r['expires_at'] === null ? null : (int) $r['expires_at'],
                ];
            }, $rows)];
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
    // A refused revoke of the Server grant is recorded as server_revoke_denied in its own transaction after the
    // rollback.
    public function revoke(int $ownerId, string $type, int $id, int $granteeId, #[\SensitiveParameter] string $ownerSk): void
    {
        self::checkType($type);
        try {
            $this->revokeLocked($ownerId, $type, $id, $granteeId, $ownerSk);
        } catch (VaultException $e) {
            if ($granteeId === ServerPrincipal::ID) {
                $this->recordDenied('server_revoke_denied', $ownerId, $type, $id, $e);
            }
            throw $e;
        }
    }

    private function revokeLocked(int $ownerId, string $type, int $id, int $granteeId, #[\SensitiveParameter] string $ownerSk): void
    {
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
            $grant = $db->fetchOne('SELECT id, subject_type, subject_id, grantee_id, consumers, fields FROM vault_grants WHERE id = ?', [$grantId]);
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
                // keyHolders, not effective: a quarantined orphan keeps its Server key row and its other grantees' rows
                // (effective() is empty for it), or a later claim couldn't restore Server reads (Task 11, carry b).
                $after = $resolver->keyHolders($t, $oid, $now, $row, $grantId);
                $this->dropLosers($db, $t, $row, $after, [(int) $grant['grantee_id']]);
            }
            $db->execute('DELETE FROM vault_grants WHERE id = ?', [$grantId]);
            if ((int) $grant['grantee_id'] === ServerPrincipal::ID) {
                // Server grants are entry only. The entry's rate buckets go with the grant: srvread:<consumer>:<entry id>.
                $db->execute('DELETE FROM vault_rate WHERE bucket LIKE ?', ['srvread:%:'.(int) $grant['subject_id']]);
                AuditModel::of($this->container, $this->clock)->record('server_revoke', [
                    'actor_user_id' => $actorId,
                    'object_type' => isset(RecipientResolver::TABLES[$type]) ? $type : null,
                    'object_id' => isset(RecipientResolver::TABLES[$type]) ? (int) $grant['subject_id'] : null,
                    'consumers' => $grant['consumers'],
                    'fields' => $grant['fields'],
                ]);
                if ($type === 'entry') {
                    ServerEvents::revoked($this->container, (int) $grant['subject_id']);
                }
                return;
            }
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

    // R1: the stored form of $fields, with each custom name (all of them in $custom) replaced by its MAC. Each custom
    // name must be a custom field of the entry (payload_invalid otherwise); the field-MAC key is wiped after use.
    /** @return list<string> */
    private function macFields(int $entryId, int $ownerId, #[\SensitiveParameter] string $ownerSk, #[\SensitiveParameter] array $fields, #[\SensitiveParameter] array $custom): array
    {
        $names = array_column($this->entryFields($entryId, $ownerId, $ownerSk), 'name');
        if (array_diff($custom, $names) !== []) {
            throw new VaultException('payload_invalid');
        }
        $key = $this->fieldMacKey();
        try {
            return array_map(static fn (string $f): string => ServerGrant::macField($key, $f), $fields);
        } finally {
            sodium_memzero($key);
        }
    }

    // The sharing view's names for a Server grant's stored fields: each MAC that matches one of the entry's custom
    // field names reads as that name. Without the owner's sk, or when there is no MAC to match, the stored form.
    /** @param list<string> $stored @return list<string> */
    private function plainFields(int $entryId, int $ownerId, #[\SensitiveParameter] ?string $ownerSk, array $stored): array
    {
        if ($ownerSk === null || array_diff($stored, ServerGrant::TOP_LEVEL) === []) {
            return $stored;
        }
        $byMac = $this->macNames($this->entryFields($entryId, $ownerId, $ownerSk));
        return array_map(static fn (string $f): string => $byMac[$f] ?? $f, $stored);
    }

    // R1, for the activity view: the entry's custom field names by their MAC, as $viewerId reads the entry with $sk
    // now. Empty when the viewer can't read it (gone, no access) or the field-MAC key can't be opened (Server off).
    // Called outside the vault lock: the key file is read first.
    /** @return array<string,string> */
    public function fieldNamesByMac(int $viewerId, int $entryId, #[\SensitiveParameter] string $sk): array
    {
        $this->warmKeyProvider();
        try {
            return $this->macNames($this->entryFields($entryId, $viewerId, $sk));
        } catch (VaultException) {
            return [];
        }
    }

    /** @param list<array{name:string}> $entryFields @return array<string,string> */
    private function macNames(#[\SensitiveParameter] array $entryFields): array
    {
        $byMac = [];
        try {
            $key = $this->fieldMacKey();
        } catch (VaultException) {
            return [];
        }
        try {
            foreach ($entryFields as $f) {
                try {
                    $byMac[ServerGrant::macField($key, (string) $f['name'])] = (string) $f['name'];
                } catch (VaultException) {
                    // A name no grant can hold (too long, a control character): nothing to match.
                }
            }
        } finally {
            sodium_memzero($key);
        }
        return $byMac;
    }

    /** @return list<array{name:string, value:string, protected:bool}> the entry's custom fields, read as its owner */
    private function entryFields(int $entryId, int $ownerId, #[\SensitiveParameter] string $ownerSk): array
    {
        return (new ObjectStore($this->container, $this->clock))->readEntry($ownerId, $entryId, $ownerSk)['payload']['fields'];
    }

    // The field-MAC key through the key provider; server_key_unavailable when it can't be opened. The caller wipes it.
    private function fieldMacKey(): string
    {
        try {
            return $this->keyProvider()->openFieldMacKey();
        } catch (ServerKeyUnavailable) {
            throw new VaultException('server_key_unavailable');
        }
    }

    // Reads the key file before the vault lock is taken (no file I/O under the global lock). A failure here is left
    // to the locked step, which reports it in order (server_off first).
    private function warmKeyProvider(): void
    {
        $provider = $this->keyProvider();
        if ($provider instanceof FileKeyProvider) {
            try {
                $provider->warm();
            } catch (ServerKeyUnavailable) {
            }
        }
    }

    private function keyProvider(): KeyProvider
    {
        return isset($this->container['vaultKeyProvider'])
            ? $this->container['vaultKeyProvider']
            : new FileKeyProvider($this->container, isset($this->container['vaultServerKeyFile']) ? $this->container['vaultServerKeyFile'] : new ServerKeyFile(ServerKeyFile::configuredPath()));
    }

    // A refused Server grant or revoke, recorded in its own transaction once the refused one has rolled back. Only a
    // reason the audit allows is recorded; any other failure (integrity_error) propagates unrecorded.
    private function recordDenied(string $action, int $actorId, string $type, int $id, VaultException $e): void
    {
        if (! in_array($e->errorCode(), AuditModel::REASONS, true)) {
            return;
        }
        $this->lock()->exclusive(fn () => AuditModel::of($this->container, $this->clock)->record($action, [
            'actor_user_id' => $actorId > 0 ? $actorId : null,
            'object_type' => $type,
            'object_id' => $id > 0 ? $id : null,
            'reason' => $e->errorCode(),
        ]));
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
