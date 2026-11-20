<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use JsonException;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use SodiumException;
use ValueError;

// Encrypted entries and groups (spec: Entries, groups and grants). Each object has a random 32-byte DEK,
// sealed per recipient in vault_keys, and a payload under XChaCha20-Poly1305 with
// AD enc(type, crypto_v, id, owner_id, key_epoch). Writes run under the exclusive vault lock, decrypting
// reads under the shared one, and all SQL inside goes through VaultDb (R13).
//
// $sk is the actor's 32-byte X25519 secret key. Callers fetch it (VaultSession::secretKey()) BEFORE calling
// here, never inside a lock (R18), and wipe their own copy (R12). Every authorisation or crypto failure on a
// read is the one generic not_found, so "exists but not yours" looks like "no such object".
//
// Authorisation has one gate: effectivePermission() ('owner'|'edit'|'read'|null). Reads need any permission,
// updateEntry and creating an entry in a group need edit or owner, and everything else (updateGroup too, R50) (sub-groups, delete,
// and GrantModel's grant, move and revoke) needs owner. effectiveRecipients() only builds the recipient set
// that DEKs are sealed to. Both delegate to RecipientResolver (owner plus live direct and ancestor grants).
//
// Payload writes call beforeWrite() under the lock first: expired grants on the object and its ancestors are
// removed (GrantModel::removeSource, whole subtree), then a queued object is re-keyed inline by the writer
// (the write barrier), so nothing is written under a DEK a removed principal could still hold.
class ObjectStore extends Base
{
    public const TYPES = ['entry', 'group'];
    public const OWNER = 'owner';
    public const EDIT = 'edit';
    public const READ = 'read';
    private const CAN_READ = [self::OWNER, self::EDIT, self::READ];
    private const CAN_EDIT = [self::OWNER, self::EDIT];
    private const OWNER_ONLY = [self::OWNER];
    public const CRYPTO_V = 1;
    public const LIST_LIMIT = 200;
    private const CHUNK = 500;
    private const TABLES = RecipientResolver::TABLES;

    private Closure $clock;

    public function __construct($container, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    public static function ad(string $type, int $id, int $ownerId, int $keyEpoch): string
    {
        return Encoding::enc($type, self::CRYPTO_V, $id, $ownerId, $keyEpoch);
    }

    // $kind is 'normal', or AgentVault::KIND for an agent's Agent-created group, which AgentVault creates: set on insert,
    // so the group is sealed to the agent that owns it (RecipientResolver counts an agent's ownership only there).
    public function createGroup(int $actorId, ?int $parentId, #[\SensitiveParameter] array $payload, string $kind = 'normal'): int
    {
        if (! in_array($kind, ['normal', AgentVault::KIND], true)) {
            throw new InvalidArgumentException('Vault: unknown group kind');
        }
        $json = EntryPayload::encode(EntryPayload::validateGroup($payload));
        try {
            return $this->lock()->exclusive(function () use ($actorId, $parentId, $json, $kind): int {
                $db = $this->vdb();
                $this->requirePrincipal($db, $actorId);
                // M1: a just-disabled agent's grants go first, so the new object is never sealed to it.
                (new Purger($this->container))->sweepDisabledAgents($this->now());
                if ($parentId !== null) {
                    $this->requirePermission('group', $parentId, $actorId, self::OWNER_ONLY);
                    $this->grants()->reconcileExpired('group', $parentId);
                }
                $now = $this->now();
                $id = $db->insert('vault_groups', [
                    'owner_id' => $actorId,
                    'parent_id' => $parentId,
                    'kind' => $kind,
                    'key_epoch' => 1,
                    'nonce' => '',
                    'ciphertext' => '',
                    'crypto_v' => self::CRYPTO_V,
                    'position' => 0,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
                $this->sealNew($db, 'group', $id, $actorId, $json);
                $this->audit('create', $actorId, 'group', $id);
                return $id;
            });
        } finally {
            sodium_memzero($json);
        }
    }

    // The new entry is owned by the group's owner (spec: entries added to a shared group belong to it).
    public function createEntry(int $actorId, int $groupId, #[\SensitiveParameter] array $payload): int
    {
        $json = EntryPayload::encode(EntryPayload::validate($payload));
        try {
            return $this->lock()->exclusive(function () use ($actorId, $groupId, $json): int {
                $db = $this->vdb();
                $this->requirePrincipal($db, $actorId);
                (new Purger($this->container))->sweepDisabledAgents($this->now());
                $this->requirePermission('group', $groupId, $actorId, self::CAN_EDIT);
                $this->grants()->reconcileExpired('group', $groupId);
                $group = $this->fetchObject($db, 'group', $groupId) ?? throw new VaultException('not_found');
                $ownerId = (int) $group['owner_id'];
                $now = $this->now();
                $id = $db->insert('vault_entries', [
                    'group_id' => $groupId,
                    'owner_id' => $ownerId,
                    'created_by' => $actorId,
                    'version' => 1,
                    'key_epoch' => 1,
                    'nonce' => '',
                    'ciphertext' => '',
                    'crypto_v' => self::CRYPTO_V,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
                $this->sealNew($db, 'entry', $id, $ownerId, $json);
                $this->audit('create', $actorId, 'entry', $id);
                return $id;
            });
        } finally {
            sodium_memzero($json);
        }
    }

    /** @return array{id:int,group_id:int,owner_id:int,version:int,key_epoch:int,created_at:int,updated_at:int,payload:array} */
    public function readEntry(int $actorId, int $entryId, #[\SensitiveParameter] string $sk): array
    {
        return $this->lock()->shared(function () use ($actorId, $entryId, $sk): array {
            $db = $this->vdb();
            $row = $this->fetchObject($db, 'entry', $entryId);
            return $this->entryMeta($row ?? []) + ['payload' => $this->decryptFor($db, 'entry', $row, $actorId, $sk)];
        });
    }

    /** @return array{id:int,parent_id:?int,owner_id:int,key_epoch:int,created_at:int,updated_at:int,payload:array} */
    public function readGroup(int $actorId, int $groupId, #[\SensitiveParameter] string $sk): array
    {
        return $this->lock()->shared(function () use ($actorId, $groupId, $sk): array {
            $db = $this->vdb();
            $row = $this->fetchObject($db, 'group', $groupId);
            $payload = $this->decryptFor($db, 'group', $row, $actorId, $sk);
            return [
                'id' => (int) $row['id'],
                'parent_id' => $row['parent_id'] === null ? null : (int) $row['parent_id'],
                'owner_id' => (int) $row['owner_id'],
                'key_epoch' => (int) $row['key_epoch'],
                'created_at' => (int) $row['created_at'],
                'updated_at' => (int) $row['updated_at'],
                'payload' => $payload,
            ];
        });
    }

    // One value: a top-level string ('password', 'username', 'otp', …) or a custom field as 'field:<name>'.
    public function readField(int $actorId, int $entryId, string $field, #[\SensitiveParameter] string $sk): string
    {
        $payload = $this->readEntry($actorId, $entryId, $sk)['payload'];
        if (in_array($field, EntryPayload::STRING_KEYS, true)) {
            return (string) $payload[$field];
        }
        if (str_starts_with($field, 'field:')) {
            $name = substr($field, strlen('field:'));
            foreach ($payload['fields'] as $f) {
                if ($f['name'] === $name) {
                    return (string) $f['value'];
                }
            }
        }
        throw new VaultException('not_found');
    }

    // Optimistic concurrency on version. Returns the new version; a stale $expectedVersion is a conflict.
    public function updateEntry(int $actorId, int $entryId, int $expectedVersion, #[\SensitiveParameter] array $payload, #[\SensitiveParameter] string $sk): int
    {
        $json = EntryPayload::encode(EntryPayload::validate($payload));
        try {
            return $this->lock()->exclusive(function () use ($actorId, $entryId, $expectedVersion, $json, $sk): int {
                $db = $this->vdb();
                $this->requirePermission('entry', $entryId, $actorId, self::CAN_EDIT);
                $this->beforeWrite('entry', $entryId, $actorId, $sk);
                $row = $this->fetchObject($db, 'entry', $entryId);
                $dek = $this->dekFor($db, 'entry', $row, $actorId, $sk);
                try {
                    if ((int) $row['version'] !== $expectedVersion) {
                        throw new VaultException('conflict');
                    }
                    $box = Aead::seal($json, $dek, self::ad('entry', $entryId, (int) $row['owner_id'], (int) $row['key_epoch']));
                    $changed = $db->execute(
                        'UPDATE vault_entries SET nonce = ?, ciphertext = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?',
                        [base64_encode($box['nonce']), base64_encode($box['ct']), $this->now(), $entryId, $expectedVersion]
                    );
                    if ($changed !== 1) {
                        throw new VaultException('conflict');
                    }
                    $this->audit('update', $actorId, 'entry', $entryId);
                    return $expectedVersion + 1;
                } finally {
                    sodium_memzero($dek);
                }
            });
        } finally {
            sodium_memzero($json);
        }
    }

    // R45: renames a group or edits its metadata. $payload holds only the keys to change (name, icon, notes); the rest
    // are kept from the current payload, so a rename never drops the icon or notes. Owner only (R50: decision 10's
    // Edit is editing and adding entries, not the group itself). A payload write like updateEntry: the gate, then beforeWrite (expiry reconciliation, the write barrier) under the
    // same exclusive lock, then the merged payload sealed under the group's current DEK and epoch. Groups carry no
    // version, so the last write wins.
    public function updateGroup(int $actorId, int $groupId, #[\SensitiveParameter] array $payload, #[\SensitiveParameter] string $sk): void
    {
        EntryPayload::validateGroup($payload + ['name' => 'unchanged']);
        $this->lock()->exclusive(function () use ($actorId, $groupId, $payload, $sk): void {
            $db = $this->vdb();
            $this->requirePermission('group', $groupId, $actorId, self::OWNER_ONLY);
            $this->beforeWrite('group', $groupId, $actorId, $sk);
            $row = $this->fetchObject($db, 'group', $groupId);
            $json = EntryPayload::encode(EntryPayload::validateGroup(array_merge($this->decryptFor($db, 'group', $row, $actorId, $sk), $payload)));
            $dek = $this->dekFor($db, 'group', $row, $actorId, $sk);
            try {
                $box = Aead::seal($json, $dek, self::ad('group', $groupId, (int) $row['owner_id'], (int) $row['key_epoch']));
                $db->execute(
                    'UPDATE vault_groups SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = ?',
                    [base64_encode($box['nonce']), base64_encode($box['ct']), $this->now(), $groupId]
                );
                $this->audit('update', $actorId, 'group', $groupId);
            } finally {
                sodium_memzero($dek);
                sodium_memzero($json);
            }
        });
    }

    // Metadata of a group's entries, decrypted from their payloads: never a password, notes, OTP seed or field
    // value. Ordered by id; $limit is capped at LIST_LIMIT.
    public function listEntries(int $actorId, int $groupId, #[\SensitiveParameter] string $sk, int $offset = 0, int $limit = self::LIST_LIMIT): array
    {
        return $this->listPage($actorId, $groupId, $sk, $offset, $limit)['entries'];
    }

    // One page of entry metadata (listEntries' rows) and whether more follow. $groupId null lists the entries shared
    // with the actor one by one (a live direct grant) whose group the actor can't read; a group's page needs read on
    // the group. Ordered by id; $limit is capped at LIST_LIMIT.
    /** @return array{entries: list<array<string,mixed>>, more: bool} */
    public function listPage(int $actorId, ?int $groupId, #[\SensitiveParameter] string $sk, int $offset = 0, int $limit = self::LIST_LIMIT): array
    {
        $offset = max(0, $offset);
        $limit = max(1, min(self::LIST_LIMIT, $limit));
        return $this->lock()->shared(function () use ($actorId, $groupId, $sk, $offset, $limit): array {
            $db = $this->vdb();
            $window = ' ORDER BY e.id LIMIT '.($limit + 1).' OFFSET '.$offset;
            if ($groupId !== null) {
                // Opening the group's DEK proves the caller can read the group with this sk.
                $groupDek = $this->dekFor($db, 'group', $this->fetchObject($db, 'group', $groupId), $actorId, $sk);
                sodium_memzero($groupDek);
                $rows = $db->fetchAll('SELECT e.* FROM vault_entries e WHERE e.group_id = ?'.$window, [$groupId]);
            } else {
                $rows = $db->fetchAll(
                    "SELECT e.* FROM vault_entries e JOIN vault_grants g ON g.subject_type = 'entry' AND g.subject_id = e.id
                     WHERE g.grantee_id = ? AND (g.expires_at IS NULL OR g.expires_at > ?)".$window,
                    [$actorId, $this->now()]
                );
            }
            $more = count($rows) > $limit;
            $out = [];
            foreach (array_slice($rows, 0, $limit) as $row) {
                if ($groupId === null && $this->effectivePermission('group', (int) $row['group_id'], $actorId) !== null) {
                    continue; // listed with its group
                }
                $item = $this->listRow($db, $row, $actorId, $sk);
                if ($item !== null) {
                    $out[] = $item;
                }
            }
            return ['entries' => $out, 'more' => $more];
        });
    }

    // The groups the actor sees in the tree: their own, and every group another owner shared with them (a live grant
    // on it or an ancestor), with the actor's permission. A group whose parent the actor can't see is a root
    // (parent_id null). R23: only groups the actor is entitled to; one that fails to decrypt is an integrity_error row
    // with no name. shared_entries says whether listPage(null) has anything. Ordered by id.
    /** @return array{groups: list<array<string,mixed>>, shared_entries: bool} */
    public function tree(int $actorId, #[\SensitiveParameter] string $sk): array
    {
        return $this->lock()->shared(function () use ($actorId, $sk): array {
            $db = $this->vdb();
            $now = $this->now();
            $ids = array_map(static fn (array $r): int => (int) $r['id'], $db->fetchAll('SELECT id FROM vault_groups WHERE owner_id = ?', [$actorId]));
            $roots = $db->fetchAll(
                "SELECT subject_id FROM vault_grants WHERE subject_type = 'group' AND grantee_id = ? AND (expires_at IS NULL OR expires_at > ?)",
                [$actorId, $now]
            );
            foreach ($roots as $r) {
                $ids = array_merge($ids, ...$this->resolver()->subtreeLevels((int) $r['subject_id']));
            }
            $ids = array_values(array_unique($ids));
            sort($ids);
            $rows = [];
            foreach ($ids as $id) {
                $row = $this->fetchObject($db, 'group', $id);
                $perm = $row === null ? null : $this->effectivePermission('group', $id, $actorId, $row);
                if ($perm !== null) {
                    $rows[$id] = [$row, $perm];
                }
            }
            $groups = [];
            foreach ($rows as $id => [$row, $perm]) {
                $parent = $row['parent_id'] === null || ! isset($rows[(int) $row['parent_id']]) ? null : (int) $row['parent_id'];
                $item = ['id' => $id, 'parent_id' => $parent, 'permission' => $perm, 'owner_id' => (int) $row['owner_id']];
                try {
                    $item['name'] = (string) ($this->decryptFor($db, 'group', $row, $actorId, $sk)['name'] ?? '');
                } catch (VaultException) {
                    $item['integrity_error'] = true;
                }
                $groups[] = $item;
            }
            $shared = $db->fetchAll(
                "SELECT e.group_id FROM vault_entries e JOIN vault_grants g ON g.subject_type = 'entry' AND g.subject_id = e.id
                 WHERE g.grantee_id = ? AND (g.expires_at IS NULL OR g.expires_at > ?)",
                [$actorId, $now]
            );
            $sharedEntries = false;
            foreach ($shared as $r) {
                if ($this->effectivePermission('group', (int) $r['group_id'], $actorId) === null) {
                    $sharedEntries = true;
                    break;
                }
            }
            return ['groups' => $groups, 'shared_entries' => $sharedEntries];
        });
    }

    // Everything the actor may export, decrypted through the read path (spec: KeePassXC import and export → Export),
    // under one shared lock so it is one consistent snapshot:
    //   groups   the actor's own groups, and with $includeShared every group another owner shared with them (a live
    //            grant on it or an ancestor, R23), as tree() lists them: {id, parent_id (null when the parent isn't
    //            listed), name, shared}. Ordered by id.
    //   entries  every entry in those groups the actor can read, and with $includeShared each entry shared on its own
    //            whose group isn't listed (group_id null): the full payload (EntryPayload's keys) plus group_id.
    //            Ordered by id.
    //   skipped  entries the actor is entitled to that fail to decrypt (and listed groups whose name doesn't): left
    //            out and counted, not a failed export (R23).
    // Callers fetch $sk before calling (R18) and wipe it; nothing here is audited (the controller audits the export).
    /** @return array{groups: list<array{id:int, parent_id:?int, name:string, shared:bool}>, entries: list<array<string,mixed>>, skipped:int} */
    public function exportFor(int $actorId, #[\SensitiveParameter] string $sk, bool $includeShared): array
    {
        return $this->lock()->shared(function () use ($actorId, $sk, $includeShared): array {
            $db = $this->vdb();
            $now = $this->now();
            $ids = array_map(static fn (array $r): int => (int) $r['id'], $db->fetchAll('SELECT id FROM vault_groups WHERE owner_id = ?', [$actorId]));
            if ($includeShared) {
                $roots = $db->fetchAll(
                    "SELECT subject_id FROM vault_grants WHERE subject_type = 'group' AND grantee_id = ? AND (expires_at IS NULL OR expires_at > ?)",
                    [$actorId, $now]
                );
                foreach ($roots as $r) {
                    $ids = array_merge($ids, ...$this->resolver()->subtreeLevels((int) $r['subject_id']));
                }
            }
            $ids = array_values(array_unique($ids));
            sort($ids);
            $rows = [];
            foreach ($ids as $id) {
                $row = $this->fetchObject($db, 'group', $id);
                if ($row !== null && $this->effectivePermission('group', $id, $actorId, $row) !== null) {
                    $rows[$id] = $row;
                }
            }
            $skipped = 0;
            $groups = [];
            foreach ($rows as $id => $row) {
                try {
                    $name = (string) ($this->decryptFor($db, 'group', $row, $actorId, $sk)['name'] ?? '');
                } catch (VaultException) {
                    $skipped++;
                    $name = '';
                }
                $parent = $row['parent_id'] === null || ! isset($rows[(int) $row['parent_id']]) ? null : (int) $row['parent_id'];
                $groups[] = ['id' => $id, 'parent_id' => $parent, 'name' => $name, 'shared' => (int) $row['owner_id'] !== $actorId];
            }
            $entryRows = [];
            foreach (array_chunk(array_keys($rows), self::CHUNK) as $chunk) {
                foreach ($db->fetchAll('SELECT * FROM vault_entries WHERE group_id IN ('.RecipientResolver::marks($chunk).')', $chunk) as $row) {
                    $entryRows[(int) $row['id']] = [$row, (int) $row['group_id']];
                }
            }
            if ($includeShared) {
                $loose = $db->fetchAll(
                    "SELECT e.* FROM vault_entries e JOIN vault_grants g ON g.subject_type = 'entry' AND g.subject_id = e.id
                     WHERE g.grantee_id = ? AND (g.expires_at IS NULL OR g.expires_at > ?)",
                    [$actorId, $now]
                );
                foreach ($loose as $row) {
                    $entryRows[(int) $row['id']] ??= [$row, null];
                }
            }
            ksort($entryRows);
            $entries = [];
            foreach ($entryRows as [$row, $groupId]) {
                if ($this->effectivePermission('entry', (int) $row['id'], $actorId, $row) === null) {
                    continue;
                }
                try {
                    $entries[] = ['group_id' => $groupId] + EntryPayload::validate($this->decryptFor($db, 'entry', $row, $actorId, $sk));
                } catch (VaultException) {
                    $skipped++;
                }
            }
            return ['groups' => $groups, 'entries' => $entries, 'skipped' => $skipped];
        });
    }

    // The names of the groups directly under $parentId that the actor owns, decrypted through the read path (the
    // import finds its group paths with it). A group that fails to decrypt is left out. Ordered by id.
    /** @return array<int,string> id => name */
    public function childGroupNames(int $actorId, int $parentId, #[\SensitiveParameter] string $sk): array
    {
        return $this->lock()->shared(function () use ($actorId, $parentId, $sk): array {
            $db = $this->vdb();
            $out = [];
            foreach ($db->fetchAll('SELECT * FROM vault_groups WHERE parent_id = ? AND owner_id = ? ORDER BY id', [$parentId, $actorId]) as $row) {
                try {
                    $out[(int) $row['id']] = (string) ($this->decryptFor($db, 'group', $row, $actorId, $sk)['name'] ?? '');
                } catch (VaultException) {
                    continue;
                }
            }
            return $out;
        });
    }

    // The actor's permission on an object ('owner'|'edit'|'read'|null), for the UI only: what to offer. Every write
    // checks it again inside its own lock.
    public function permission(int $actorId, string $type, int $id): ?string
    {
        if (! in_array($type, self::TYPES, true)) {
            throw new InvalidArgumentException('Vault: unknown object type');
        }
        return $this->lock()->shared(fn (): ?string => $this->effectivePermission($type, $id, $actorId));
    }

    // One list row. R23: an entry the caller isn't entitled to (live grants) is left out (null); an entitled one that
    // fails to decrypt is shown as integrity_error, with no data, rather than failing the page.
    private function listRow(VaultDb $db, array $row, int $actorId, #[\SensitiveParameter] string $sk): ?array
    {
        if ($this->effectivePermission('entry', (int) $row['id'], $actorId, $row) === null) {
            return null;
        }
        $meta = $this->entryMeta($row);
        try {
            $p = $this->decryptFor($db, 'entry', $row, $actorId, $sk);
        } catch (VaultException) {
            return ['id' => $meta['id'], 'group_id' => $meta['group_id'], 'integrity_error' => true];
        }
        $out = [
            'id' => $meta['id'],
            'group_id' => $meta['group_id'],
            'title' => $p['title'] ?? '',
            'username' => $p['username'] ?? '',
            'url' => $p['url'] ?? '',
            'field_names' => array_map(static fn (array $f): string => (string) $f['name'], $p['fields'] ?? []),
            'expires_at' => $p['expires_at'] ?? null,
            'version' => $meta['version'],
            'updated_at' => $meta['updated_at'],
        ];
        unset($p);
        return $out;
    }

    // Owner only, and the owner must be unlocked: $sk must be the actor's current key (R25). A group takes
    // its whole subtree with it. Key, grant and re-key queue rows have no FK (R6),
    // so they are deleted here, per type, for every object removed. Rows are deleted bottom-up rather than
    // left to the parent_id cascade (InnoDB stops cascading at 15 levels).
    public function deleteObject(int $actorId, string $type, int $id, #[\SensitiveParameter] string $sk): void
    {
        if (! in_array($type, self::TYPES, true)) {
            throw new InvalidArgumentException('Vault: unknown object type');
        }
        $this->lock()->exclusive(function () use ($actorId, $type, $id, $sk): void {
            $db = $this->vdb();
            $this->requirePermission($type, $id, $actorId, self::OWNER_ONLY);
            $this->requireCurrentKey($db, $actorId, $sk);
            $this->audit('delete', $actorId, $type, $id);
            if ($type === 'entry') {
                $this->purgeRefs($db, 'entry', [$id]);
                $db->execute('DELETE FROM vault_entries WHERE id = ?', [$id]);
                return;
            }
            $levels = $this->resolver()->subtreeLevels($id);
            $groupIds = array_merge(...$levels);
            $entryIds = $this->resolver()->entriesIn($groupIds);
            $this->purgeRefs($db, 'entry', $entryIds);
            $this->purgeRefs($db, 'group', $groupIds);
            foreach (array_chunk($entryIds, self::CHUNK) as $chunk) {
                $db->execute('DELETE FROM vault_entries WHERE id IN ('.RecipientResolver::marks($chunk).')', $chunk);
            }
            foreach (array_reverse($levels) as $level) {
                foreach (array_chunk($level, self::CHUNK) as $chunk) {
                    $db->execute('DELETE FROM vault_groups WHERE id IN ('.RecipientResolver::marks($chunk).')', $chunk);
                }
            }
        });
    }

    // Spec "Expiry reconciliation on write" and "Write barrier", for a payload write of an existing object.
    // Runs inside the caller's exclusive lock (or its own): principals of deleted users are swept (R26), expired
    // sources on the object and its ancestors
    // are removed for their whole subtrees, then, if the object is queued, the writer re-keys it inline. Rotation
    // uses the same barrier: an object that still holds an old-generation key row for a rotating principal is
    // re-keyed inline too (the rotating principal gets its next key only). A writer who can't re-key it gets
    // not_found and nothing is written.
    public function beforeWrite(string $type, int $id, int $actorId, #[\SensitiveParameter] string $sk): void
    {
        $this->lock()->exclusive(function () use ($type, $id, $actorId, $sk): void {
            $db = $this->vdb();
            $rekeyer = $this->rekeyer();
            // R26: a deleted Kanboard user's principal is swept into re-keys first, as the purge would.
            $purger = new Purger($this->container);
            $purger->sweepOrphans($this->now());
            // T7: a disabled agent's grants go the same way first, so nothing new is written under a DEK it holds.
            $purger->sweepDisabledAgents($this->now());
            $this->grants()->reconcileExpired($type, $id);
            if (! $rekeyer->processQueued($db, $type, $id, $actorId, $sk)) {
                throw new VaultException('not_found');
            }
            if ($rekeyer->holdsOldGeneration($db, $type, $id)) {
                $row = $this->fetchObject($db, $type, $id);
                if ($row === null || ! $rekeyer->rekeyRow($db, $type, $row, $actorId, $sk)) {
                    throw new VaultException('not_found');
                }
            }
        });
    }

    // The actor's permission on an object: 'owner', 'edit', 'read' or null. The single authorisation gate,
    // from RecipientResolver: the highest among ownership and live direct and ancestor grants. A missing
    // object gives null (R8). $row saves a fetch when the caller has it. Protected so tests can override it.
    protected function effectivePermission(string $type, int $id, int $actorId, ?array $row = null): ?string
    {
        return $this->resolver()->effective($type, $id, $this->now(), $row)[$actorId] ?? null;
    }

    private function requirePermission(string $type, int $id, int $actorId, array $allowed, ?array $row = null): void
    {
        if (! in_array($this->effectivePermission($type, $id, $actorId, $row), $allowed, true)) {
            throw new VaultException('not_found');
        }
    }

    // The recipient set DEKs are sealed to (never an authorisation decision on its own): the owner plus the
    // grantees of live direct and ancestor grants. A missing object has no recipients (R8).
    /** @return list<int> */
    protected function effectiveRecipients(string $type, int $id, ?array $row = null): array
    {
        return array_keys($this->resolver()->effective($type, $id, $this->now(), $row));
    }

    // Fresh DEK, payload sealed under it, DEK sealed to every effective recipient at their current key_gen.
    // The row was inserted first so its id is in the AD (all inside the caller's exclusive transaction).
    private function sealNew(VaultDb $db, string $type, int $id, int $ownerId, #[\SensitiveParameter] string $json): void
    {
        $dek = random_bytes(Sealer::DEK_BYTES);
        try {
            $box = Aead::seal($json, $dek, self::ad($type, $id, $ownerId, 1));
            $db->execute(
                'UPDATE '.self::TABLES[$type].' SET nonce = ?, ciphertext = ? WHERE id = ?',
                [base64_encode($box['nonce']), base64_encode($box['ct']), $id]
            );
            $this->rekeyer()->sealTo($db, $type, $id, 1, $dek, $this->effectiveRecipients($type, $id), false, true);
        } finally {
            sodium_memzero($dek);
        }
    }

    private function decryptFor(VaultDb $db, string $type, ?array $row, int $actorId, #[\SensitiveParameter] string $sk): array
    {
        $dek = $this->dekFor($db, $type, $row, $actorId, $sk);
        $json = '';
        try {
            if ((int) $row['crypto_v'] !== self::CRYPTO_V) {
                throw new CryptoException('object: unsupported crypto version');
            }
            $nonce = base64_decode((string) $row['nonce'], true);
            $ct = base64_decode((string) $row['ciphertext'], true);
            if ($nonce === false || $ct === false) {
                throw new CryptoException('object: malformed row');
            }
            $json = Aead::open($nonce, $ct, $dek, self::ad($type, (int) $row['id'], (int) $row['owner_id'], (int) $row['key_epoch']));
            return EntryPayload::decode($json);
        } catch (CryptoException|JsonException|SodiumException|ValueError) {
            throw new VaultException('not_found');
        } finally {
            sodium_memzero($dek);
            sodium_memzero($json);
        }
    }

    // The read path (spec): the actor must be an effective recipient, $sk must be the actor's current key,
    // and the key row must be at the object's key_epoch. A key row alone never grants access. The caller
    // wipes the returned DEK.
    private function dekFor(VaultDb $db, string $type, ?array $row, int $actorId, #[\SensitiveParameter] string $sk): string
    {
        if ($row === null) {
            throw new VaultException('not_found');
        }
        $id = (int) $row['id'];
        $this->requirePermission($type, $id, $actorId, self::CAN_READ, $row);
        if (! in_array($actorId, $this->effectiveRecipients($type, $id, $row), true)) {
            throw new VaultException('not_found');
        }
        return $this->rekeyer()->openDek($db, $type, $id, (int) $row['key_epoch'], $actorId, $sk)
            ?? throw new VaultException('not_found');
    }

    // The actor's principal, provided $sk is its current secret key; any mismatch is not_found.
    private function requireCurrentKey(VaultDb $db, int $actorId, #[\SensitiveParameter] string $sk): array
    {
        return $this->rekeyer()->currentPrincipal($db, $actorId, $sk) ?? throw new VaultException('not_found');
    }

    private function requirePrincipal(VaultDb $db, int $userId): array
    {
        return $this->rekeyer()->principal($db, $userId) ?? throw new VaultException('not_enrolled');
    }

    private function fetchObject(VaultDb $db, string $type, int $id): ?array
    {
        return $db->fetchOne('SELECT * FROM '.self::TABLES[$type].' WHERE id = ?', [$id]);
    }

    private function entryMeta(array $row): array
    {
        return [
            'id' => (int) ($row['id'] ?? 0),
            'group_id' => (int) ($row['group_id'] ?? 0),
            'owner_id' => (int) ($row['owner_id'] ?? 0),
            'version' => (int) ($row['version'] ?? 0),
            'key_epoch' => (int) ($row['key_epoch'] ?? 0),
            'created_at' => (int) ($row['created_at'] ?? 0),
            'updated_at' => (int) ($row['updated_at'] ?? 0),
        ];
    }

    /** @param list<int> $ids */
    private function purgeRefs(VaultDb $db, string $type, array $ids): void
    {
        foreach (array_chunk($ids, self::CHUNK) as $chunk) {
            $in = RecipientResolver::marks($chunk);
            $params = array_merge([$type], $chunk);
            $db->execute('DELETE FROM vault_keys WHERE object_type = ? AND object_id IN ('.$in.')', $params);
            $db->execute('DELETE FROM vault_grants WHERE subject_type = ? AND subject_id IN ('.$in.')', $params);
            $db->execute('DELETE FROM vault_rekey_queue WHERE object_type = ? AND object_id IN ('.$in.')', $params);
        }
    }

    // Inside the caller's exclusive transaction, so the row commits or rolls back with the change.
    private function audit(string $action, int $actorId, string $type, int $id): void
    {
        AuditModel::of($this->container, $this->clock)->record($action, ['actor_user_id' => $actorId, 'object_type' => $type, 'object_id' => $id]);
    }

    private function resolver(): RecipientResolver
    {
        return new RecipientResolver($this->container);
    }

    private function rekeyer(): Rekeyer
    {
        return new Rekeyer($this->container, $this->clock);
    }

    private function grants(): GrantModel
    {
        return new GrantModel($this->container, $this->clock);
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
