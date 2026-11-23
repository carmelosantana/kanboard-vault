<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\Bridge;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use RuntimeException;
use SodiumException;
use ValueError;

// Key material for objects (spec: Entries, groups and grants): opening a holder's sealed DEK, sealing a DEK
// to recipients, re-keying, and the re-key queue.
//
// A re-key runs under the exclusive vault lock, against current rows: a holder who is a live effective
// recipient opens the current DEK, the payload is decrypted and re-encrypted under a new random DEK with
// key_epoch + 1 in the AD, every key row of the object is replaced by the new DEK sealed to every effective
// recipient, and the object's queue row is deleted, all in the caller's transaction. A holder who can't open
// the DEK changes nothing, so a queued item stays queued.
//
// Queue rows carry expected_key_epoch. An item re-keys only if key_epoch still equals it; otherwise the object
// was re-keyed since (every epoch change seals a fresh DEK to the then-effective recipients), so the row is
// just deleted.
//
// Key generations (spec: Key rotation; R27). While a principal is rotating (a vault_rotations row exists) it has
// two keys: the current one (old_pk, principal_key_gen = key_gen) and the next one (new_pk, key_gen + 1). Sealing
// an existing DEK to a new recipient seals to both keys; a fresh DEK (a new object or a re-key) is sealed to the
// next key only, so a re-keyed object never again holds an old-generation row. Either secret key is accepted as
// the principal's: sk1 opens old-generation rows, and sk2 opens new-generation rows directly and old-generation
// rows through the bridge (sk1 under a key derived from sk2), with both keys checked against their public keys.
//
// Server (and, later, host) principals are seal targets only (spec amendment: security requirement 7): principal()
// admits a Server principal so DEKs are sealed to it and every re-key re-seals to it while its grant lives, but only
// HOLDER_KINDS hold a key here: holder(), currentPrincipal() and holderKeypairs() refuse every other kind, so Server
// never opens a DEK, re-keys or drains the queue through this class.
class Rekeyer extends Base
{
    public const MAX_DRAIN = 500;
    private const HOLDER_KINDS = ['human', 'agent'];

    private Closure $clock;

    public function __construct($container, ?callable $now = null)
    {
        parent::__construct($container);
        $this->clock = Closure::fromCallable($now ?? time(...));
    }

    // Re-keys one object. not_found if it is missing or the holder can't open its DEK.
    public function rekey(string $type, int $id, #[\SensitiveParameter] string $anyHolderSk, int $holderId): void
    {
        $this->lock()->exclusive(function () use ($type, $id, $anyHolderSk, $holderId): void {
            $row = $this->resolver()->object($type, $id);
            if ($row === null || ! $this->rekeyRow($this->vdb(), $type, $row, $holderId, $anyHolderSk)) {
                throw new VaultException('not_found');
            }
        });
    }

    // Clears up to $max queue items the holder has a key row for, in one exclusive transaction. Returns the number
    // of queue rows cleared (re-keyed, stale or orphaned). Items the holder can't re-key stay queued and are skipped
    // (T7 minor), so they can't block the rest; at most MAX_DRAIN items are examined per call.
    public function drainQueue(int $holderId, #[\SensitiveParameter] string $holderSk, int $max = 50): int
    {
        $max = max(1, min(self::MAX_DRAIN, $max));
        return $this->lock()->exclusive(function () use ($holderId, $holderSk, $max): int {
            $db = $this->vdb();
            if ($this->currentPrincipal($db, $holderId, $holderSk) === null) {
                throw new VaultException('not_found');
            }
            $cleared = 0;
            $examined = 0;
            $lastId = 0;
            while ($cleared < $max && $examined < self::MAX_DRAIN) {
                $items = $db->fetchAll(
                    'SELECT q.id, q.object_type, q.object_id FROM vault_rekey_queue q WHERE q.id > ? AND EXISTS (SELECT 1 FROM vault_keys k'
                    .' WHERE k.object_type = q.object_type AND k.object_id = q.object_id AND k.principal_id = ?) ORDER BY q.id LIMIT '.$max,
                    [$lastId, $holderId]
                );
                if ($items === []) {
                    break;
                }
                foreach ($items as $item) {
                    $lastId = (int) $item['id'];
                    $examined++;
                    if ($this->processQueued($db, (string) $item['object_type'], (int) $item['object_id'], $holderId, $holderSk)) {
                        $cleared++;
                    }
                    if ($cleared >= $max || $examined >= self::MAX_DRAIN) {
                        break 2;
                    }
                }
            }
            return $cleared;
        });
    }

    // The write barrier and the queue use this: clears the object's queue row, re-keying first when the row is
    // current. True when no queue row remains; false when the holder couldn't re-key (the row stays).
    public function processQueued(VaultDb $db, string $type, int $id, int $holderId, #[\SensitiveParameter] string $sk): bool
    {
        $q = $db->fetchOne('SELECT expected_key_epoch FROM vault_rekey_queue WHERE object_type = ? AND object_id = ?', [$type, $id]);
        if ($q === null) {
            return true;
        }
        $row = $this->resolver()->object($type, $id);
        if ($row === null || (int) $row['key_epoch'] !== (int) $q['expected_key_epoch']) {
            $this->dequeue($db, $type, $id);
            return true;
        }
        return $this->rekeyRow($db, $type, $row, $holderId, $sk);
    }

    public function isQueued(VaultDb $db, string $type, int $id): bool
    {
        return $db->fetchOne('SELECT id FROM vault_rekey_queue WHERE object_type = ? AND object_id = ?', [$type, $id]) !== null;
    }

    // Queues the object at its current epoch, replacing any older row (unique per object).
    public function enqueue(VaultDb $db, string $type, int $id, int $keyEpoch): void
    {
        $this->dequeue($db, $type, $id);
        $db->insert('vault_rekey_queue', [
            'object_type' => $type,
            'object_id' => $id,
            'expected_key_epoch' => $keyEpoch,
            'created_at' => $this->now(),
        ]);
    }

    // The re-key itself, inside the caller's exclusive transaction. False (nothing written) when the holder is
    // not a live recipient or can't open the current DEK, or the stored ciphertext doesn't open.
    public function rekeyRow(VaultDb $db, string $type, array $row, int $holderId, #[\SensitiveParameter] string $sk): bool
    {
        $id = (int) $row['id'];
        $recipients = $this->resolver()->effective($type, $id, $this->now(), $row);
        if (! isset($recipients[$holderId])) {
            return false;
        }
        $json = $this->decryptRow($db, $type, $row, $holderId, $sk);
        if ($json === null) {
            return false;
        }
        try {
            $this->writeFresh($db, $type, $row, $json, (int) $row['owner_id'], [], array_keys($recipients));
            AuditModel::of($this->container, $this->clock)->record('rekey', ['actor_user_id' => $holderId, 'object_type' => $type, 'object_id' => $id]);
            return true;
        } finally {
            sodium_memzero($json);
        }
    }

    // An entry's change of owner (the orphan claim), inside the caller's exclusive lock: the holder opens the current DEK
    // (a key row is all it takes here; the caller decides who may), the payload is decrypted under the old owner's AD and
    // re-encrypted under a fresh DEK with key_epoch + 1 and the new owner's AD, owner_id and group_id are set, and every
    // key row is replaced by the fresh DEK sealed to the recipients effective after the move; the queue row goes. False
    // and nothing written when the holder can't open the DEK or the ciphertext doesn't open. Not audited here.
    public function transferRow(VaultDb $db, array $row, int $holderId, #[\SensitiveParameter] string $holderSk, int $newOwnerId, int $newGroupId): bool
    {
        $json = $this->decryptRow($db, 'entry', $row, $holderId, $holderSk);
        if ($json === null) {
            return false;
        }
        try {
            // Phase 2 (versions) hooks in here: every kept version of the entry is re-encrypted the same way, under the
            // fresh DEK and the new owner's AD, in this transaction.
            $this->writeFresh($db, 'entry', $row, $json, $newOwnerId, ['owner_id' => $newOwnerId, 'group_id' => $newGroupId], null);
            return true;
        } finally {
            sodium_memzero($json);
        }
    }

    // The object's payload JSON, opened as the holder at the row's key_epoch under its owner's AD, or null when the
    // holder can't open the DEK or the row doesn't decrypt. Wipes the DEK; the caller wipes the JSON.
    private function decryptRow(VaultDb $db, string $type, array $row, int $holderId, #[\SensitiveParameter] string $sk): ?string
    {
        if ((int) $row['crypto_v'] !== ObjectStore::CRYPTO_V) {
            return null;
        }
        $id = (int) $row['id'];
        $epoch = (int) $row['key_epoch'];
        $dek = $this->openDek($db, $type, $id, $epoch, $holderId, $sk);
        if ($dek === null) {
            return null;
        }
        try {
            $nonce = base64_decode((string) $row['nonce'], true);
            $ct = base64_decode((string) $row['ciphertext'], true);
            if ($nonce === false || $ct === false) {
                return null;
            }
            return Aead::open($nonce, $ct, $dek, ObjectStore::ad($type, $id, (int) $row['owner_id'], $epoch));
        } catch (CryptoException|SodiumException|ValueError) {
            return null;
        } finally {
            sodium_memzero($dek);
        }
    }

    // Seals $json under a fresh DEK at key_epoch + 1 with $ownerId in the AD and writes it (with $set's columns) if the
    // row is still at its epoch, then replaces every key row by the fresh DEK sealed to $recipients (null: the effective
    // recipients once written) and dequeues the object. Wipes the DEK.
    /** @param array<string,int> $set @param list<int>|null $recipients */
    private function writeFresh(VaultDb $db, string $type, array $row, #[\SensitiveParameter] string $json, int $ownerId, array $set, ?array $recipients): void
    {
        $id = (int) $row['id'];
        $epoch = (int) $row['key_epoch'];
        $new = random_bytes(Sealer::DEK_BYTES);
        try {
            $box = Aead::seal($json, $new, ObjectStore::ad($type, $id, $ownerId, $epoch + 1));
            $cols = ['nonce' => base64_encode($box['nonce']), 'ciphertext' => base64_encode($box['ct']), 'key_epoch' => $epoch + 1] + $set;
            $changed = $db->execute(
                'UPDATE '.RecipientResolver::TABLES[$type].' SET '.implode(', ', array_map(static fn (string $c): string => $c.' = ?', array_keys($cols)))
                .' WHERE id = ? AND key_epoch = ?',
                array_merge(array_values($cols), [$id, $epoch])
            );
            if ($changed !== 1) {
                throw new RuntimeException('Vault: the object changed under the exclusive lock');
            }
            $recipients ??= array_keys($this->resolver()->effective($type, $id, $this->now()));
            $db->execute('DELETE FROM vault_keys WHERE object_type = ? AND object_id = ?', [$type, $id]);
            $this->sealTo($db, $type, $id, $epoch + 1, $new, $recipients, false, true);
            $this->dequeue($db, $type, $id);
        } finally {
            sodium_memzero($new);
        }
    }

    // Seals $dek to every key of every principal given; principals with no principal row are skipped. By
    // default every row is a plain insert, so a row already there (which a new or just re-keyed object can't
    // legitimately have) aborts the transaction. With $onlyMissing (topping up recipients), a key that already
    // has a row at this key_epoch is left alone and a stale row for it is replaced; a rotating principal whose
    // next key already holds this epoch is not sealed to the old key again. $fresh says the DEK was just
    // generated (a new object or a re-key): a rotating principal then gets the next key only.
    /** @param list<int> $principalIds */
    public function sealTo(VaultDb $db, string $type, int $id, int $keyEpoch, #[\SensitiveParameter] string $dek, array $principalIds, bool $onlyMissing = false, bool $fresh = false): void
    {
        foreach (array_unique($principalIds) as $principalId) {
            $keys = $this->principalKeysForSealing((int) $principalId, $fresh);
            if ($onlyMissing && $keys !== [] && $this->keyEpochOf($db, $type, $id, (int) $principalId, $keys[0]['key_gen']) === $keyEpoch) {
                continue;
            }
            foreach ($keys as $key) {
                $existing = ! $onlyMissing ? null : $db->fetchOne(
                    'SELECT key_epoch FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ? AND principal_key_gen = ?',
                    [$type, $id, $principalId, $key['key_gen']]
                );
                if ($existing !== null && (int) $existing['key_epoch'] === $keyEpoch) {
                    continue;
                }
                if ($existing !== null) {
                    $db->execute(
                        'DELETE FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ? AND principal_key_gen = ?',
                        [$type, $id, $principalId, $key['key_gen']]
                    );
                }
                $db->insert('vault_keys', [
                    'object_type' => $type,
                    'object_id' => $id,
                    'principal_id' => (int) $principalId,
                    'principal_key_gen' => $key['key_gen'],
                    'key_epoch' => $keyEpoch,
                    'sealed_dek' => base64_encode(Sealer::sealDek($dek, $type, $id, $keyEpoch, (int) $principalId, $key['public_key'])),
                ], null);
            }
        }
    }

    // The public keys a DEK for this principal is sealed to, with their key_gen, newest first: the current key,
    // or while the principal is rotating the next key and the current one (the next key alone for a fresh DEK).
    /** @return list<array{key_gen:int,public_key:string}> public_key as raw bytes; empty if not enrolled */
    public function principalKeysForSealing(int $principalId, bool $fresh = false): array
    {
        $db = $this->vdb();
        $p = $this->principal($db, $principalId);
        if ($p === null) {
            return [];
        }
        $rotation = $this->rotation($db, $principalId);
        if ($rotation === null) {
            return [$p];
        }
        $next = ['public_key' => $rotation['new_pk'], 'key_gen' => $p['key_gen'] + 1];
        return $fresh ? [$next] : [$next, $p];
    }

    // The holder's DEK for the object at $keyEpoch, or null: $sk must be one of the holder's keys (see the class
    // comment) and a key row of a generation that key opens must be at $keyEpoch. The caller wipes the result.
    public function openDek(VaultDb $db, string $type, int $id, int $keyEpoch, int $holderId, #[\SensitiveParameter] string $sk): ?string
    {
        $keypairs = $this->holderKeypairs($db, $holderId, $sk);
        try {
            foreach (array_keys($keypairs) as $gen) {
                $key = $db->fetchOne(
                    'SELECT key_epoch, sealed_dek FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ? AND principal_key_gen = ?',
                    [$type, $id, $holderId, $gen]
                );
                if ($key === null || (int) $key['key_epoch'] !== $keyEpoch) {
                    continue;
                }
                $sealed = base64_decode((string) $key['sealed_dek'], true);
                if ($sealed === false) {
                    continue;
                }
                try {
                    return Sealer::openDek($sealed, $keypairs[$gen], $type, $id, $keyEpoch, $holderId);
                } catch (CryptoException|SodiumException|ValueError) {
                    continue;
                }
            }
            return null;
        } finally {
            foreach (array_keys($keypairs) as $gen) {
                sodium_memzero($keypairs[$gen]);
            }
        }
    }

    // The principal, provided $sk is its current secret key (pk(sk) equals the stored pk) or, while it is
    // rotating, the next key (pk(sk) equals the rotation's new_pk); otherwise null.
    /** @return array{public_key:string,key_gen:int,kind:string}|null  the stored (current) key */
    public function currentPrincipal(VaultDb $db, int $userId, #[\SensitiveParameter] string $sk): ?array
    {
        $principal = $this->holder($db, $userId);
        if ($principal === null) {
            return null;
        }
        try {
            $pk = sodium_crypto_box_publickey_from_secretkey($sk);
        } catch (SodiumException|ValueError) {
            return null;
        }
        if (hash_equals($principal['public_key'], $pk)) {
            return $principal;
        }
        $rotation = $this->rotation($db, $userId);
        return $rotation !== null && hash_equals($rotation['new_pk'], $pk) ? $principal : null;
    }

    // The principal's rotation in progress, or null. Keys and the bridge as raw bytes.
    /** @return array{old_pk:string,new_pk:string,bridge_nonce:string,bridge:string,phase:string}|null */
    public function rotation(VaultDb $db, int $userId): ?array
    {
        $row = $db->fetchOne('SELECT old_pk, new_pk, bridge_nonce, bridge, phase FROM vault_rotations WHERE user_id = ?', [$userId]);
        if ($row === null) {
            return null;
        }
        $out = ['phase' => (string) $row['phase']];
        foreach (['old_pk', 'new_pk', 'bridge_nonce', 'bridge'] as $col) {
            $v = base64_decode((string) $row[$col], true);
            if ($v === false) {
                throw new RuntimeException('Vault: malformed rotation row');
            }
            $out[$col] = $v;
        }
        return $out;
    }

    // Write barrier for rotation (spec): does the object still hold an old-generation key row for a principal
    // that is rotating?
    public function holdsOldGeneration(VaultDb $db, string $type, int $id): bool
    {
        return $db->fetchOne(
            'SELECT 1 AS x FROM vault_keys k JOIN vault_rotations r ON r.user_id = k.principal_id JOIN vault_principals p ON p.user_id = k.principal_id'
            .' WHERE k.object_type = ? AND k.object_id = ? AND k.principal_key_gen = p.key_gen',
            [$type, $id]
        ) !== null;
    }

    // key_gen => 64-byte keypair for every generation $sk opens for this principal, newest first. Empty when
    // $sk is neither its current key nor its next key. The caller wipes the keypairs.
    /** @return array<int,string> */
    private function holderKeypairs(VaultDb $db, int $userId, #[\SensitiveParameter] string $sk): array
    {
        $principal = $this->holder($db, $userId);
        if ($principal === null) {
            return [];
        }
        try {
            $pk = sodium_crypto_box_publickey_from_secretkey($sk);
            if (hash_equals($principal['public_key'], $pk)) {
                return [$principal['key_gen'] => sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, $pk)];
            }
        } catch (SodiumException|ValueError) {
            return [];
        }
        $rotation = $this->rotation($db, $userId);
        if ($rotation === null || ! hash_equals($rotation['new_pk'], $pk) || ! hash_equals($rotation['old_pk'], $principal['public_key'])) {
            return [];
        }
        $out = [$principal['key_gen'] + 1 => sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, $pk)];
        $sk1 = '';
        try {
            $sk1 = Bridge::open($rotation['bridge_nonce'], $rotation['bridge'], $sk, $userId, $rotation['old_pk'], $rotation['new_pk']);
            $out[$principal['key_gen']] = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk1, $rotation['old_pk']);
        } catch (CryptoException|SodiumException|ValueError) {
            // The bridge doesn't open: only the next generation is reachable.
        } finally {
            sodium_memzero($sk1);
        }
        return $out;
    }

    private function keyEpochOf(VaultDb $db, string $type, int $id, int $principalId, int $keyGen): ?int
    {
        $r = $db->fetchOne(
            'SELECT key_epoch FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ? AND principal_key_gen = ?',
            [$type, $id, $principalId, $keyGen]
        );
        return $r === null ? null : (int) $r['key_epoch'];
    }

    // A principal whose Kanboard user was deleted (live_user_id NULL, R26) counts as not enrolled, so nothing is
    // ever sealed to it again; the purge (or the next write) sweeps it into re-keys. The Server principal has no
    // Kanboard user (live_user_id is always NULL) and is admitted as a seal target.
    /** @return array{public_key:string,key_gen:int,kind:string}|null  public_key as raw bytes */
    public function principal(VaultDb $db, int $userId): ?array
    {
        $row = $db->fetchOne(
            "SELECT public_key, key_gen, kind FROM vault_principals WHERE user_id = ? AND (live_user_id IS NOT NULL OR kind = 'server')",
            [$userId]
        );
        if ($row === null) {
            return null;
        }
        $pk = base64_decode((string) $row['public_key'], true);
        if ($pk === false || strlen($pk) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            return null;
        }
        return ['public_key' => $pk, 'key_gen' => (int) $row['key_gen'], 'kind' => (string) $row['kind']];
    }

    // principal(), for a kind that may hold a key: a live human or agent. Null for Server (a seal target only).
    /** @return array{public_key:string,key_gen:int,kind:string}|null */
    public function holder(VaultDb $db, int $userId): ?array
    {
        $principal = $this->principal($db, $userId);
        return $principal !== null && in_array($principal['kind'], self::HOLDER_KINDS, true) ? $principal : null;
    }

    private function dequeue(VaultDb $db, string $type, int $id): void
    {
        $db->execute('DELETE FROM vault_rekey_queue WHERE object_type = ? AND object_id = ?', [$type, $id]);
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
