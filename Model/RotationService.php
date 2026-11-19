<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\Bridge;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use RuntimeException;
use SodiumException;
use Throwable;
use ValueError;

// Key rotation (spec: Key rotation): a new keypair for a principal, and every object it can read re-keyed, so a
// backup taken afterwards is useless to anyone holding pre-rotation credentials. A durable state machine, one
// vault_rotations row per principal, each phase committed under the exclusive vault lock with all SQL through
// VaultDb (R13):
//
//   start   pending wraps of sk2 under every surviving factor's KEK, the bridge (sk1 under a key derived from
//           sk2), the old wraps deleted, state = rotating, the principal's other sessions locked and
//           enc_sk_next added to the current one. One transaction.
//   sweep   batches, one transaction each: every object with a key row for the principal at the old generation
//           is re-checked for live access and re-keyed (new DEK, key_epoch + 1, sealed to every effective
//           recipient, the rotating principal at the new key only). Objects shared with the principal are
//           re-keyed too, not just re-sealed: re-sealing would leave a DEK that sk1 recovers from an old backup.
//           Each batch first opens the bridge with sk2 and requires exactly sk1; anything else aborts the batch.
//           R31 (revised): the principal's rows on an object are dropped (and the object queued) only when it is
//           no longer an effective recipient, or when its rows open with neither sk1 nor sk2. A DEK that opens
//           but whose payload or crypto_v doesn't is kept: the object stays old-generation, is reported as an
//           integrity error (integrityErrors(); complete() throws integrity_error) and finish stays refused.
//   finish  refused while an old-generation row remains; otherwise the pending wraps become active, the bridge
//           is deleted, public_key = new_pk, key_gen + 1, enc_sk_next moves to enc_sk, rotating is cleared.
//
// A crash anywhere resumes from the next unlock with any surviving factor: it opens sk2 from a pending wrap, the
// bridge gives sk1, both are checked against old_pk and new_pk (resume()), and complete() carries on.
//
// Callers fetch sk before calling (R18) and wipe their own copies (R12); this class wipes its own.
class RotationService extends Base
{
    public const DEFAULT_BATCH = 100;
    // Results of a passphrase ceremony. Both mean the change took effect (the old passphrase opens nothing).
    public const ROTATED = 'rotated';
    public const PENDING = 'rotation_pending';
    private const FINISH_ATTEMPTS = 3;
    private const KDF_METHODS = ['passphrase', 'passphrase+prf'];

    private ArgonSlots $slots;
    private Closure $argon2;
    private Closure $clock;
    private VaultSession $session;
    private ?Closure $hook;
    private int $batch;
    /** @var list<array{0:string,1:int}> */
    private array $integrityErrors = [];

    // $hook is test-only: called as ($point, $index, $seconds) after start commits ('start', 0) and after each
    // sweep batch commits ('batch', k). A hook that throws simulates a crash at that point.
    public function __construct($container, ?ArgonSlots $slots = null, ?callable $argon2 = null, ?callable $clock = null, ?VaultSession $session = null, ?callable $hook = null, int $batch = self::DEFAULT_BATCH)
    {
        parent::__construct($container);
        $this->slots = $slots ?? new ArgonSlots($container);
        $this->argon2 = Closure::fromCallable($argon2 ?? [Kdf::class, 'argon2id']);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
        $this->session = $session ?? new VaultSession($container, null, null, $this->clock);
        $this->hook = $hook !== null ? Closure::fromCallable($hook) : null;
        $this->batch = max(1, $batch);
    }

    // "Rotate my keys": the same passphrase, a new keypair. The passphrase is checked first.
    public function requestManual(int $userId, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] string $passphrase): string
    {
        return $this->rotateWithPassphrase($userId, $sk, $passphrase, $passphrase);
    }

    // The passphrase ceremony (passphrase change, Rotate my keys). The surviving factor is the new passphrase,
    // under a fresh salt at the default KDF parameters. The current passphrase must open the principal's active
    // passphrase wrap to exactly $sk, so a hijacked unlocked session can't change it, and a mistyped one can't
    // lock the user out; failures count against the unlock back-off. Principals with other kinds of wrap
    // (hardware keys, recovery, agent) are refused here: their ceremonies must present those factors (T9/T20).
    // Only failures before start() commits are thrown. After it, the change has happened (the old passphrase
    // opens nothing), so the rest of the rotation is contained as at unlock (R33): ROTATED when it finished,
    // PENDING when it stopped (logged with the exception class only; the next unlock or request continues it).
    public function rotateWithPassphrase(int $userId, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] string $currentPassphrase, #[\SensitiveParameter] string $newPassphrase): string
    {
        $slot = $this->slots->acquire($userId);
        if ($slot === null) {
            throw new VaultException($this->slots->lastBusy() === ArgonSlots::BUSY_GLOBAL ? 'busy_global' : 'busy');
        }
        $limiter = new RateLimiter($this->container, null, $this->clock);
        $ikm = $kek = $opened = $sk2 = '';
        try {
            if ($limiter->backoffSeconds(UnlockService::userBucket($userId)) > 0) {
                throw new VaultException('rate_limited');
            }
            $db = $this->vdb();
            $rekeyer = $this->rekeyer();
            $principal = $rekeyer->principal($db, $userId);
            if ($principal === null || $rekeyer->currentPrincipal($db, $userId, $sk) === null) {
                throw new VaultException('not_found');
            }
            if ($rekeyer->rotation($db, $userId) !== null) {
                throw new VaultException('rotation_in_progress');
            }
            // The org wrap and the recovery code are rebuilt without the user (start() re-seals the one and flags the
            // other as replaced); a hardware key or an agent key must be presented, which this ceremony can't do.
            $others = $db->fetchOne("SELECT 1 AS x FROM vault_wraps WHERE user_id = ? AND method NOT IN ('passphrase', 'org', 'recovery')", [$userId]);
            if ($others !== null) {
                throw new VaultException('rotation_needs_factors');
            }
            $wrap = $db->fetchOne(
                "SELECT * FROM vault_wraps WHERE user_id = ? AND method = 'passphrase' AND status = 'active' AND key_gen = ? ORDER BY id LIMIT 1",
                [$userId, $principal['key_gen']]
            );
            $salt = $wrap === null ? false : base64_decode((string) $wrap['kdf_salt'], true);
            if ($salt === false || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
                throw new VaultException('unlock_failed');
            }
            try {
                $ikm = ($this->argon2)($currentPassphrase, $salt, (int) $wrap['kdf_ops'], (int) $wrap['kdf_mem']);
                $kek = Kdf::kek($ikm, 'passphrase');
                $opened = Wraps::unwrap(self::wrapRow($wrap), $kek, $principal['public_key']);
            } catch (CryptoException) {
                $opened = '';
            }
            if ($opened === '' || ! hash_equals($opened, $sk)) {
                $limiter->recordFailure(UnlockService::userBucket($userId));
                throw new VaultException('unlock_failed');
            }
            sodium_memzero($ikm);
            sodium_memzero($kek);

            $newSalt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $ikm = ($this->argon2)($newPassphrase, $newSalt, Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM);
            $kek = Kdf::kek($ikm, 'passphrase');
            $sk2 = $this->start($userId, $sk, [[
                'method' => 'passphrase',
                'kek' => $kek,
                'kdf_salt' => $newSalt,
                'kdf_ops' => Kdf::DEFAULT_OPS,
                'kdf_mem' => Kdf::DEFAULT_MEM,
            ]]);
            try {
                $this->complete($userId, $sk, $sk2);
                return self::ROTATED;
            } catch (Throwable $e) {
                $this->logger->warning('Vault: key rotation for user '.$userId.' started but could not complete and stays pending ('.get_class($e).')');
                return self::PENDING;
            }
        } finally {
            sodium_memzero($ikm);
            sodium_memzero($kek);
            sodium_memzero($opened);
            sodium_memzero($sk2);
            $slot->release();
        }
    }

    // Phase start. $survivingFactors: a non-empty list of {method, kek, credential_id?, kdf_salt?, kdf_ops?,
    // kdf_mem?}; passphrase methods carry the KDF parameters their KEK was derived with (raw salt). Returns sk2,
    // which the caller wipes. Refused while a rotation is already in progress, or if $sk1 isn't the current key.
    public function start(int $userId, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] array $survivingFactors): string
    {
        $factors = self::checkFactors($survivingFactors);
        $keypair = sodium_crypto_box_keypair();
        $sk2 = sodium_crypto_box_secretkey($keypair);
        $pk2 = sodium_crypto_box_publickey($keypair);
        $t0 = microtime(true);
        try {
            $this->lock()->exclusive(function () use ($userId, $sk1, $sk2, $pk2, $factors): void {
                $db = $this->vdb();
                $rekeyer = $this->rekeyer();
                $principal = $rekeyer->principal($db, $userId) ?? throw new VaultException('not_found');
                if ($rekeyer->rotation($db, $userId) !== null) {
                    throw new VaultException('rotation_in_progress');
                }
                $pk1 = self::publicKey($sk1);
                if ($pk1 === null || ! hash_equals($principal['public_key'], $pk1)) {
                    throw new VaultException('not_found');
                }
                $now = $this->now();
                $bridge = Bridge::seal($sk1, $sk2, $userId, $pk1, $pk2);
                $db->insert('vault_rotations', [
                    'user_id' => $userId,
                    'old_pk' => base64_encode($pk1),
                    'new_pk' => base64_encode($pk2),
                    'bridge_nonce' => base64_encode($bridge['nonce']),
                    'bridge' => base64_encode($bridge['ct']),
                    // start is one transaction, so 'start' is never observable: it commits straight into sweep.
                    'phase' => 'sweep',
                    'started_at' => $now,
                ], null);
                $oldMethods = array_column($db->fetchAll('SELECT DISTINCT method FROM vault_wraps WHERE user_id = ?', [$userId]), 'method');
                // The old wraps go in this transaction: from here on the old credentials open nothing.
                $db->execute('DELETE FROM vault_wraps WHERE user_id = ?', [$userId]);
                $newGen = $principal['key_gen'] + 1;
                foreach ($factors as $f) {
                    // R10: the row first, so its id is in the wrap's AD.
                    $wrapId = $db->insert('vault_wraps', [
                        'user_id' => $userId,
                        'method' => $f['method'],
                        'credential_id' => $f['credential_id'] === '' ? null : $f['credential_id'],
                        'kdf_salt' => $f['kdf_salt'] === null ? null : base64_encode($f['kdf_salt']),
                        'kdf_ops' => $f['kdf_ops'],
                        'kdf_mem' => $f['kdf_mem'],
                        'status' => 'pending',
                        'key_gen' => $newGen,
                        'nonce' => '',
                        'wrapped_sk' => '',
                        'crypto_v' => Wraps::CRYPTO_V,
                        'created_at' => $now,
                    ]);
                    $w = Wraps::wrap($sk2, $f['kek'], $userId, $f['method'], $f['credential_id'], $wrapId);
                    $db->execute('UPDATE vault_wraps SET nonce = ?, wrapped_sk = ? WHERE id = ?', [$w['nonce'], $w['wrapped_sk'], $wrapId]);
                }
                // Rebuilt without the user (spec): an org wrap is re-sealed to the org key, as a pending wrap of sk2, if
                // the policy still allows one; a recovery code that wasn't replaced by a factor is gone, and the user
                // is told once. Any queued rotation (a lowered policy) is satisfied by this one.
                $settings = new VaultSettings($this->container);
                $orgPk = $settings->orgPublicKey();
                if (in_array('org', $oldMethods, true) && $orgPk !== null && $settings->get(VaultSettings::POLICY) === VaultSettings::POLICY_CODE_ORG) {
                    RecoveryService::insertOrgWrap($db, $userId, $sk2, $orgPk, $newGen, 'pending', $now);
                }
                $notice = in_array('recovery', $oldMethods, true) && ! in_array('recovery', array_column($factors, 'method'), true)
                    ? RecoveryService::NOTICE_RECOVERY_RESET : 0;
                $db->execute("UPDATE vault_principals SET state = 'rotating', rotate_requested = 0, notices = notices | ? WHERE user_id = ?", [$notice, $userId]);
                $keep = $this->session->stageNextKey($db, $userId, $sk1, $sk2);
                if ($keep === null) {
                    $db->execute('DELETE FROM vault_sessions WHERE user_id = ?', [$userId]);
                } else {
                    $db->execute('DELETE FROM vault_sessions WHERE user_id = ? AND sid_hash <> ?', [$userId, $keep]);
                }
            });
            $this->fire('start', 0, microtime(true) - $t0);
            return $sk2;
        } catch (Throwable $e) {
            sodium_memzero($sk2);
            throw $e;
        } finally {
            sodium_memzero($keypair);
        }
    }

    // Phase sweep, in batches of $batch objects, one exclusive transaction each, one pass in (type, id) order
    // until no object is left or $maxBatches batches ran. Returns the number of objects still holding an
    // old-generation row for the principal (0 also when no rotation is in progress). Objects kept for an
    // integrity fault during this call are listed by integrityErrors().
    public function sweep(int $userId, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] string $sk2, int $batch = self::DEFAULT_BATCH, ?int $maxBatches = null): int
    {
        $batch = max(1, $batch);
        $this->integrityErrors = [];
        $cursor = null;
        for ($k = 0; ; $k++) {
            $t0 = microtime(true);
            $result = $this->lock()->exclusive(fn (): ?array => $this->sweepBatch($userId, $sk1, $sk2, $batch, $cursor));
            if ($result === null) {
                return 0;
            }
            [$processed, $left, $cursor, $faults] = $result;
            array_push($this->integrityErrors, ...$faults);
            if ($processed === 0) {
                return $left;
            }
            $this->fire('batch', $k, microtime(true) - $t0);
            if ($left === 0 || ($maxBatches !== null && $k + 1 >= $maxBatches)) {
                return $left;
            }
        }
    }

    // The objects the last sweep() kept at the old generation because their DEK opens but their payload or
    // crypto_v doesn't (R31). For T10 to audit as integrity events.
    /** @return list<array{0:string,1:int}> */
    public function integrityErrors(): array
    {
        return $this->integrityErrors;
    }

    // Phase finish. rotation_incomplete (and the phase goes back to sweep) while any key row for the principal
    // is at the old generation. A no-op when no rotation is in progress.
    public function finish(int $userId): void
    {
        $incomplete = $this->lock()->exclusive(function () use ($userId): bool {
            $db = $this->vdb();
            $rekeyer = $this->rekeyer();
            $principal = $rekeyer->principal($db, $userId);
            $rotation = $rekeyer->rotation($db, $userId);
            if ($principal === null || $rotation === null) {
                return false;
            }
            $gen = $principal['key_gen'];
            if ($this->oldGenerationLeft($db, $userId, $gen) > 0) {
                $db->execute("UPDATE vault_rotations SET phase = 'sweep' WHERE user_id = ?", [$userId]);
                return true;
            }
            $newGen = $gen + 1;
            $pending = $db->fetchOne("SELECT COUNT(*) AS n FROM vault_wraps WHERE user_id = ? AND status = 'pending' AND key_gen = ?", [$userId, $newGen]);
            if ((int) ($pending['n'] ?? 0) === 0) {
                throw new RuntimeException('Vault: a rotation without pending wraps cannot finish');
            }
            // Anything but sk2's pending wraps would still hold sk1.
            $db->execute("DELETE FROM vault_wraps WHERE user_id = ? AND NOT (status = 'pending' AND key_gen = ?)", [$userId, $newGen]);
            $db->execute("UPDATE vault_wraps SET status = 'active' WHERE user_id = ? AND key_gen = ?", [$userId, $newGen]);
            $db->execute(
                "UPDATE vault_principals SET public_key = ?, key_gen = ?, state = 'active' WHERE user_id = ?",
                [base64_encode($rotation['new_pk']), $newGen, $userId]
            );
            // Sessions without sk2 hold only sk1: lock them. The rest switch to sk2.
            $db->execute("DELETE FROM vault_sessions WHERE user_id = ? AND (enc_sk_next IS NULL OR enc_sk_next = '')", [$userId]);
            $db->execute(
                'UPDATE vault_sessions SET nonce = nonce_next, enc_sk = enc_sk_next, nonce_next = NULL, enc_sk_next = NULL WHERE user_id = ?',
                [$userId]
            );
            $db->execute('DELETE FROM vault_rotations WHERE user_id = ?', [$userId]);
            return false;
        });
        if ($incomplete) {
            throw new VaultException('rotation_incomplete');
        }
    }

    // Opens the bridge with sk2 and checks both keys against the rotation's old_pk and new_pk (and old_pk
    // against the principal's stored key). not_found for any failure. The caller wipes both keys.
    /** @return array{sk1:string,sk2:string} */
    public function resume(int $userId, #[\SensitiveParameter] string $sk2): array
    {
        return $this->lock()->shared(function () use ($userId, $sk2): array {
            $db = $this->vdb();
            $rekeyer = $this->rekeyer();
            $principal = $rekeyer->principal($db, $userId);
            $rotation = $rekeyer->rotation($db, $userId);
            $pk2 = self::publicKey($sk2);
            if ($principal === null || $rotation === null || $pk2 === null
                || ! hash_equals($rotation['new_pk'], $pk2) || ! hash_equals($rotation['old_pk'], $principal['public_key'])) {
                throw new VaultException('not_found');
            }
            try {
                $sk1 = Bridge::open($rotation['bridge_nonce'], $rotation['bridge'], $sk2, $userId, $rotation['old_pk'], $rotation['new_pk']);
            } catch (CryptoException) {
                throw new VaultException('not_found');
            }
            return ['sk1' => $sk1, 'sk2' => $sk2];
        });
    }

    // Sweep to the end, then finish. Grants that land between the last batch and finish send it back to sweep.
    // integrity_error (the rotation stays pending) when the sweep had to keep objects for an integrity fault.
    public function complete(int $userId, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] string $sk2): void
    {
        for ($attempt = 1; ; $attempt++) {
            $this->sweep($userId, $sk1, $sk2, $this->batch);
            if ($this->integrityErrors !== []) {
                throw new VaultException('integrity_error');
            }
            try {
                $this->finish($userId);
                return;
            } catch (VaultException $e) {
                if ($e->errorCode() !== 'rotation_incomplete' || $attempt >= self::FINISH_ATTEMPTS) {
                    throw $e;
                }
            }
        }
    }

    // One sweep batch inside the exclusive lock: [processed, left, cursor, integrity faults], or null without a
    // rotation. The bridge must open with sk2 to exactly sk1, or the batch aborts (rolls back) before any change.
    private function sweepBatch(int $userId, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] string $sk2, int $batch, ?array $cursor): ?array
    {
        $db = $this->vdb();
        $rekeyer = $this->rekeyer();
        $principal = $rekeyer->principal($db, $userId);
        $rotation = $rekeyer->rotation($db, $userId);
        if ($principal === null || $rotation === null) {
            return null;
        }
        $pk1 = self::publicKey($sk1);
        $pk2 = self::publicKey($sk2);
        if ($pk1 === null || $pk2 === null || ! hash_equals($rotation['old_pk'], $pk1)
            || ! hash_equals($principal['public_key'], $pk1) || ! hash_equals($rotation['new_pk'], $pk2)) {
            throw new VaultException('not_found');
        }
        $bridged = '';
        try {
            $bridged = Bridge::open($rotation['bridge_nonce'], $rotation['bridge'], $sk2, $userId, $rotation['old_pk'], $rotation['new_pk']);
            $bridgeOk = hash_equals($bridged, $sk1);
        } catch (CryptoException) {
            $bridgeOk = false;
        } finally {
            sodium_memzero($bridged);
        }
        if (! $bridgeOk) {
            throw new RuntimeException('Vault: the rotation bridge does not open to the current key; the sweep stops');
        }
        $gen = $principal['key_gen'];
        $after = $cursor === null ? '' : ' AND (object_type > ? OR (object_type = ? AND object_id > ?))';
        $objects = $db->fetchAll(
            'SELECT DISTINCT object_type, object_id FROM vault_keys WHERE principal_id = ? AND principal_key_gen = ?'.$after
            .' ORDER BY object_type, object_id LIMIT '.$batch,
            $cursor === null ? [$userId, $gen] : [$userId, $gen, $cursor[0], $cursor[0], $cursor[1]]
        );
        $faults = [];
        foreach ($objects as $o) {
            $cursor = [(string) $o['object_type'], (int) $o['object_id']];
            if (! $this->sweepObject($db, $cursor[0], $cursor[1], $userId, $gen, $sk1, $sk2)) {
                $faults[] = $cursor;
            }
        }
        $left = $this->oldGenerationLeft($db, $userId, $gen);
        $db->execute('UPDATE vault_rotations SET phase = ? WHERE user_id = ?', [$left === 0 ? 'finish' : 'sweep', $userId]);
        return [count($objects), $left, $cursor, $faults];
    }

    // Re-checks live access, then re-keys the object with the rotating principal as the holder (sk2 reaches both
    // generations; the batch has checked the bridge). False for an integrity fault: the DEK is kept and the
    // object stays old-generation. The principal's rows are dropped and the object queued (so another holder
    // re-keys it, and the write barrier holds meanwhile) only when it lost access or its rows open with neither
    // key: nothing anyone could read is lost that way.
    private function sweepObject(VaultDb $db, string $type, int $id, int $userId, int $gen, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] string $sk2): bool
    {
        $resolver = new RecipientResolver($this->container);
        $row = isset(RecipientResolver::TABLES[$type]) ? $resolver->object($type, $id) : null;
        if ($row === null) {
            // R8: a key row for a missing object grants nothing; drop it.
            $this->dropKeys($db, $type, $id, $userId);
            return true;
        }
        (new GrantModel($this->container, $this->clock))->reconcileExpired($type, $id);
        $row = $resolver->object($type, $id);
        $rekeyer = $this->rekeyer();
        if (! isset($resolver->effective($type, $id, $this->now(), $row)[$userId])) {
            $this->dropKeys($db, $type, $id, $userId);
            $rekeyer->enqueue($db, $type, $id, (int) $row['key_epoch']);
            return true;
        }
        if ($rekeyer->rekeyRow($db, $type, $row, $userId, $sk2)) {
            return true;
        }
        if ($this->anyRowOpens($db, $type, $id, $userId, $gen, $sk1, $sk2)) {
            return false;
        }
        $this->dropKeys($db, $type, $id, $userId);
        $rekeyer->enqueue($db, $type, $id, (int) $row['key_epoch']);
        return true;
    }

    // Does any of the principal's key rows on the object open, with sk1 or sk2, at the row's own epoch?
    private function anyRowOpens(VaultDb $db, string $type, int $id, int $userId, int $gen, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] string $sk2): bool
    {
        $rows = $db->fetchAll(
            'SELECT key_epoch, sealed_dek FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ?',
            [$type, $id, $userId]
        );
        $keypairs = [
            sodium_crypto_box_keypair_from_secretkey_and_publickey($sk1, sodium_crypto_box_publickey_from_secretkey($sk1)),
            sodium_crypto_box_keypair_from_secretkey_and_publickey($sk2, sodium_crypto_box_publickey_from_secretkey($sk2)),
        ];
        try {
            foreach ($rows as $r) {
                $sealed = base64_decode((string) $r['sealed_dek'], true);
                if ($sealed === false) {
                    continue;
                }
                foreach (array_keys($keypairs) as $i) {
                    try {
                        $dek = Sealer::openDek($sealed, $keypairs[$i], $type, $id, (int) $r['key_epoch'], $userId);
                        sodium_memzero($dek);
                        return true;
                    } catch (CryptoException) {
                    }
                }
            }
            return false;
        } finally {
            foreach (array_keys($keypairs) as $i) {
                sodium_memzero($keypairs[$i]);
            }
        }
    }

    private function dropKeys(VaultDb $db, string $type, int $id, int $userId): void
    {
        $db->execute('DELETE FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ?', [$type, $id, $userId]);
    }

    private function oldGenerationLeft(VaultDb $db, int $userId, int $gen): int
    {
        $r = $db->fetchOne(
            'SELECT COUNT(*) AS n FROM (SELECT DISTINCT object_type, object_id FROM vault_keys WHERE principal_id = ? AND principal_key_gen = ?) t',
            [$userId, $gen]
        );
        return (int) ($r['n'] ?? 0);
    }

    /** @return list<array{method:string,kek:string,credential_id:string,kdf_salt:?string,kdf_ops:?int,kdf_mem:?int}> */
    private static function checkFactors(#[\SensitiveParameter] array $factors): array
    {
        if ($factors === [] || ! array_is_list($factors)) {
            throw new InvalidArgumentException('Vault rotation: at least one surviving factor is required');
        }
        $out = [];
        foreach ($factors as $f) {
            $method = (string) ($f['method'] ?? '');
            $kek = $f['kek'] ?? null;
            $credentialId = (string) ($f['credential_id'] ?? '');
            if (! in_array($method, Wraps::METHODS, true) || ! is_string($kek) || strlen($kek) !== 32
                || ($method === 'passphrase+prf') !== ($credentialId !== '')) {
                throw new InvalidArgumentException('Vault rotation: invalid surviving factor');
            }
            $kdf = in_array($method, self::KDF_METHODS, true);
            $salt = $f['kdf_salt'] ?? null;
            if ($kdf && (! is_string($salt) || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES || (int) ($f['kdf_ops'] ?? 0) < 1 || (int) ($f['kdf_mem'] ?? 0) < 1)) {
                throw new InvalidArgumentException('Vault rotation: a passphrase factor needs its KDF parameters');
            }
            $out[] = [
                'method' => $method,
                'kek' => $kek,
                'credential_id' => $credentialId,
                'kdf_salt' => $kdf ? $salt : null,
                'kdf_ops' => $kdf ? (int) $f['kdf_ops'] : null,
                'kdf_mem' => $kdf ? (int) $f['kdf_mem'] : null,
            ];
        }
        return $out;
    }

    private static function publicKey(#[\SensitiveParameter] string $sk): ?string
    {
        try {
            return sodium_crypto_box_publickey_from_secretkey($sk);
        } catch (SodiumException|ValueError) {
            return null;
        }
    }

    // The vault_wraps columns Wraps::unwrap reads, with ids as ints (R12).
    private static function wrapRow(array $wrap): array
    {
        return [
            'id' => (int) $wrap['id'],
            'user_id' => (int) $wrap['user_id'],
            'method' => (string) $wrap['method'],
            'credential_id' => $wrap['credential_id'],
            'nonce' => (string) $wrap['nonce'],
            'wrapped_sk' => (string) $wrap['wrapped_sk'],
            'crypto_v' => (int) $wrap['crypto_v'],
        ];
    }

    private function fire(string $point, int $index, float $seconds): void
    {
        if ($this->hook !== null) {
            ($this->hook)($point, $index, $seconds);
        }
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
