<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use JsonException;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Secrets\RefStatus;
use Kanboard\Plugin\Vault\Secrets\SecretRef;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;
use Kanboard\Plugin\Vault\Secrets\ServiceSecrets;
use SodiumException;
use ValueError;

// The consumer API (spec amendment: Consumer API → The read path). Server reads one field of one entry for a consumer,
// in this order; the first failing step is the refusal:
//
//    1  the ref parses (SecretRef)                                          not_found
//   1b  the job ref, if given, is one the audit can hold (AuditModel::JOB_REF)  payload_invalid, thrown as
//                                                                          InvalidArgumentException (a caller error;
//                                                                          ServiceSecretException::REASONS stay frozen)
//    2  Server is on                                                       server_off
//    3  the entry exists                                                   not_found
//    4  a live Server grant on it                                          revoked if the newest server_grant/
//                                                                          server_revoke row is a revoke, else not_shared
//    5  the consumer is in the grant's consumers                           consumer_not_allowed
//    6  the field is in the grant's fields (R1: a custom one by its MAC)   field_not_allowed (server_key_unavailable
//                                                                          when the field-MAC key won't open)
//    7  no owner on the entry's chain is gone                              orphaned
//    8  a token from srvread:<consumer>:<entry id>, at the grant's rates    rate_limited
//       clamped to the admin maxima now
//    9  the -1 key row at the entry's key_epoch                            not_shared (a key row alone grants nothing)
//   10  the key provider opens the DEK                                     server_key_unavailable
//   11  the entry decrypts and has the field (top-level wins)              not_found
//
// Steps 3–11 run in one exclusive transaction that also holds the audit row (server_read, or server_read_denied with
// its reason) and the spent token: the locked step returns a refusal instead of throwing, so both commit, and a failed
// audit write rolls the token back. Steps 1–2 (and 1b) are audited outside any lock. A rate_limited refusal is aggregated (R3,
// RateLimitAudit::noteServerRead). After the commit a refusal is thrown as ServiceSecretException, which carries the
// reason and nothing else. No title, value or payload reaches an exception, a log or an audit column; a custom field
// name is audited only as its MAC. The key file is read before the lock is taken.
class ServerSecrets extends Base implements ServiceSecrets
{
    private Closure $clock;

    public function __construct($container, private KeyProvider $provider, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    public static function bucket(string $consumer, int $entryId): string
    {
        return 'srvread:'.$consumer.':'.$entryId;
    }

    public function available(): bool
    {
        return ServerPrincipal::of($this->container)->isOn() && $this->provider->healthy();
    }

    public function read(string $consumer, #[\SensitiveParameter] string $ref, ?string $jobRef = null): SecretValue
    {
        // A job ref the audit can't hold is never written; the row goes without it.
        $jobRefValid = $jobRef === null || preg_match(AuditModel::JOB_REF, $jobRef) === 1;
        $cols = ['consumer' => ServerGrant::validConsumer($consumer) ? $consumer : null, 'job_ref' => $jobRefValid ? $jobRef : null];
        $parsed = SecretRef::parse($ref);
        if ($parsed === null) {
            $this->denied($cols, 'not_found');
            throw new ServiceSecretException('not_found');
        }
        // A custom field is audited only as its MAC, known from step 6 on.
        $cols += ['object_type' => 'entry', 'object_id' => $parsed->entryId, 'field_name' => $parsed->isTopLevel() ? $parsed->field : null];
        if (! $jobRefValid) {
            $this->denied($cols, 'payload_invalid');
            throw new InvalidArgumentException('Vault: a job ref is 1 to 64 of A-Z a-z 0-9 _ . : -');
        }
        if (! ServerPrincipal::of($this->container)->isOn()) {
            $this->denied($cols, 'server_off');
            throw new ServiceSecretException('server_off');
        }
        $this->warm();
        [$value, $reason] = (new VaultLock($this->container))->exclusive(fn (): array => $this->readLocked($consumer, $parsed, $cols));
        if ($reason !== null) {
            throw new ServiceSecretException($reason);
        }
        try {
            return SecretValue::of($value);
        } finally {
            sodium_memzero($value);
        }
    }

    public function describe(#[\SensitiveParameter] string $ref): RefStatus
    {
        $parsed = SecretRef::parse($ref);
        if ($parsed === null) {
            return new RefStatus(false, 'not_found', null, null);
        }
        $reason = 'server_off';
        if (ServerPrincipal::of($this->container)->isOn()) {
            $this->warm();
            $reason = (new VaultLock($this->container))->shared(function () use ($parsed): ?string {
                $db = new VaultDb($this->container);
                $gate = $this->gate($db, $parsed, null);
                return $gate['reason'] ?? ($this->currentKeyRow($db, $gate['entry']) === null ? 'not_shared' : null);
            });
        }
        return new RefStatus($reason === null, $reason, $parsed->entryId, $parsed->field);
    }

    // Steps 3–11 inside the exclusive lock. Returns [value, null] or [null, reason], with the audit row written.
    /** @return array{0: ?string, 1: ?string} */
    private function readLocked(string $consumer, SecretRef $ref, array $cols): array
    {
        $db = new VaultDb($this->container);
        $gate = $this->gate($db, $ref, $consumer);
        $entry = $gate['entry'];
        $cols['field_name'] = $gate['field'] ?? $cols['field_name'];
        $cols['entry_version'] = $entry === null ? null : (int) $entry['version'];
        if ($gate['reason'] !== null) {
            return $this->refuse($cols, $gate['reason']);
        }
        $grant = $gate['grant'];
        $settings = new VaultSettings($this->container, null, $this->clock);
        $burst = min((int) $grant['rate_burst'], (int) $settings->get('vault_server_burst_max'));
        $perHour = min((int) $grant['rate_per_hour'], (int) $settings->get('vault_server_rate_max'));
        if (! (new RateLimiter($this->container, null, $this->clock))->consume(self::bucket($consumer, $ref->entryId), $burst, $perHour / 3600)) {
            return $this->refuse($cols, 'rate_limited');
        }
        $key = $this->currentKeyRow($db, $entry);
        if ($key === null) {
            return $this->refuse($cols, 'not_shared');
        }
        try {
            $dek = $this->provider->openSealedDek((string) base64_decode((string) $key['sealed_dek'], true), new DekContext('entry', $ref->entryId, (int) $entry['key_epoch'], ServerPrincipal::ID));
        } catch (ServerKeyUnavailable) {
            return $this->refuse($cols, 'server_key_unavailable');
        }
        // Wiped here, not in field(): while field() runs this frame holds the string too, and sodium_memzero only zeroes
        // a string nothing else holds.
        try {
            $value = $this->field($entry, $dek, $ref);
        } finally {
            sodium_memzero($dek);
        }
        if ($value === null) {
            return $this->refuse($cols, 'not_found');
        }
        $this->noticeFirstRead($db, $consumer, $entry);
        AuditModel::of($this->container, $this->clock)->record('server_read', ['actor_kind' => 'server'] + $cols);
        return [$value, null];
    }

    // Inside the lock, before this read's audit row: with no earlier server_read of the entry by the consumer
    // (vault_audit_object_idx), the owner is emailed after the commit. Best effort: an owner with no live Kanboard user
    // gets nothing, and a failed notice never fails the read.
    private function noticeFirstRead(VaultDb $db, string $consumer, array $entry): void
    {
        $entryId = (int) $entry['id'];
        if ($db->fetchOne("SELECT 1 AS seen FROM vault_audit WHERE action = 'server_read' AND object_id = ? AND consumer = ? LIMIT 1", [$entryId, $consumer]) !== null) {
            return;
        }
        $owner = $db->fetchOne('SELECT live_user_id FROM vault_principals WHERE user_id = ?', [(int) $entry['owner_id']]);
        if ($owner === null || $owner['live_user_id'] === null) {
            return;
        }
        $userId = (int) $owner['live_user_id'];
        (new VaultLock($this->container))->afterCommit(fn () => Notifier::of($this->container)->serverFirstRead($userId, $consumer, $entryId));
    }

    // Steps 3–7 (step 5 only with a consumer). 'field' is the ref's field in its stored form once step 6 has it.
    /** @return array{reason: ?string, entry: ?array, grant: ?array, field: ?string} */
    private function gate(VaultDb $db, SecretRef $ref, ?string $consumer): array
    {
        $out = ['reason' => null, 'entry' => null, 'grant' => null, 'field' => null];
        $out['entry'] = $db->fetchOne('SELECT * FROM vault_entries WHERE id = ?', [$ref->entryId]);
        if ($out['entry'] === null) {
            return ['reason' => 'not_found'] + $out;
        }
        $out['grant'] = $db->fetchOne(
            "SELECT * FROM vault_grants WHERE subject_type = 'entry' AND subject_id = ? AND grantee_id = ? AND (expires_at IS NULL OR expires_at > ?)",
            [$ref->entryId, ServerPrincipal::ID, (int) ($this->clock)()]
        );
        if ($out['grant'] === null) {
            return ['reason' => $this->lastServerAction($db, $ref->entryId) === 'server_revoke' ? 'revoked' : 'not_shared'] + $out;
        }
        if ($consumer !== null && ! (ServerGrant::validConsumer($consumer) && in_array($consumer, ServerGrant::decodeList($out['grant']['consumers']), true))) {
            return ['reason' => 'consumer_not_allowed'] + $out;
        }
        try {
            $out['field'] = $this->storedField($ref);
        } catch (ServerKeyUnavailable) {
            return ['reason' => 'server_key_unavailable'] + $out;
        }
        if (! in_array($out['field'], ServerGrant::decodeList($out['grant']['fields']), true)) {
            return ['reason' => 'field_not_allowed'] + $out;
        }
        if ((new RecipientResolver($this->container))->chainGone($db, 'entry', $out['entry'])) {
            return ['reason' => 'orphaned'] + $out;
        }
        return $out;
    }

    // R1: a top-level name as is; a custom name as its MAC, the field-MAC key opened only for it and wiped after.
    private function storedField(SecretRef $ref): string
    {
        if ($ref->isTopLevel()) {
            return $ref->field;
        }
        $key = $this->provider->openFieldMacKey();
        try {
            return ServerGrant::macField($key, $ref->field);
        } finally {
            sodium_memzero($key);
        }
    }

    private function lastServerAction(VaultDb $db, int $entryId): ?string
    {
        $row = $db->fetchOne(
            "SELECT action FROM vault_audit WHERE action IN ('server_grant', 'server_revoke') AND object_type = 'entry' AND object_id = ? ORDER BY id DESC LIMIT 1",
            [$entryId]
        );
        return $row === null ? null : (string) $row['action'];
    }

    // The -1 key row at the entry's key_epoch; a missing or stale one is null.
    private function currentKeyRow(VaultDb $db, array $entry): ?array
    {
        $key = $db->fetchOne(
            "SELECT key_epoch, sealed_dek FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND principal_id = ?",
            [(int) $entry['id'], ServerPrincipal::ID]
        );
        return $key !== null && (int) $key['key_epoch'] === (int) $entry['key_epoch'] ? $key : null;
    }

    // Step 11: the one field, or null when the entry doesn't decrypt or hasn't got it. Wipes the plaintext JSON and every
    // decrypted value but the one returned (the caller wipes the DEK).
    private function field(array $entry, #[\SensitiveParameter] string $dek, SecretRef $ref): ?string
    {
        $json = '';
        try {
            $nonce = base64_decode((string) $entry['nonce'], true);
            $ct = base64_decode((string) $entry['ciphertext'], true);
            if ((int) $entry['crypto_v'] !== ObjectStore::CRYPTO_V || $nonce === false || $ct === false) {
                return null;
            }
            $json = Aead::open($nonce, $ct, $dek, ObjectStore::ad('entry', (int) $entry['id'], (int) $entry['owner_id'], (int) $entry['key_epoch']));
            $payload = EntryPayload::decode($json);
        } catch (CryptoException|JsonException|SodiumException|ValueError) {
            return null;
        } finally {
            sodium_memzero($json);
        }
        $value = null;
        if ($ref->isTopLevel()) {
            $value = $payload[$ref->field] ?? null;
        } else {
            foreach (is_array($payload['fields'] ?? null) ? $payload['fields'] : [] as $f) {
                if (is_array($f) && ($f['name'] ?? null) === $ref->field) {
                    $value = $f['value'] ?? null;
                    break;
                }
            }
            unset($f); // the loop's copy would keep the field's array shared and stop the wipe below
        }
        $value = is_string($value) ? $value : null;
        self::wipe($payload);
        return $value;
    }

    // Zeroes every string leaf nothing else holds. A leaf the caller still has ($value) is shared, so it is only
    // dropped from the array, not zeroed.
    private static function wipe(#[\SensitiveParameter] array &$a): void
    {
        foreach ($a as &$v) {
            if (is_string($v)) {
                sodium_memzero($v);
            } elseif (is_array($v)) {
                self::wipe($v);
            }
        }
        unset($v);
    }

    // Inside the lock: the refusal's audit (R3: rate_limited aggregated) and the closure's result.
    /** @return array{0: null, 1: string} */
    private function refuse(array $cols, string $reason): array
    {
        if ($reason === 'rate_limited') {
            (new RateLimitAudit($this->container, $this->clock))->noteServerRead($cols);
        } else {
            $this->denied($cols, $reason);
        }
        return [null, $reason];
    }

    private function denied(array $cols, string $reason): void
    {
        AuditModel::of($this->container, $this->clock)->record('server_read_denied', ['reason' => $reason, 'actor_kind' => 'server'] + $cols);
    }

    // The key file is read before the vault lock is taken (no file I/O under the global lock). A failure here is left
    // to the locked steps, which report it in order.
    private function warm(): void
    {
        if ($this->provider instanceof FileKeyProvider) {
            try {
                $this->provider->warm();
            } catch (ServerKeyUnavailable) {
            }
        }
    }
}
