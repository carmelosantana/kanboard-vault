<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;

// Passphrase unlock (spec: Unlocked sessions, Throttling). Order of work (R15):
//   transport check → the principal's Argon2 slot (busy: 429 / busy_global: 503) → per-principal back-off →
//   per-IP failure bucket → Argon2 → unwrap and public-key check → record the outcome → KDF upgrade → session.
// Every failed guess, whatever the cause, is the one generic VaultException('unlock_failed'); each runs the
// same Argon2 work so timing doesn't separate them either.
//
// Key rotation, crash recovery (spec): while the principal has a vault_rotations row its old wraps are gone, so
// the wrap tried is its pending passphrase wrap of sk2 (checked against new_pk). After it opens, the bridge gives
// sk1, both keys are checked (RotationService::resume) and the session is created with both keys. The rotation then
// runs on for at most ROTATION_BATCHES sweep batches after the Argon2 slot is released (R32/R33); what's left, or a
// crash, leaves it where it stopped, for later requests (Housekeeping) or the next unlock.
class UnlockService extends Base
{
    public const IP_FAILURES = 30;
    public const IP_WINDOW = 600;
    // R32: sweep batches a rotation gets at unlock, after the slot is released; the rest runs on later requests.
    public const ROTATION_BATCHES = 10;

    private ArgonSlots $slots;
    private Closure $argon2;
    private VaultSession $session;
    private RateLimiter $limiter;
    private Closure $clock;
    private RotationService $rotation;
    private RecoveryService $recovery;
    private int $rotationBatches;

    public function __construct($container, ?ArgonSlots $slots = null, ?callable $argon2 = null, ?VaultSession $session = null, ?RateLimiter $limiter = null, ?callable $clock = null, ?RotationService $rotation = null, ?RecoveryService $recovery = null, int $rotationBatches = self::ROTATION_BATCHES)
    {
        $this->rotationBatches = max(1, $rotationBatches);
        parent::__construct($container);
        $this->slots = $slots ?? new ArgonSlots($container);
        $this->argon2 = Closure::fromCallable($argon2 ?? [Kdf::class, 'argon2id']);
        $this->session = $session ?? new VaultSession($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
        $this->limiter = $limiter ?? new RateLimiter($container, null, $this->clock);
        $this->rotation = $rotation ?? new RotationService($container, $this->slots, $this->argon2, $this->clock, $this->session);
        $this->recovery = $recovery ?? new RecoveryService($container, $this->slots, $this->argon2, $this->clock, $this->rotation);
    }

    public static function userBucket(int $userId): string
    {
        return 'unlock:user:'.$userId;
    }

    public static function ipBucket(string $ip): string
    {
        return 'unlock:ip:'.bin2hex(sodium_crypto_generichash($ip === '' ? 'unknown' : $ip, '', 16));
    }

    // Returns the raw 32-byte session_key (also sent as the vault cookie).
    public function unlock(int $userId, #[\SensitiveParameter] string $passphrase, string $ip, #[\SensitiveParameter] ?array $prf = null): string
    {
        if (! $this->session->transportAllowed()) {
            throw new VaultException('https_required');
        }
        if ($userId <= 0) {
            throw new VaultException('unlock_failed');
        }
        $slot = $this->slots->acquire($userId);
        if ($slot === null) {
            throw new VaultException($this->slots->lastBusy() === ArgonSlots::BUSY_GLOBAL ? 'busy_global' : 'busy');
        }
        $sk = '';
        $guess = null;
        $streak = 0;
        $keys = null;
        try {
            if ($this->limiter->backoffSeconds(self::userBucket($userId)) > 0) {
                $this->noteRateLimited($userId, $ip);
                throw new VaultException('rate_limited');
            }
            $ipBucket = self::ipBucket($ip);
            if (! $this->limiter->consume($ipBucket, self::IP_FAILURES, self::IP_FAILURES / self::IP_WINDOW)) {
                $this->noteRateLimited(null, $ip);
                throw new VaultException('rate_limited');
            }

            $wrap = $this->loadPassphraseWrap($userId, $prf);
            $sk = $this->open($wrap, $passphrase);
            if ($sk === null) {
                $guess = new FailedGuess($this->container, $this->limiter, $this->clock);
                $streak = $guess->record($userId, self::userBucket($userId), $ip);
                throw new VaultException('unlock_failed');
            }

            $this->recordSuccess($userId, $ipBucket, $ip);
            $this->upgradeKdf($wrap, $sk, $passphrase);
            [$sessionKey, $keys] = empty($wrap['resume']) ? $this->openSession($userId, $sk, $passphrase) : $this->resumeRotation($userId, $sk);
        } finally {
            if (is_string($sk)) {
                sodium_memzero($sk);
            }
            $slot->release();
            // R39: the five-failure email goes once the slot is free.
            $guess?->notifyIfDue($userId, $streak);
        }
        if ($keys !== null) {
            $this->continueRotation($userId, $keys);
        }
        return $sessionKey;
    }

    // R32/R33: a rotation the unlock resumed or started runs on here, after the Argon2 slot is released, for at
    // most $rotationBatches sweep batches; the rest is left for later requests (Housekeeping). The unlock has
    // succeeded, so a failure is logged (the exception class only) and the rotation stays pending.
    private function continueRotation(int $userId, #[\SensitiveParameter] array $keys): void
    {
        try {
            $this->rotation->advance($userId, $keys['sk1'], $keys['sk2'], $this->rotationBatches);
        } catch (\Throwable $e) {
            $this->logger->warning('Vault: key rotation for user '.$userId.' could not complete at unlock and stays pending ('.get_class($e).')');
        } finally {
            sodium_memzero($keys['sk1']);
            sodium_memzero($keys['sk2']);
        }
    }

    // R39: a refusal is audited per bucket and window (RateLimitAudit), never failing the refusal itself.
    private function noteRateLimited(?int $targetUserId, string $ip): void
    {
        try {
            (new RateLimitAudit($this->container, $this->clock))->note($targetUserId, $ip);
        } catch (\Throwable $e) {
            $this->logger->warning('Vault: a rate-limit refusal could not be audited ('.get_class($e).')');
        }
    }

    // R33: once resume has verified sk2 (and, through the bridge, sk1) the unlock succeeds. The session holds sk1
    // and sk2 as the initiating session does (enc_sk, enc_sk_next), so it serves sk2 and finish switches it over.
    // Returns [session_key, {sk1, sk2}]; the caller continues the rotation outside the slot and wipes both keys.
    private function resumeRotation(int $userId, #[\SensitiveParameter] string $sk2): array
    {
        try {
            $keys = $this->rotation->resume($userId, $sk2);
        } catch (VaultException) {
            throw new VaultException('unlock_failed');
        }
        try {
            return [$this->session->create($userId, $keys['sk1'], $keys['sk2']), $keys];
        } catch (\Throwable $e) {
            sodium_memzero($keys['sk1']);
            sodium_memzero($keys['sk2']);
            throw $e;
        }
    }

    // Recovery-policy housekeeping (RecoveryService::reconcileAtUnlock): it may add the org wrap, or start a queued
    // rotation, in which case the session holds both keys and the rotation continues as at resume (R33). The
    // unlock has already succeeded, so a failure here is logged (the class only) and never fails it.
    // Returns [session_key, {sk1, sk2} or null].
    private function openSession(int $userId, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] string $passphrase): array
    {
        $sk2 = null;
        try {
            $sk2 = $this->recovery->reconcileAtUnlock($userId, $sk, $passphrase);
        } catch (\Throwable $e) {
            $this->logger->warning('Vault: recovery policy housekeeping for user '.$userId.' failed at unlock ('.get_class($e).')');
        }
        if ($sk2 === null) {
            return [$this->session->create($userId, $sk), null];
        }
        try {
            return [$this->session->create($userId, $sk, $sk2), ['sk1' => $sk, 'sk2' => $sk2]];
        } catch (\Throwable $e) {
            sodium_memzero($sk2);
            throw $e;
        }
    }

    // The wrap to try, or null when there is none to try (unknown, disabled or unenrolled user, or a PRF
    // unlock, which needs hardware-key wraps that don't exist yet). Null still costs one Argon2 run.
    private function loadPassphraseWrap(int $userId, ?array $prf): ?array
    {
        if ($prf !== null) {
            return null;
        }
        $db = new VaultDb($this->container);
        $principal = $db->fetchOne(
            'SELECT p.public_key, p.key_gen FROM vault_principals p JOIN users u ON u.id = p.user_id WHERE p.user_id = ? AND u.is_active = 1',
            [$userId]
        );
        if ($principal === null) {
            return null;
        }
        $rotation = $db->fetchOne('SELECT new_pk FROM vault_rotations WHERE user_id = ?', [$userId]);
        if ($rotation !== null) {
            // Mid-rotation: only sk2's pending wrap (key_gen + 1), checked against new_pk, and only to resume.
            $wrap = $db->fetchOne(
                "SELECT * FROM vault_wraps WHERE user_id = ? AND method = 'passphrase' AND status = 'pending' AND key_gen = ? ORDER BY id LIMIT 1",
                [$userId, (int) $principal['key_gen'] + 1]
            );
            if ($wrap === null) {
                return null;
            }
            $wrap['public_key'] = $rotation['new_pk'];
            $wrap['resume'] = true;
            return $wrap;
        }
        $wrap = $db->fetchOne(
            "SELECT * FROM vault_wraps WHERE user_id = ? AND method = 'passphrase' AND status = 'active' AND key_gen = ? ORDER BY id LIMIT 1",
            [$userId, (int) $principal['key_gen']]
        );
        if ($wrap === null) {
            return null;
        }
        $wrap['public_key'] = $principal['public_key'];
        return $wrap;
    }

    // sk, or null for any failure. Crypto error labels never leave this method (R12).
    private function open(?array $wrap, #[\SensitiveParameter] string $passphrase): ?string
    {
        $ikm = $kek = '';
        try {
            $salt = $wrap === null ? false : base64_decode((string) $wrap['kdf_salt'], true);
            $pk = $wrap === null ? false : base64_decode((string) $wrap['public_key'], true);
            if ($salt === false || $pk === false || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
                // Nothing to open: burn the same Argon2 work as a real attempt.
                ($this->argon2)($passphrase, random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES), Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM);
                return null;
            }
            $ikm = ($this->argon2)($passphrase, $salt, (int) $wrap['kdf_ops'], (int) $wrap['kdf_mem']);
            $kek = Kdf::kek($ikm, 'passphrase');
            return Wraps::unwrap(self::wrapRow($wrap), $kek, $pk);
        } catch (CryptoException) {
            return null;
        } finally {
            sodium_memzero($ikm);
            sodium_memzero($kek);
        }
    }

    // The failure count before this success is kept for the banner; the back-off resets and the IP
    // token spent on this attempt goes back. The unlock is audited in the same transaction.
    private function recordSuccess(int $userId, string $ipBucket, string $ip): void
    {
        (new VaultLock($this->container))->exclusive(function () use ($userId, $ipBucket, $ip): void {
            $db = new VaultDb($this->container);
            // The banner shows the consecutive-failure streak (passphrase and recovery code), as the email counts it.
            $failures = FailedGuess::streak($db, $userId);
            FailedGuess::resetStreak($db, $userId);
            $db->execute('DELETE FROM vault_rate WHERE bucket = ?', [PrincipalModel::noticeBucket($userId)]);
            if ($failures > 0) {
                $db->insert('vault_rate', ['bucket' => PrincipalModel::noticeBucket($userId), 'tokens' => $failures, 'updated_at' => $this->now()], null);
            }
            $this->limiter->recordSuccess(self::userBucket($userId));
            $this->limiter->refund($ipBucket, self::IP_FAILURES, self::IP_FAILURES / self::IP_WINDOW);
            $ipTrunc = (new ClientIp($this->container))->truncate($ip);
            AuditModel::of($this->container, $this->clock)->record('unlock', [
                'actor_user_id' => $userId,
                'ip_trunc' => $ipTrunc === '' ? null : $ipTrunc,
                'ua_family' => UaFamily::fromRequest($this->request),
            ]);
        });
    }

    // Re-derives a wrap below the default KDF parameters, in place: same row id (so the same AD), new salt.
    private function upgradeKdf(array $wrap, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] string $passphrase): void
    {
        $ops = (int) $wrap['kdf_ops'];
        $mem = (int) $wrap['kdf_mem'];
        if ($ops >= Kdf::DEFAULT_OPS && $mem >= Kdf::DEFAULT_MEM) {
            return;
        }
        $ops = max($ops, Kdf::DEFAULT_OPS);
        $mem = max($mem, Kdf::DEFAULT_MEM);
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $ikm = $kek = '';
        try {
            $ikm = ($this->argon2)($passphrase, $salt, $ops, $mem);
            $kek = Kdf::kek($ikm, 'passphrase');
            $wrapId = (int) $wrap['id'];
            $userId = (int) $wrap['user_id'];
            $new = Wraps::wrap($sk, $kek, $userId, 'passphrase', '', $wrapId);
            (new VaultLock($this->container))->exclusive(function () use ($new, $wrap, $wrapId, $salt, $ops, $mem): void {
                // Only if the row is still the one we opened; otherwise someone changed it and theirs stands.
                (new VaultDb($this->container))->execute(
                    'UPDATE vault_wraps SET kdf_salt = ?, kdf_ops = ?, kdf_mem = ?, nonce = ?, wrapped_sk = ? WHERE id = ? AND nonce = ? AND wrapped_sk = ?',
                    [base64_encode($salt), $ops, $mem, $new['nonce'], $new['wrapped_sk'], $wrapId, $wrap['nonce'], $wrap['wrapped_sk']]
                );
            });
        } finally {
            sodium_memzero($ikm);
            sodium_memzero($kek);
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

    private function now(): int
    {
        return (int) ($this->clock)();
    }
}
