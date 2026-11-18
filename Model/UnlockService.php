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
class UnlockService extends Base
{
    public const IP_FAILURES = 30;
    public const IP_WINDOW = 600;

    private ArgonSlots $slots;
    private Closure $argon2;
    private VaultSession $session;
    private RateLimiter $limiter;
    private Closure $clock;

    public function __construct($container, ?ArgonSlots $slots = null, ?callable $argon2 = null, ?VaultSession $session = null, ?RateLimiter $limiter = null, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->slots = $slots ?? new ArgonSlots($container);
        $this->argon2 = Closure::fromCallable($argon2 ?? [Kdf::class, 'argon2id']);
        $this->session = $session ?? new VaultSession($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
        $this->limiter = $limiter ?? new RateLimiter($container, null, $this->clock);
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
    public function unlock(int $userId, string $passphrase, string $ip, ?array $prf = null): string
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
        try {
            if ($this->limiter->backoffSeconds(self::userBucket($userId)) > 0) {
                throw new VaultException('rate_limited');
            }
            $ipBucket = self::ipBucket($ip);
            if (! $this->limiter->consume($ipBucket, self::IP_FAILURES, self::IP_FAILURES / self::IP_WINDOW)) {
                throw new VaultException('rate_limited');
            }

            $wrap = $this->loadPassphraseWrap($userId, $prf);
            $sk = $this->open($wrap, $passphrase);
            if ($sk === null) {
                $this->limiter->recordFailure(self::userBucket($userId));
                throw new VaultException('unlock_failed');
            }

            $this->recordSuccess($userId, $ipBucket);
            $this->upgradeKdf($wrap, $sk, $passphrase);
            return $this->session->create($userId, $sk);
        } finally {
            if (is_string($sk)) {
                sodium_memzero($sk);
            }
            $slot->release();
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
    private function open(?array $wrap, string $passphrase): ?string
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
    // token spent on this attempt goes back.
    private function recordSuccess(int $userId, string $ipBucket): void
    {
        (new VaultLock($this->container))->exclusive(function () use ($userId, $ipBucket): void {
            $db = new VaultDb($this->container);
            $row = $db->fetchOne('SELECT tokens FROM vault_rate WHERE bucket = ?', [self::userBucket($userId)]);
            $failures = $row === null ? 0 : (int) round((float) $row['tokens']);
            $db->execute('DELETE FROM vault_rate WHERE bucket = ?', [PrincipalModel::noticeBucket($userId)]);
            if ($failures > 0) {
                $db->insert('vault_rate', ['bucket' => PrincipalModel::noticeBucket($userId), 'tokens' => $failures, 'updated_at' => $this->now()], null);
            }
            $this->limiter->recordSuccess(self::userBucket($userId));
            $this->limiter->refund($ipBucket, self::IP_FAILURES, self::IP_FAILURES / self::IP_WINDOW);
        });
    }

    // Re-derives a wrap below the default KDF parameters, in place: same row id (so the same AD), new salt.
    private function upgradeKdf(array $wrap, string $sk, string $passphrase): void
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
