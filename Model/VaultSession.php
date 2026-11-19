<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Encoding;

// Unlocked vault sessions, split between the DB and a cookie (spec: Unlocked sessions).
// vault_sessions holds enc_sk = XChaCha20-Poly1305(sk, session_key) under
// AD enc("session", crypto_v, sid_hash, user_id, created_at), keyed by sid_hash = hex BLAKE2b-256(PHP session id).
// session_key lives only in an HttpOnly cookie. A DB row alone, or a cookie alone, opens nothing.
// API (JSON-RPC) requests never touch vault_sessions.
class VaultSession extends Base
{
    public const COOKIE = '__Host-kb_vault';
    public const DEV_COOKIE = 'kb_vault_dev';
    public const DEV_OPT_IN = 'VAULT_DEV_INSECURE_LOCALHOST';
    public const IDLE_TIMEOUT = 900;
    public const ABSOLUTE_TIMEOUT = 28800;
    public const CRYPTO_V = 1;
    private const KEY_BYTES = 32;

    private CookieJar $jar;
    private Closure $sessionId;
    private Closure $clock;

    public function __construct($container, ?CookieJar $jar = null, ?callable $sessionId = null, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->jar = $jar ?? new CookieJar();
        $this->sessionId = $sessionId !== null ? Closure::fromCallable($sessionId) : static fn (): string => (string) session_id();
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    // HTTPS, or plain HTTP in the opted-in dev stack. Anything else must not unlock.
    public function transportAllowed(): bool
    {
        return $this->request->isHTTPS() || $this->isInsecureDev();
    }

    public function cookieName(): string
    {
        return ! $this->request->isHTTPS() && $this->isInsecureDev() ? self::DEV_COOKIE : self::COOKIE;
    }

    // A JSON-RPC request. Kanboard's API middleware marks the session scope 'API' before it authenticates
    // (user and app credentials alike); jsonrpc.php as the entry script is checked too.
    public function isApiRequest(): bool
    {
        return session_get('scope') === 'API'
            || basename($this->request->getServerVariable('SCRIPT_NAME')) === 'jsonrpc.php';
    }

    // hex BLAKE2b-256 of the PHP session id; null without a UI session.
    public function sidHash(): ?string
    {
        if ($this->isApiRequest()) {
            return null;
        }
        $sid = ($this->sessionId)();
        return $sid === '' ? null : bin2hex(sodium_crypto_generichash($sid, '', 32));
    }

    // The idle timeout, capped by the effective Kanboard session lifetime.
    public function idleTimeout(): int
    {
        return self::effectiveIdleTimeout((int) SESSION_DURATION, (int) ini_get('session.gc_maxlifetime'));
    }

    // Kanboard's session handler keeps a session for SESSION_DURATION, or for gc_maxlifetime (PHP's default
    // 1440 s) when SESSION_DURATION is 0. The vault idle timeout never outlives it.
    public static function effectiveIdleTimeout(int $sessionDuration, int $gcMaxLifetime): int
    {
        $lifetime = $sessionDuration > 0 ? $sessionDuration : ($gcMaxLifetime > 0 ? $gcMaxLifetime : 1440);
        return min(self::IDLE_TIMEOUT, $lifetime);
    }

    // Stores sk for this UI session and sets the cookie. Returns the raw 32-byte session_key.
    // The caller keeps (and wipes) its own copy of sk. $nextSk (a rotation resumed at unlock) is stored as
    // enc_sk_next under the same session_key and AD, as start does for the initiating session.
    public function create(int $userId, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] ?string $nextSk = null): string
    {
        if (! $this->transportAllowed()) {
            throw new VaultException('https_required');
        }
        if (strlen($sk) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES || $userId <= 0 || ($nextSk !== null && strlen($nextSk) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES)) {
            throw new InvalidArgumentException('Vault session: bad secret key or user');
        }
        $sidHash = $this->sidHash();
        if ($sidHash === null) {
            throw new VaultException('unlock_failed');
        }
        $now = $this->now();
        $sessionKey = random_bytes(self::KEY_BYTES);
        $box = Aead::seal($sk, $sessionKey, self::ad($sidHash, $userId, $now));
        $row = [
            'sid_hash' => $sidHash,
            'user_id' => $userId,
            'nonce' => base64_encode($box['nonce']),
            'enc_sk' => base64_encode($box['ct']),
            'created_at' => $now,
            'last_used_at' => $now,
            'idle_expires_at' => min($now + $this->idleTimeout(), $now + self::ABSOLUTE_TIMEOUT),
            'abs_expires_at' => $now + self::ABSOLUTE_TIMEOUT,
        ];
        if ($nextSk !== null) {
            $next = Aead::seal($nextSk, $sessionKey, self::ad($sidHash, $userId, $now));
            $row['nonce_next'] = base64_encode($next['nonce']);
            $row['enc_sk_next'] = base64_encode($next['ct']);
        }
        $this->vaultLock()->exclusive(function () use ($row): void {
            $db = new VaultDb($this->container);
            $db->execute('DELETE FROM vault_sessions WHERE sid_hash = ?', [$row['sid_hash']]);
            $db->insert('vault_sessions', $row, null);
        });
        $this->setCookie(sodium_bin2base64($sessionKey, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING));
        return $sessionKey;
    }

    // The unlocked sk for the current user in this UI session, or null. The caller wipes it after use. While a
    // key rotation is in progress the row also holds enc_sk_next (sk2), and that is the key returned: sk2 opens
    // both key generations (the old one through the rotation bridge), sk1 only the old one.
    public function secretKey(): ?string
    {
        $sidHash = $this->sidHash();
        $userId = (int) $this->userSession->getId();
        if ($sidHash === null || $userId <= 0) {
            return null;
        }
        $db = new VaultDb($this->container);
        $row = $db->fetchOne('SELECT * FROM vault_sessions WHERE sid_hash = ?', [$sidHash]);
        if ($row === null) {
            return null;
        }
        $rowUser = (int) $row['user_id'];
        if ($rowUser !== $userId) {
            // This PHP session now belongs to someone else: the old unlock dies with it.
            $this->lock($rowUser, $sidHash);
            return null;
        }
        if (! $this->userIsActive($userId)) {
            $this->lock($userId);
            return null;
        }
        $now = $this->now();
        if ($now >= (int) $row['idle_expires_at'] || $now >= (int) $row['abs_expires_at']) {
            $this->lock($userId, $sidHash);
            return null;
        }
        $sessionKey = $this->cookieKey();
        if ($sessionKey === null) {
            return null;
        }
        try {
            $nonce = base64_decode((string) $row['nonce'], true);
            $ct = base64_decode((string) $row['enc_sk'], true);
            if ($nonce === false || $ct === false) {
                return null;
            }
            $ad = self::ad($sidHash, $userId, (int) $row['created_at']);
            $sk = Aead::open($nonce, $ct, $sessionKey, $ad);
            if ($row['enc_sk_next'] !== null && $row['enc_sk_next'] !== '') {
                try {
                    $next = $this->openNext($row, $sessionKey, $ad);
                } finally {
                    sodium_memzero($sk);
                }
                if ($next === null) {
                    return null;
                }
                $sk = $next;
            }
        } catch (CryptoException) {
            return null;
        } finally {
            sodium_memzero($sessionKey);
        }
        $db->execute(
            'UPDATE vault_sessions SET last_used_at = ?, idle_expires_at = ? WHERE sid_hash = ? AND user_id = ?',
            [$now, min($now + $this->idleTimeout(), (int) $row['abs_expires_at']), $sidHash, $userId]
        );
        return $sk;
    }

    // Key rotation, start (spec): inside the caller's exclusive transaction, adds enc_sk_next = sk2 under this UI
    // session's session_key (the same AD as enc_sk) to the current user's row. Only when the cookie's key opens
    // that row to exactly $sk1. Returns the row's sid_hash, or null when there is no such session (for example
    // a CLI rotation), in which case nothing is written. Takes no lock itself (R18).
    public function stageNextKey(VaultDb $db, int $userId, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] string $sk2): ?string
    {
        $sidHash = $this->sidHash();
        if ($sidHash === null || (int) $this->userSession->getId() !== $userId) {
            return null;
        }
        $row = $db->fetchOne('SELECT * FROM vault_sessions WHERE sid_hash = ? AND user_id = ?', [$sidHash, $userId]);
        $sessionKey = $row === null ? null : $this->cookieKey();
        if ($sessionKey === null) {
            return null;
        }
        $current = '';
        try {
            $nonce = base64_decode((string) $row['nonce'], true);
            $ct = base64_decode((string) $row['enc_sk'], true);
            if ($nonce === false || $ct === false) {
                return null;
            }
            $ad = self::ad($sidHash, $userId, (int) $row['created_at']);
            $current = Aead::open($nonce, $ct, $sessionKey, $ad);
            if (! hash_equals($current, $sk1)) {
                return null;
            }
            $box = Aead::seal($sk2, $sessionKey, $ad);
        } catch (CryptoException) {
            return null;
        } finally {
            sodium_memzero($sessionKey);
            sodium_memzero($current);
        }
        $db->execute(
            'UPDATE vault_sessions SET nonce_next = ?, enc_sk_next = ? WHERE sid_hash = ? AND user_id = ?',
            [base64_encode($box['nonce']), base64_encode($box['ct']), $sidHash, $userId]
        );
        return $sidHash;
    }

    // Deletes the user's vault sessions (only $sidHash's when given). Clears the cookie when the
    // current session is among them.
    public function lock(int $userId, ?string $sidHash = null): void
    {
        $this->vaultLock()->exclusive(function () use ($userId, $sidHash): void {
            $db = new VaultDb($this->container);
            if ($sidHash === null) {
                $db->execute('DELETE FROM vault_sessions WHERE user_id = ?', [$userId]);
            } else {
                $db->execute('DELETE FROM vault_sessions WHERE user_id = ? AND sid_hash = ?', [$userId, $sidHash]);
            }
        });
        $current = $this->sidHash();
        if ($current !== null && (int) $this->userSession->getId() === $userId && ($sidHash === null || hash_equals($current, $sidHash))) {
            $this->clearCookie();
        }
    }

    public static function ad(string $sidHash, int $userId, int $createdAt): string
    {
        return Encoding::enc('session', self::CRYPTO_V, $sidHash, $userId, $createdAt);
    }

    private function openNext(array $row, #[\SensitiveParameter] string $sessionKey, string $ad): ?string
    {
        $nonce = base64_decode((string) $row['nonce_next'], true);
        $ct = base64_decode((string) $row['enc_sk_next'], true);
        if ($nonce === false || $ct === false) {
            return null;
        }
        return Aead::open($nonce, $ct, $sessionKey, $ad);
    }

    private function cookieKey(): ?string
    {
        $value = $this->request->getCookie($this->cookieName());
        if (! is_string($value) || $value === '') {
            return null;
        }
        try {
            $key = sodium_base642bin($value, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        } catch (\SodiumException) {
            return null;
        }
        return strlen($key) === self::KEY_BYTES ? $key : null;
    }

    private function setCookie(#[\SensitiveParameter] string $value): void
    {
        $this->jar->set($this->cookieName(), $value, $this->cookieOptions(0));
    }

    private function clearCookie(): void
    {
        $this->jar->set($this->cookieName(), '', $this->cookieOptions(1));
    }

    // __Host- needs Secure, Path=/ and no Domain. The localhost dev cookie can't be Secure over HTTP.
    private function cookieOptions(int $expires): array
    {
        return [
            'expires' => $expires,
            'path' => '/',
            'secure' => $this->cookieName() === self::COOKIE,
            'httponly' => true,
            'samesite' => 'Strict',
        ];
    }

    // R20: the plain-HTTP dev exception needs BOTH the explicit opt-in VAULT_DEV_INSECURE_LOCALHOST=1 and an
    // exact localhost Host. Host alone fails open behind a reverse proxy or tunnel whose origin is localhost.
    private function isInsecureDev(): bool
    {
        return getenv(self::DEV_OPT_IN) === '1' && $this->isLocalhost();
    }

    private function isLocalhost(): bool
    {
        $host = strtolower($this->request->getServerVariable('HTTP_HOST'));
        return preg_replace('/:\d+$/D', '', $host) === 'localhost';
    }

    private function userIsActive(int $userId): bool
    {
        $row = (new VaultDb($this->container))->fetchOne('SELECT is_active FROM users WHERE id = ?', [$userId]);
        return $row !== null && (int) $row['is_active'] === 1;
    }

    private function vaultLock(): VaultLock
    {
        return new VaultLock($this->container);
    }

    private function now(): int
    {
        return (int) ($this->clock)();
    }
}
