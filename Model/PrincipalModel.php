<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use PDOException;
use RuntimeException;

// Vault principals (spec: Principals and wraps): an X25519 keypair per enrolled user, with sk only in wraps.
// Human enrolment creates the principal and its 'passphrase' wrap in one exclusive transaction: the wrap
// row is inserted first, then sealed with its own id in the AD (R10).
class PrincipalModel extends Base
{
    public const MIN_PASSPHRASE_CHARS = 14;
    // Consecutive failed unlocks after which the user is told at the next unlock (banner; email later).
    public const NOTIFY_AFTER = 5;

    private ArgonSlots $slots;
    private Closure $argon2;
    private Closure $clock;
    private ?RotationService $rotation;

    public function __construct($container, ?ArgonSlots $slots = null, ?callable $argon2 = null, ?callable $clock = null, ?RotationService $rotation = null)
    {
        parent::__construct($container);
        $this->slots = $slots ?? new ArgonSlots($container);
        $this->argon2 = Closure::fromCallable($argon2 ?? [Kdf::class, 'argon2id']);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
        $this->rotation = $rotation;
    }

    // A passphrase change is a key rotation trigger (spec: Key rotation). The new passphrase meets the same
    // rules as at enrolment; the current one must open the principal's wrap to $sk (RotationService). Returns
    // RotationService::ROTATED or ::PENDING; both mean the new passphrase is now the one. Throws only when nothing
    // changed. $ip is the client address from ClientIp (R21), for the throttle and the audit.
    public function changePassphrase(int $userId, #[\SensitiveParameter] string $currentPassphrase, #[\SensitiveParameter] string $newPassphrase, #[\SensitiveParameter] string $sk, string $ip): string
    {
        $user = (new VaultDb($this->container))->fetchOne('SELECT username, password, is_active FROM users WHERE id = ?', [$userId]);
        if ($user === null || (int) $user['is_active'] !== 1) {
            throw new VaultException('not_found');
        }
        $this->checkPassphrase($newPassphrase, (string) $user['username'], (string) ($user['password'] ?? ''));
        $rotation = $this->rotation ?? new RotationService($this->container, $this->slots, $this->argon2, $this->clock);
        return $rotation->rotateWithPassphrase($userId, $sk, $currentPassphrase, $newPassphrase, $ip);
    }

    /** @return array{user_id:int,kind:string,public_key:string,key_gen:int,state:string,created_at:int}|null */
    public function get(int $userId): ?array
    {
        $row = (new VaultDb($this->container))->fetchOne(
            'SELECT user_id, kind, public_key, key_gen, state, created_at FROM vault_principals WHERE user_id = ?',
            [$userId]
        );
        if ($row === null) {
            return null;
        }
        return [
            'user_id' => (int) $row['user_id'],
            'kind' => (string) $row['kind'],
            'public_key' => (string) $row['public_key'],
            'key_gen' => (int) $row['key_gen'],
            'state' => (string) $row['state'],
            'created_at' => (int) $row['created_at'],
        ];
    }

    public function enrolHuman(int $userId, #[\SensitiveParameter] string $passphrase): void
    {
        // R72: never while a Steward switch-user session is active (an admin would choose the target's passphrase);
        // before the passphrase checks, the login-hash compare and any Argon2.
        $ip = (new ClientIp($this->container))->resolve($this->request, (new VaultSettings($this->container))->trustedProxies());
        (new SwitchedSessionGuard($this->container, $this->clock))->refuseUnlock($userId, $ip);
        $user = (new VaultDb($this->container))->fetchOne('SELECT username, password, is_active FROM users WHERE id = ?', [$userId]);
        if ($user === null || (int) $user['is_active'] !== 1) {
            throw new RuntimeException('Vault: enrolment needs an active user');
        }
        // An agent never holds a human principal (R47): agents enrol only through the agent path (T16). Generic error.
        if (AgentRoster::of($this->container)->isAgent($userId)) {
            throw new VaultException('enrol_refused');
        }
        $this->checkPassphrase($passphrase, (string) $user['username'], (string) ($user['password'] ?? ''));
        if ($this->get($userId) !== null) {
            throw new VaultException('already_enrolled');
        }

        $slot = $this->slots->acquire($userId);
        if ($slot === null) {
            throw new VaultException($this->slots->lastBusy() === ArgonSlots::BUSY_GLOBAL ? 'busy_global' : 'busy');
        }
        $keypair = $sk = $ikm = $kek = '';
        try {
            $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $ikm = ($this->argon2)($passphrase, $salt, Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM);
            $kek = Kdf::kek($ikm, 'passphrase');
            $keypair = sodium_crypto_box_keypair();
            $sk = sodium_crypto_box_secretkey($keypair);
            $pk = sodium_crypto_box_publickey($keypair);
            $now = $this->now();
            (new VaultLock($this->container))->exclusive(function () use ($userId, $pk, $sk, $kek, $salt, $now): void {
                $db = new VaultDb($this->container);
                try {
                    $db->insert('vault_principals', [
                        'user_id' => $userId,
                        'kind' => 'human',
                        'public_key' => base64_encode($pk),
                        'key_gen' => 1,
                        'state' => 'active',
                        'created_at' => $now,
                        'live_user_id' => $userId,
                    ], null);
                } catch (PDOException) {
                    // Raced by another enrolment of the same user: the primary key says so.
                    throw new VaultException('already_enrolled');
                }
                $wrapId = $db->insert('vault_wraps', [
                    'user_id' => $userId,
                    'method' => 'passphrase',
                    'credential_id' => null,
                    'kdf_salt' => base64_encode($salt),
                    'kdf_ops' => Kdf::DEFAULT_OPS,
                    'kdf_mem' => Kdf::DEFAULT_MEM,
                    'status' => 'active',
                    'key_gen' => 1,
                    'nonce' => '',
                    'wrapped_sk' => '',
                    'crypto_v' => Wraps::CRYPTO_V,
                    'created_at' => $now,
                ]);
                $wrap = Wraps::wrap($sk, $kek, $userId, 'passphrase', '', $wrapId);
                $db->execute('UPDATE vault_wraps SET nonce = ?, wrapped_sk = ? WHERE id = ?', [$wrap['nonce'], $wrap['wrapped_sk'], $wrapId]);
                AuditModel::of($this->container, $this->clock)->record('enroll', ['actor_user_id' => $userId]);
            });
        } finally {
            sodium_memzero($keypair);
            sodium_memzero($sk);
            sodium_memzero($ikm);
            sodium_memzero($kek);
            $slot->release();
        }
    }

    // How many failed unlock attempts came before the user's latest successful unlock (0 if none).
    // The unlock records it, so the page shown after it can warn at NOTIFY_AFTER or more.
    public function failedAttemptsSinceLastUnlock(int $userId): int
    {
        $row = (new VaultDb($this->container))->fetchOne('SELECT tokens FROM vault_rate WHERE bucket = ?', [self::noticeBucket($userId)]);
        return $row === null ? 0 : (int) round((float) $row['tokens']);
    }

    public static function noticeBucket(int $userId): string
    {
        return 'unlock:notice:'.$userId;
    }

    // The enrolment rules for a new passphrase (length, not the username, not the login password), for the
    // recovery flows. not_found for an unknown user.
    public function validateNewPassphrase(int $userId, #[\SensitiveParameter] string $passphrase): void
    {
        $user = (new VaultDb($this->container))->fetchOne('SELECT username, password FROM users WHERE id = ?', [$userId]);
        if ($user === null) {
            throw new VaultException('not_found');
        }
        $this->checkPassphrase($passphrase, (string) $user['username'], (string) ($user['password'] ?? ''));
    }

    private function checkPassphrase(#[\SensitiveParameter] string $passphrase, string $username, #[\SensitiveParameter] string $loginHash): void
    {
        if (mb_strlen($passphrase, 'UTF-8') < self::MIN_PASSPHRASE_CHARS) {
            throw new VaultException('passphrase_weak');
        }
        if (mb_strtolower(trim($passphrase), 'UTF-8') === mb_strtolower(trim($username), 'UTF-8')) {
            throw new VaultException('passphrase_weak');
        }
        if ($loginHash !== '' && password_verify($passphrase, $loginHash)) {
            throw new VaultException('passphrase_reuse');
        }
    }

    private function now(): int
    {
        return (int) ($this->clock)();
    }
}
