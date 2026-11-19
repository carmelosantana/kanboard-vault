<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\OrgSecret;
use Kanboard\Plugin\Vault\Crypto\RecoveryCode;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use RuntimeException;
use SodiumException;
use Throwable;
use ValueError;

// Recovery (spec: Recovery): the policy (none | code | code_org), personal recovery codes, the org key and org
// recovery. All SQL inside the vault lock goes through VaultDb (R13).
//
// - A recovery code wrap is a vault_wraps row, method 'recovery', KEK = BLAKE2b(key = the code's 20-byte secret,
//   msg = enc("kek", "recovery")). Using a code is throttled like a passphrase in its own buckets (R15 order:
//   the principal's Argon2 slot, then its back-off, then the per-IP bucket, then the check, then the outcome).
//   The use is one transaction: the code's wrap is re-checked, hardware keys and sessions go, and the rotation's
//   start (which deletes every old wrap, the recovery wrap included, and writes the new passphrase's pending wrap)
//   commits with it. A failure before that commit changes nothing, so the old code stays valid.
// - The org wrap is also a vault_wraps row, method 'org': crypto_box_seal(enc("orgwrap", principal_id, sk), org_pk)
//   in wrapped_sk (no nonce, no KDF). Living in vault_wraps means RotationService::start deletes it with the
//   other wraps; start re-seals it to sk2 when the policy still allows it, and finish activates it.
// - Org recovery and code use run a rotation that keeps only the new passphrase: hardware-key wraps go with
//   every other old wrap and their vault_webauthn rows are deleted (spec: Key rotation).
// - After start commits the change has happened, so the rest of the rotation is contained as at unlock (R33):
//   ROTATED or PENDING, never a failure.
//
// Callers wipe their own copies of secrets (R12); this class wipes its own.
class RecoveryService extends Base
{
    public const NOTICE_ORG_ENABLED = 1;
    public const NOTICE_RECOVERY_RESET = 2;
    public const NOTICE_ORG_RECOVERED = 4;
    public const NOTICES = [
        self::NOTICE_ORG_ENABLED => 'org_enabled',
        self::NOTICE_RECOVERY_RESET => 'recovery_code_reset',
        self::NOTICE_ORG_RECOVERED => 'org_recovered',
    ];
    public const IP_FAILURES = 30;
    public const IP_WINDOW = 600;
    // The wrap methods each policy allows, beyond passphrases and hardware keys.
    private const ALLOWED = [
        VaultSettings::POLICY_NONE => [],
        VaultSettings::POLICY_CODE => ['recovery'],
        VaultSettings::POLICY_CODE_ORG => ['recovery', 'org'],
    ];
    private const POLICY_METHODS = ['recovery', 'org'];
    // vault:org-keygen and vault:org-recover are CLI only (spec), whatever process runs them.
    private const CLI = ['actor_kind' => 'cli', 'via' => 'cli'];

    private ArgonSlots $slots;
    private Closure $argon2;
    private Closure $clock;
    private ?RotationService $rotation;
    private Closure $audit;

    // $audit is called as ($action, $columns) inside the transaction of the change it records; by default it is
    // the audit log (AuditModel::record).
    public function __construct($container, ?ArgonSlots $slots = null, ?callable $argon2 = null, ?callable $clock = null, ?RotationService $rotation = null, ?callable $audit = null)
    {
        parent::__construct($container);
        $this->slots = $slots ?? new ArgonSlots($container);
        $this->argon2 = Closure::fromCallable($argon2 ?? [Kdf::class, 'argon2id']);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
        $this->rotation = $rotation;
        $this->audit = $audit !== null ? Closure::fromCallable($audit) : fn (string $action, array $cols) => AuditModel::of($container, $this->clock)->record($action, $cols);
    }

    public static function userBucket(int $userId): string
    {
        return 'recovery:user:'.$userId;
    }

    public static function ipBucket(string $ip): string
    {
        return 'recovery:ip:'.bin2hex(sodium_crypto_generichash($ip === '' ? 'unknown' : $ip, '', 16));
    }

    // A new recovery code for an unlocked human ($sk is their current key), replacing any old one. Returns the
    // display form, shown once. policy_forbids below "code"; rotation_in_progress while rotating.
    public function createCode(int $userId, #[\SensitiveParameter] string $sk): string
    {
        $code = RecoveryCode::generate();
        $kek = '';
        try {
            $kek = Kdf::kek($code['secret'], 'recovery');
            $this->lock()->exclusive(function () use ($userId, $sk, $kek): void {
                $db = $this->vdb();
                if (! in_array('recovery', self::ALLOWED[$this->settings()->get(VaultSettings::POLICY)], true)) {
                    throw new VaultException('policy_forbids');
                }
                $p = $this->livePrincipal($db, $userId);
                if ($p === null || $p['kind'] !== 'human' || ! self::keyMatches($sk, $p['public_key'])) {
                    throw new VaultException('not_found');
                }
                if ($p['state'] !== 'active') {
                    throw new VaultException('rotation_in_progress');
                }
                $db->execute("DELETE FROM vault_wraps WHERE user_id = ? AND method = 'recovery'", [$userId]);
                // R10: the row first, so its id is in the wrap's AD.
                $wrapId = $db->insert('vault_wraps', [
                    'user_id' => $userId,
                    'method' => 'recovery',
                    'credential_id' => null,
                    'kdf_salt' => null,
                    'kdf_ops' => null,
                    'kdf_mem' => null,
                    'status' => 'active',
                    'key_gen' => $p['key_gen'],
                    'nonce' => '',
                    'wrapped_sk' => '',
                    'crypto_v' => Wraps::CRYPTO_V,
                    'created_at' => $this->now(),
                ]);
                $w = Wraps::wrap($sk, $kek, $userId, 'recovery', '', $wrapId);
                $db->execute('UPDATE vault_wraps SET nonce = ?, wrapped_sk = ? WHERE id = ?', [$w['nonce'], $w['wrapped_sk'], $wrapId]);
                ($this->audit)('recovery_code_create', ['actor_user_id' => $userId]);
            });
            return $code['display'];
        } finally {
            sodium_memzero($code['secret']);
            sodium_memzero($kek);
        }
    }

    // Spec: verify the code, create the new passphrase wrap, delete the recovery wrap, lock every session, then
    // run key rotation. Every failed guess is the one generic unlock_failed. Returns ROTATED or PENDING.
    public function useCode(int $userId, #[\SensitiveParameter] string $code, #[\SensitiveParameter] string $newPassphrase, string $ip): string
    {
        if ($userId <= 0) {
            throw new VaultException('unlock_failed');
        }
        $slot = $this->slots->acquire($userId);
        if ($slot === null) {
            throw new VaultException($this->slots->lastBusy() === ArgonSlots::BUSY_GLOBAL ? 'busy_global' : 'busy');
        }
        $limiter = new RateLimiter($this->container, null, $this->clock);
        $secret = $kek = $sk1 = $sk2 = $ikm = $newKek = '';
        try {
            if ($limiter->backoffSeconds(self::userBucket($userId)) > 0) {
                throw new VaultException('rate_limited');
            }
            $ipBucket = self::ipBucket($ip);
            if (! $limiter->consume($ipBucket, self::IP_FAILURES, self::IP_FAILURES / self::IP_WINDOW)) {
                throw new VaultException('rate_limited');
            }
            $wrap = $this->recoveryWrap($userId);
            try {
                $secret = RecoveryCode::parse($code);
                if ($wrap !== null) {
                    $kek = Kdf::kek($secret, 'recovery');
                    $sk1 = Wraps::unwrap(self::wrapRow($wrap), $kek, $wrap['public_key']);
                }
            } catch (CryptoException) {
                $sk1 = '';
            }
            if ($sk1 === '') {
                // Audited as unlock_failed (the table has no recovery failure) and counted toward the five-failure
                // notice with the unlock failures.
                (new FailedGuess($this->container, $limiter, $this->clock))->record($userId, self::userBucket($userId), $ip);
                throw new VaultException('unlock_failed');
            }
            $limiter->recordSuccess(self::userBucket($userId));
            $limiter->refund($ipBucket, self::IP_FAILURES, self::IP_FAILURES / self::IP_WINDOW);

            // Only a code holder learns whether the new passphrase passes (the check reads the login hash).
            $this->principals()->validateNewPassphrase($userId, $newPassphrase);
            $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $ikm = ($this->argon2)($newPassphrase, $salt, Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM);
            $newKek = Kdf::kek($ikm, 'passphrase');
            $wrapId = (int) $wrap['id'];
            $sk2 = $this->lock()->exclusive(function () use ($userId, $wrapId, $sk1, $newKek, $salt, $ip): string {
                $db = $this->vdb();
                // One use: a concurrent use has already consumed the wrap (its rotation deleted it).
                if ($db->fetchOne("SELECT id FROM vault_wraps WHERE id = ? AND user_id = ? AND method = 'recovery'", [$wrapId, $userId]) === null) {
                    throw new VaultException('unlock_failed');
                }
                $sk2 = $this->replaceFactors($db, $userId, $sk1, $newKek, $salt, []);
                ($this->audit)('recovery_used', ['actor_user_id' => $userId, 'ip_trunc' => (new ClientIp($this->container))->truncate($ip) ?: null]);
                return $sk2;
            });
            return $this->completeContained($userId, $sk1, $sk2);
        } finally {
            sodium_memzero($secret);
            sodium_memzero($kek);
            sodium_memzero($sk1);
            sodium_memzero($sk2);
            sodium_memzero($ikm);
            sodium_memzero($newKek);
            $slot->release();
        }
    }

    // Spec: "Lowering the policy deletes the affected wraps at once, then queues key rotation for every user who
    // had one." Raising it changes no wraps (org wraps are added at each user's next unlock).
    public function setPolicy(string $policy, int $actorId): void
    {
        $policy = VaultSettings::normalize(VaultSettings::POLICY, $policy);
        $settings = $this->settings();
        $this->lock()->exclusive(function () use ($settings, $policy, $actorId): void {
            $db = $this->vdb();
            $settings->write($db, VaultSettings::POLICY, $policy, $actorId);
            $this->pruneMethods($db, self::forbidden($policy), null);
        });
        $settings->changed();
    }

    // vault:org-keygen. Stores only the public key, on the vault_meta lock row, and returns the secret's display
    // form (printed once). org_key_exists unless $replace; replacing deletes every org wrap sealed to the old key
    // and queues a rotation for each user that had one, so the old secret opens nothing written afterwards.
    public function orgKeygen(bool $replace = false): string
    {
        $keypair = sodium_crypto_box_keypair();
        $sk = sodium_crypto_box_secretkey($keypair);
        $pk = sodium_crypto_box_publickey($keypair);
        try {
            $this->lock()->exclusive(function () use ($pk, $replace): void {
                $db = $this->vdb();
                $row = $db->fetchOne('SELECT org_pk FROM vault_meta WHERE id = 1') ?? throw new RuntimeException('Vault: the vault_meta row is missing');
                if ($row['org_pk'] !== null && $row['org_pk'] !== '') {
                    if (! $replace) {
                        throw new VaultException('org_key_exists');
                    }
                    $this->pruneMethods($db, ['org'], null);
                }
                $db->execute('UPDATE vault_meta SET org_pk = ? WHERE id = 1', [base64_encode($pk)]);
                ($this->audit)('policy_change', ['actor_user_id' => null] + self::CLI);
            });
            return OrgSecret::format($sk);
        } finally {
            sodium_memzero($sk);
            sodium_memzero($keypair);
        }
    }

    // vault:org-recover (CLI only). The org secret opens the user's org wrap; a new passphrase is set and the key
    // rotated, removing hardware keys. A rotation left pending is finished first (its org wrap is the pending one,
    // of sk2). recovery_failed for a bad secret, an unknown user, a policy below code_org or no org wrap.
    public function orgRecover(string $username, #[\SensitiveParameter] string $orgSecret, #[\SensitiveParameter] string $newPassphrase): string
    {
        $orgSk = $orgKeypair = $sk1 = $sk2 = $ikm = $kek = '';
        $slot = null;
        try {
            try {
                $orgSk = OrgSecret::parse($orgSecret);
            } catch (CryptoException) {
                throw new VaultException('recovery_failed');
            }
            $settings = $this->settings();
            $orgPk = $settings->orgPublicKey();
            $user = $this->vdb()->fetchOne('SELECT id FROM users WHERE username = ?', [$username]);
            if ($user === null || $orgPk === null || $settings->get(VaultSettings::POLICY) !== VaultSettings::POLICY_CODE_ORG
                || ! self::keyMatches($orgSk, $orgPk)) {
                throw new VaultException('recovery_failed');
            }
            $userId = (int) $user['id'];
            $orgKeypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($orgSk, $orgPk);
            $this->principals()->validateNewPassphrase($userId, $newPassphrase);
            $slot = $this->slots->acquire($userId);
            if ($slot === null) {
                throw new VaultException($this->slots->lastBusy() === ArgonSlots::BUSY_GLOBAL ? 'busy_global' : 'busy');
            }
            $this->finishPendingRotation($userId, $orgKeypair);

            $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
            $ikm = ($this->argon2)($newPassphrase, $salt, Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM);
            $kek = Kdf::kek($ikm, 'passphrase');
            $sk2 = $this->lock()->exclusive(function () use ($userId, $orgKeypair, $kek, $salt, &$sk1): string {
                $db = $this->vdb();
                $sk1 = $this->openOrgWrap($db, $userId, $orgKeypair, false) ?? throw new VaultException('recovery_failed');
                $sk2 = $this->replaceFactors($db, $userId, $sk1, $kek, $salt, self::CLI);
                $db->execute('UPDATE vault_principals SET notices = notices | ? WHERE user_id = ?', [self::NOTICE_ORG_RECOVERED, $userId]);
                ($this->audit)('org_recovery', ['target_user_id' => $userId] + self::CLI);
                return $sk2;
            });
            $result = $this->completeContained($userId, $sk1, $sk2);
            // Spec: the user is notified. After the commit, and contained: the recovery has happened.
            try {
                Notifier::of($this->container)->orgRecovered($userId);
            } catch (Throwable $e) {
                $this->logger->warning('Vault: the org recovery notice could not be sent ('.get_class($e).')');
            }
            return $result;
        } finally {
            sodium_memzero($orgSk);
            sodium_memzero($orgKeypair);
            sodium_memzero($sk1);
            sodium_memzero($sk2);
            sodium_memzero($ikm);
            sodium_memzero($kek);
            $slot?->release();
        }
    }

    // Policy housekeeping after a passphrase unlock opened $sk (the current key), inside the caller's Argon2 slot:
    // wraps the policy no longer allows are deleted and a rotation queued (this also covers a policy row an admin
    // wrote through Kanboard's settings form); a queued rotation is started with the unlocking passphrase as the
    // surviving factor, unless the principal has a hardware or agent wrap, whose ceremony must run it (R30); and
    // under code_org a missing org wrap is added, with the one-time banner. Returns sk2 when a rotation started
    // (the caller creates the session with both keys, completes the rotation and wipes sk2), else null.
    public function reconcileAtUnlock(int $userId, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] string $passphrase): ?string
    {
        $rotate = $this->lock()->exclusive(function () use ($userId, $sk): bool {
            $db = $this->vdb();
            $p = $this->livePrincipal($db, $userId);
            if ($p === null || $p['kind'] !== 'human' || $p['state'] !== 'active' || ! self::keyMatches($sk, $p['public_key'])) {
                return false;
            }
            $settings = $this->settings();
            $policy = $settings->get(VaultSettings::POLICY);
            $pruned = $this->pruneMethods($db, self::forbidden($policy), $userId);
            if ($p['rotate_requested'] || $pruned > 0) {
                return $db->fetchOne("SELECT 1 AS x FROM vault_wraps WHERE user_id = ? AND method IN ('passphrase+prf', 'agent')", [$userId]) === null;
            }
            $orgPk = $settings->orgPublicKey();
            if ($policy === VaultSettings::POLICY_CODE_ORG && $orgPk !== null
                && $db->fetchOne("SELECT 1 AS x FROM vault_wraps WHERE user_id = ? AND method = 'org'", [$userId]) === null) {
                self::insertOrgWrap($db, $userId, $sk, $orgPk, $p['key_gen'], 'active', $this->now());
                $db->execute('UPDATE vault_principals SET notices = notices | ? WHERE user_id = ?', [self::NOTICE_ORG_ENABLED, $userId]);
            }
            return false;
        });
        if (! $rotate) {
            return null;
        }
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $ikm = $kek = '';
        try {
            $ikm = ($this->argon2)($passphrase, $salt, Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM);
            $kek = Kdf::kek($ikm, 'passphrase');
            return $this->rotation()->start($userId, $sk, [self::passphraseFactor($kek, $salt)]);
        } finally {
            sodium_memzero($ikm);
            sodium_memzero($kek);
        }
    }

    // The one-time notices for the user's next page (banner), cleared as they are read.
    /** @return list<string> */
    public function takeNotices(int $userId): array
    {
        return $this->lock()->exclusive(function () use ($userId): array {
            $db = $this->vdb();
            $row = $db->fetchOne('SELECT notices FROM vault_principals WHERE user_id = ?', [$userId]);
            $bits = $row === null ? 0 : (int) $row['notices'];
            if ($bits === 0) {
                return [];
            }
            $db->execute('UPDATE vault_principals SET notices = 0 WHERE user_id = ?', [$userId]);
            $out = [];
            foreach (self::NOTICES as $bit => $name) {
                if ($bits & $bit) {
                    $out[] = $name;
                }
            }
            return $out;
        });
    }

    // An org wrap row, inside the caller's exclusive transaction.
    public static function insertOrgWrap(VaultDb $db, int $userId, #[\SensitiveParameter] string $sk, string $orgPk, int $keyGen, string $status, int $now): void
    {
        $db->insert('vault_wraps', [
            'user_id' => $userId,
            'method' => 'org',
            'credential_id' => null,
            'kdf_salt' => null,
            'kdf_ops' => null,
            'kdf_mem' => null,
            'status' => $status,
            'key_gen' => $keyGen,
            'nonce' => '',
            'wrapped_sk' => base64_encode(Wraps::sealOrg($sk, $userId, $orgPk)),
            'crypto_v' => Wraps::CRYPTO_V,
            'created_at' => $now,
        ]);
    }

    // Inside the caller's exclusive transaction: hardware keys and every session go, and the rotation starts with
    // the new passphrase as the only surviving factor (start deletes every old wrap). Each removed hardware key is
    // an hw_key_remove row ($context: the caller's actor_kind and via). Returns sk2.
    private function replaceFactors(VaultDb $db, int $userId, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] string $kek, string $salt, array $context): string
    {
        $removed = $db->execute('DELETE FROM vault_webauthn WHERE user_id = ?', [$userId]);
        for ($i = 0; $i < $removed; $i++) {
            ($this->audit)('hw_key_remove', ['actor_user_id' => $userId] + $context);
        }
        $db->execute('DELETE FROM vault_sessions WHERE user_id = ?', [$userId]);
        return $this->rotation()->start($userId, $sk1, [self::passphraseFactor($kek, $salt)]);
    }

    private function completeContained(int $userId, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] string $sk2): string
    {
        try {
            $this->rotation()->complete($userId, $sk1, $sk2);
            return RotationService::ROTATED;
        } catch (Throwable $e) {
            $this->logger->warning('Vault: key rotation for user '.$userId.' after recovery could not complete and stays pending ('.get_class($e).')');
            return RotationService::PENDING;
        }
    }

    // A rotation left pending: the org key opens sk2 from the pending org wrap, the bridge gives sk1, and the
    // rotation is completed, so the recovery starts from a settled key. recovery_failed when that can't be done.
    private function finishPendingRotation(int $userId, #[\SensitiveParameter] string $orgKeypair): void
    {
        if ($this->vdb()->fetchOne('SELECT user_id FROM vault_rotations WHERE user_id = ?', [$userId]) === null) {
            return;
        }
        $sk2 = $this->lock()->shared(fn (): ?string => $this->openOrgWrap($this->vdb(), $userId, $orgKeypair, true)) ?? throw new VaultException('recovery_failed');
        $keys = ['sk1' => '', 'sk2' => ''];
        try {
            $keys = $this->rotation()->resume($userId, $sk2);
            $this->rotation()->complete($userId, $keys['sk1'], $keys['sk2']);
        } catch (Throwable $e) {
            $this->logger->warning('Vault: org recovery for user '.$userId.' could not finish the pending rotation ('.get_class($e).')');
            throw new VaultException('recovery_failed');
        } finally {
            sodium_memzero($sk2);
            sodium_memzero($keys['sk1']);
            sodium_memzero($keys['sk2']);
        }
    }

    // The principal's sk from its org wrap: the active wrap at key_gen checked against public_key, or ($pending)
    // the rotation's pending wrap at key_gen + 1 checked against new_pk. Null for any failure.
    private function openOrgWrap(VaultDb $db, int $userId, #[\SensitiveParameter] string $orgKeypair, bool $pending): ?string
    {
        $p = $this->livePrincipal($db, $userId);
        if ($p === null) {
            return null;
        }
        $gen = $p['key_gen'];
        $pk = $p['public_key'];
        if ($pending) {
            $r = $db->fetchOne('SELECT new_pk FROM vault_rotations WHERE user_id = ?', [$userId]);
            $pk = $r === null ? false : base64_decode((string) $r['new_pk'], true);
            $gen++;
        }
        $w = $db->fetchOne(
            "SELECT wrapped_sk FROM vault_wraps WHERE user_id = ? AND method = 'org' AND status = ? AND key_gen = ? ORDER BY id LIMIT 1",
            [$userId, $pending ? 'pending' : 'active', $gen]
        );
        $sealed = $w === null ? false : base64_decode((string) $w['wrapped_sk'], true);
        if ($pk === false || $sealed === false) {
            return null;
        }
        try {
            return Wraps::openOrg($sealed, $orgKeypair, $userId, $pk);
        } catch (CryptoException) {
            return null;
        }
    }

    // The recovery wrap a code would open, with the principal's public key, or null: the policy allows codes, the
    // user is an active human principal that isn't rotating, and it has an active recovery wrap at key_gen.
    private function recoveryWrap(int $userId): ?array
    {
        $db = $this->vdb();
        if (! in_array('recovery', self::ALLOWED[$this->settings()->get(VaultSettings::POLICY)], true)) {
            return null;
        }
        $p = $this->livePrincipal($db, $userId);
        $active = $db->fetchOne('SELECT is_active FROM users WHERE id = ?', [$userId]);
        if ($p === null || $p['kind'] !== 'human' || $p['state'] !== 'active' || $active === null || (int) $active['is_active'] !== 1) {
            return null;
        }
        $w = $db->fetchOne(
            "SELECT * FROM vault_wraps WHERE user_id = ? AND method = 'recovery' AND status = 'active' AND key_gen = ? ORDER BY id LIMIT 1",
            [$userId, $p['key_gen']]
        );
        if ($w === null) {
            return null;
        }
        $w['public_key'] = $p['public_key'];
        return $w;
    }

    // Deletes the given wrap methods (for one user, or everyone) and queues a rotation for every principal that
    // had one. Returns how many principals that was.
    /** @param list<string> $methods */
    private function pruneMethods(VaultDb $db, array $methods, ?int $userId): int
    {
        if ($methods === []) {
            return 0;
        }
        $where = 'method IN ('.RecipientResolver::marks($methods).')'.($userId === null ? '' : ' AND user_id = ?');
        $params = $userId === null ? $methods : array_merge($methods, [$userId]);
        $users = array_map('intval', array_column($db->fetchAll('SELECT DISTINCT user_id FROM vault_wraps WHERE '.$where, $params), 'user_id'));
        if ($users === []) {
            return 0;
        }
        $db->execute('DELETE FROM vault_wraps WHERE '.$where, $params);
        foreach (array_chunk($users, 500) as $chunk) {
            $db->execute('UPDATE vault_principals SET rotate_requested = 1 WHERE user_id IN ('.RecipientResolver::marks($chunk).')', $chunk);
        }
        return count($users);
    }

    /** @return list<string> */
    private static function forbidden(string $policy): array
    {
        return array_values(array_diff(self::POLICY_METHODS, self::ALLOWED[$policy]));
    }

    /** @return array{kind:string,public_key:string,key_gen:int,state:string,rotate_requested:bool}|null public_key raw */
    private function livePrincipal(VaultDb $db, int $userId): ?array
    {
        $row = $db->fetchOne(
            'SELECT kind, public_key, key_gen, state, rotate_requested FROM vault_principals WHERE user_id = ? AND live_user_id IS NOT NULL',
            [$userId]
        );
        $pk = $row === null ? false : base64_decode((string) $row['public_key'], true);
        if ($pk === false || strlen($pk) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            return null;
        }
        return [
            'kind' => (string) $row['kind'],
            'public_key' => $pk,
            'key_gen' => (int) $row['key_gen'],
            'state' => (string) $row['state'],
            'rotate_requested' => (int) $row['rotate_requested'] === 1,
        ];
    }

    private static function passphraseFactor(#[\SensitiveParameter] string $kek, string $salt): array
    {
        return ['method' => 'passphrase', 'kek' => $kek, 'kdf_salt' => $salt, 'kdf_ops' => Kdf::DEFAULT_OPS, 'kdf_mem' => Kdf::DEFAULT_MEM];
    }

    private static function keyMatches(#[\SensitiveParameter] string $sk, string $pk): bool
    {
        try {
            return strlen($sk) === SODIUM_CRYPTO_BOX_SECRETKEYBYTES && hash_equals($pk, sodium_crypto_box_publickey_from_secretkey($sk));
        } catch (SodiumException|ValueError) {
            return false;
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

    private function principals(): PrincipalModel
    {
        return new PrincipalModel($this->container, $this->slots, $this->argon2, $this->clock);
    }

    private function rotation(): RotationService
    {
        return $this->rotation ??= new RotationService($this->container, $this->slots, $this->argon2, $this->clock);
    }

    private function settings(): VaultSettings
    {
        return new VaultSettings($this->container, $this->audit, $this->clock);
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
