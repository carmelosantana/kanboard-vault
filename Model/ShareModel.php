<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use PDO;

// One-time shares, the server's half (spec: One-time shares). The browser (T18) encrypts with AES-256-GCM under a key
// that lives only in the link's #fragment, so the server never sees k, the plaintext or b. It stores the ciphertext,
// iv, salt and two hashes, and never which entry a share came from.
//
// The wire contract with the browser:
//   share_id    128 random bits, 32 lowercase hex characters, made here at reservation.
//   b           the burn capability, 16 random bytes made by the browser, sent at reveal as 32 lowercase hex.
//   id_hash     hex BLAKE2b-256 of the 16 raw bytes of share_id (idHash); the vault_shares key and the audit's share_hash.
//   burn_hash   hex BLAKE2b-256 of the 16 raw bytes of b (burnHash); computed by the browser at create, by the server at
//               reveal, compared with hash_equals.
//   ciphertext  base64 AES-256-GCM output (tag included), at most MAX_CIPHERTEXT bytes; iv base64 of 12 bytes; salt
//               base64 of 16 bytes when there is a passphrase, '' otherwise. The AD is enc("share", 1, share_id,
//               expires_at, has_passphrase), so the reveal returns expires_at and has_passphrase too. Its field types
//               (Encoding::enc): "share" a string; 1 an int64; share_id the 32-character lowercase hex STRING as it is
//               in the link (not its 16 raw bytes); expires_at an int64 (Unix seconds, as reserve() returned it);
//               has_passphrase an int64, 0 or 1. Test/fixtures/enc-vectors.json (made by PHP) pins the bytes, and
//               the browser checks itself against it (Test/js/vault-onetime.test.mjs).
//   create      has_passphrase is sent as the string '0' or '1' and is required; there is no default.
//   key         k without a passphrase; with one, HKDF-SHA256(k ‖ Argon2id(p, salt, t=3, m=64 MiB, p=1, 32 bytes),
//               salt = '', info = "vault/share/v1"). The server never derives it; Assets/js/vault-onetime.js does.
//
//   reserve()   (creator, their sid_hash, 1h|1d|7d): a reservation row holding only id_hash, bound to the creator and
//               their session for RESERVATION_TTL seconds, with the share expiry the AD will carry.
//   finalize()  consumes the reservation once, in one exclusive transaction, and stores the share. The label, if any,
//               is sealed to the creator's public key (crypto_box_seal of enc("share_label", id_hash, label)).
//   reveal()    throttled per client IP first (REVEAL_WINDOW and REVEAL_DAY buckets; a refusal throws rate_limited and
//               is audited per window, R39). Then, in one exclusive transaction (VaultLock: BEGIN IMMEDIATE on SQLite,
//               the vault_meta row FOR UPDATE elsewhere, plus FOR UPDATE on the share row there): find the row by
//               id_hash, check expiry and hash_equals(burn_hash), delete it (exactly one row, or nothing is returned)
//               and audit share_reveal. Every failure is the same null: unknown, malformed, wrong b, expired, revoked,
//               already burned. The id alone can never burn a link. After commit the creator gets the notice (R19).
//   revoke()    the creator deletes an unviewed link by id_hash.
//   listMine()  the creator's live links with their labels opened by sk.
//   Labels and key rotation (R58): while a rotation is in progress a new label is sealed to the rotation's new public
//               key, and every sweep batch re-seals the creator's labels that still open with the old key
//               (resealLabels), so labels survive the rotation and the old key opens none of them afterwards.
//
// Expired rows are removed by the purge (Purger::expiredShares, share_expire audited); expired reservations too.
class ShareModel extends Base
{
    public const EXPIRIES = ['1h' => 3600, '1d' => 86400, '7d' => 604800];
    public const RESERVATION_TTL = 600;
    // "The payload is at most 64 KB": a 64 KiB plaintext plus the 16-byte GCM tag.
    public const MAX_CIPHERTEXT = 65536 + 16;
    public const IV_BYTES = 12;
    public const SALT_BYTES = 16;
    public const LABEL_MAX = 100; // characters
    public const REVEAL_WINDOW = 600;
    public const REVEAL_DAY = 86400;
    public const REVEAL_DAY_LIMIT = 200;
    public const CRYPTO_V = 1;
    public const ID_HASH_PATTERN = '/^[0-9a-f]{64}$/D';
    private const TOKEN_PATTERN = '/^[0-9a-f]{32}$/D';
    private const RAW_BYTES = 16;

    private Closure $clock;
    private ?Closure $hook;

    // $hook is test-only (as RotationService's): called as ($point) in reveal, 'throttled' after the throttle and
    // 'read' right after the share row is read inside the transaction, so a concurrency test can fix an interleaving.
    public function __construct($container, ?callable $clock = null, ?callable $hook = null)
    {
        parent::__construct($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
        $this->hook = $hook !== null ? Closure::fromCallable($hook) : null;
    }

    public static function idHash(string $shareId): string
    {
        return self::hashToken($shareId);
    }

    public static function burnHash(#[\SensitiveParameter] string $burn): string
    {
        return self::hashToken($burn);
    }

    /** @return array{share_id:string, expires_at:int} */
    public function reserve(int $creatorId, string $sidHash, string $expiry): array
    {
        if ($creatorId <= 0 || preg_match(self::ID_HASH_PATTERN, $sidHash) !== 1 || ! isset(self::EXPIRIES[$expiry])) {
            throw new VaultException('payload_invalid');
        }
        $seconds = self::EXPIRIES[$expiry];
        if ($seconds > (int) (new VaultSettings($this->container))->get('vault_share_max_expiry')) {
            throw new VaultException('payload_invalid');
        }
        $shareId = bin2hex(random_bytes(self::RAW_BYTES));
        $now = $this->now();
        $this->vdb()->insert('vault_share_reservations', [
            'id_hash' => self::idHash($shareId),
            'creator_id' => $creatorId,
            'sid_hash' => $sidHash,
            'expires_at' => $now + self::RESERVATION_TTL,
            'share_expires_at' => $now + $seconds,
        ], null);
        return ['share_id' => $shareId, 'expires_at' => $now + $seconds];
    }

    public function finalize(int $creatorId, string $sidHash, array $body): void
    {
        $share = self::validBody($body);
        $idHash = self::idHash($share['share_id']);
        $this->lock()->exclusive(function () use ($creatorId, $sidHash, $share, $idHash): void {
            $db = $this->vdb();
            $now = $this->now();
            $res = $db->fetchOne('SELECT * FROM vault_share_reservations WHERE id_hash = ?', [$idHash]);
            if ($res === null || (int) $res['creator_id'] !== $creatorId || ! hash_equals((string) $res['sid_hash'], $sidHash)
                || (int) $res['expires_at'] <= $now) {
                throw new VaultException('not_found');
            }
            if ($db->execute('DELETE FROM vault_share_reservations WHERE id_hash = ?', [$idHash]) !== 1) {
                throw new VaultException('not_found');
            }
            $db->insert('vault_shares', [
                'id_hash' => $idHash,
                'burn_hash' => $share['burn_hash'],
                'creator_id' => $creatorId,
                'ciphertext' => base64_encode($share['ciphertext']),
                'iv' => base64_encode($share['iv']),
                'salt' => base64_encode($share['salt']),
                'has_passphrase' => $share['has_passphrase'] ? 1 : 0,
                'sealed_label' => $share['label'] === '' ? null : $this->sealLabel($db, $creatorId, $idHash, $share['label']),
                'created_at' => $now,
                'expires_at' => (int) $res['share_expires_at'],
                'crypto_v' => self::CRYPTO_V,
            ], null);
            AuditModel::of($this->container, $this->clock)->record('share_create', ['actor_user_id' => $creatorId, 'share_hash' => $idHash]);
        });
    }

    /** @return array{ciphertext:string, iv:string, salt:string, has_passphrase:bool, expires_at:int}|null */
    public function reveal(string $id, #[\SensitiveParameter] string $burn, string $ip, ?string $uaFamily = null): ?array
    {
        $this->throttle($ip);
        $this->fire('throttled');
        if (preg_match(self::TOKEN_PATTERN, $id) !== 1 || preg_match(self::TOKEN_PATTERN, $burn) !== 1) {
            return null;
        }
        $idHash = self::idHash($id);
        $burnHash = self::burnHash($burn);
        $ipTrunc = (new ClientIp($this->container))->truncate($ip);
        $revealed = $this->lock()->exclusive(function () use ($idHash, $burnHash, $ipTrunc, $uaFamily): ?array {
            $db = $this->vdb();
            // VaultLock already holds the install-wide lock; on MySQL and Postgres the share row is locked as well.
            $forUpdate = $this->db->getConnection()->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite' ? '' : ' FOR UPDATE';
            $row = $db->fetchOne('SELECT * FROM vault_shares WHERE id_hash = ?'.$forUpdate, [$idHash]);
            $this->fire('read');
            if ($row === null || (int) $row['expires_at'] <= $this->now() || ! hash_equals((string) $row['burn_hash'], $burnHash)) {
                return null;
            }
            if ($db->execute('DELETE FROM vault_shares WHERE id_hash = ? AND burn_hash = ?', [$idHash, $burnHash]) !== 1) {
                return null;
            }
            AuditModel::of($this->container, $this->clock)->record('share_reveal', [
                'actor_kind' => 'public',
                'target_user_id' => (int) $row['creator_id'],
                'share_hash' => $idHash,
                'ip_trunc' => $ipTrunc === '' ? null : $ipTrunc,
                'ua_family' => $uaFamily,
            ]);
            return $row;
        });
        if ($revealed === null) {
            return null;
        }
        Notifier::of($this->container)->shareRevealed((int) $revealed['creator_id']);
        return [
            'ciphertext' => (string) $revealed['ciphertext'],
            'iv' => (string) $revealed['iv'],
            'salt' => (string) $revealed['salt'],
            'has_passphrase' => (int) $revealed['has_passphrase'] === 1,
            'expires_at' => (int) $revealed['expires_at'],
        ];
    }

    public function revoke(int $creatorId, string $idHash): void
    {
        if (preg_match(self::ID_HASH_PATTERN, $idHash) !== 1) {
            throw new VaultException('not_found');
        }
        $this->lock()->exclusive(function () use ($creatorId, $idHash): void {
            if ($this->vdb()->execute('DELETE FROM vault_shares WHERE id_hash = ? AND creator_id = ?', [$idHash, $creatorId]) !== 1) {
                throw new VaultException('not_found');
            }
            AuditModel::of($this->container, $this->clock)->record('share_revoke', ['actor_user_id' => $creatorId, 'share_hash' => $idHash]);
        });
    }

    // The creator's live links, newest first: id_hash, the label (null when there is none or it doesn't open for this
    // sk and this link), has_passphrase, created_at and expires_at.
    /** @return list<array{id_hash:string, label:?string, has_passphrase:bool, created_at:int, expires_at:int}> */
    public function listMine(int $creatorId, #[\SensitiveParameter] string $sk): array
    {
        $rows = $this->vdb()->fetchAll(
            'SELECT id_hash, has_passphrase, sealed_label, created_at, expires_at FROM vault_shares WHERE creator_id = ? AND expires_at > ? ORDER BY created_at DESC, id_hash',
            [$creatorId, $this->now()]
        );
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, sodium_crypto_box_publickey_from_secretkey($sk));
        try {
            return array_map(fn (array $r): array => [
                'id_hash' => (string) $r['id_hash'],
                'label' => $r['sealed_label'] === null ? null : self::openLabel((string) $r['sealed_label'], $keypair, (string) $r['id_hash']),
                'has_passphrase' => (int) $r['has_passphrase'] === 1,
                'created_at' => (int) $r['created_at'],
                'expires_at' => (int) $r['expires_at'],
            ], $rows);
        } finally {
            sodium_memzero($keypair);
        }
    }

    private function throttle(string $ip): void
    {
        $bucket = bin2hex(sodium_crypto_generichash($ip === '' ? 'unknown' : $ip, '', 16));
        $limit = (float) (new VaultSettings($this->container))->get('vault_reveal_limit');
        $limiter = new RateLimiter($this->container, null, $this->clock);
        if ($limiter->consume('reveal:ip:'.$bucket, $limit, $limit / self::REVEAL_WINDOW)
            && $limiter->consume('reveal:ipday:'.$bucket, self::REVEAL_DAY_LIMIT, self::REVEAL_DAY_LIMIT / self::REVEAL_DAY)) {
            return;
        }
        try {
            (new RateLimitAudit($this->container, $this->clock))->note(null, $ip);
        } catch (\Throwable $e) {
            $this->logger->warning('Vault: a rate-limit refusal could not be audited ('.get_class($e).')');
        }
        throw new VaultException('rate_limited');
    }

    /** @return array{share_id:string, ciphertext:string, iv:string, salt:string, has_passphrase:bool, burn_hash:string, label:string} */
    private static function validBody(array $body): array
    {
        $str = static function (string $key) use ($body): string {
            $v = $body[$key] ?? '';
            if (! is_string($v)) {
                throw new VaultException('payload_invalid');
            }
            return $v;
        };
        $shareId = $str('share_id');
        $burnHash = $str('burn_hash');
        $hasPassphrase = $body['has_passphrase'] ?? null;
        if (! in_array($hasPassphrase, ['0', '1', 0, 1, true, false], true)) {
            throw new VaultException('payload_invalid');
        }
        $hasPassphrase = $hasPassphrase === '1' || $hasPassphrase === 1 || $hasPassphrase === true;
        $encoded = $str('ciphertext');
        // A base64 string longer than the largest allowed ciphertext's encoding is refused before decoding it.
        if (strlen($encoded) > 4 * intdiv(self::MAX_CIPHERTEXT + 2, 3) + 4) {
            throw new VaultException('payload_too_large');
        }
        $ciphertext = self::b64($encoded);
        if (strlen($ciphertext) > self::MAX_CIPHERTEXT) {
            throw new VaultException('payload_too_large');
        }
        $iv = self::b64($str('iv'));
        $salt = self::b64($str('salt'), true);
        $label = $str('label');
        if (preg_match(self::TOKEN_PATTERN, $shareId) !== 1 || preg_match(self::ID_HASH_PATTERN, $burnHash) !== 1
            || $ciphertext === '' || strlen($iv) !== self::IV_BYTES || strlen($salt) !== ($hasPassphrase ? self::SALT_BYTES : 0)
            || ! mb_check_encoding($label, 'UTF-8') || mb_strlen($label, 'UTF-8') > self::LABEL_MAX) {
            throw new VaultException('payload_invalid');
        }
        return ['share_id' => $shareId, 'ciphertext' => $ciphertext, 'iv' => $iv, 'salt' => $salt, 'has_passphrase' => $hasPassphrase, 'burn_hash' => $burnHash, 'label' => $label];
    }

    // Strict base64; '' only where $emptyOk.
    private static function b64(string $value, bool $emptyOk = false): string
    {
        if ($value === '' && $emptyOk) {
            return '';
        }
        $raw = base64_decode($value, true);
        if ($raw === false || $raw === '' || base64_encode($raw) !== $value) {
            throw new VaultException('payload_invalid');
        }
        return $raw;
    }

    // Sealed to the creator's public key, or to the rotation's new key while a rotation is in progress (R58): a label
    // made between the sweep's last batch and finish would otherwise stay sealed to a key that finish retires.
    // Called inside finalize's exclusive transaction, which orders it against the rotation's start and finish.
    private function sealLabel(VaultDb $db, int $creatorId, string $idHash, string $label): string
    {
        $p = $db->fetchOne('SELECT public_key FROM vault_principals WHERE user_id = ?', [$creatorId]);
        $r = $db->fetchOne('SELECT new_pk FROM vault_rotations WHERE user_id = ?', [$creatorId]);
        $key = $r !== null ? (string) $r['new_pk'] : ($p === null ? '' : (string) $p['public_key']);
        $pk = $p === null ? false : base64_decode($key, true);
        if ($pk === false || strlen($pk) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new VaultException('not_enrolled');
        }
        return self::seal($idHash, $label, $pk);
    }

    private static function seal(string $idHash, string $label, string $pk): string
    {
        return base64_encode(sodium_crypto_box_seal(Encoding::enc('share_label', $idHash, $label), $pk));
    }

    // R58: re-seals the creator's labels that open with sk1 to pk2. RotationService::sweepBatch calls it inside the
    // batch's exclusive transaction, after its bridge check has proven sk1 and pk2. Labels that don't open with sk1
    // (already re-sealed, or none) are left as they are. Returns how many were re-sealed.
    public static function resealLabels(VaultDb $db, int $creatorId, #[\SensitiveParameter] string $sk1, string $pk2): int
    {
        $rows = $db->fetchAll('SELECT id_hash, sealed_label FROM vault_shares WHERE creator_id = ? AND sealed_label IS NOT NULL', [$creatorId]);
        if ($rows === []) {
            return 0;
        }
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk1, sodium_crypto_box_publickey_from_secretkey($sk1));
        $n = 0;
        try {
            foreach ($rows as $row) {
                $idHash = (string) $row['id_hash'];
                $label = self::openLabel((string) $row['sealed_label'], $keypair, $idHash);
                if ($label === null) {
                    continue;
                }
                $db->execute('UPDATE vault_shares SET sealed_label = ? WHERE id_hash = ?', [self::seal($idHash, $label, $pk2), $idHash]);
                $n++;
            }
        } finally {
            sodium_memzero($keypair);
        }
        return $n;
    }

    private static function openLabel(string $sealed, #[\SensitiveParameter] string $keypair, string $idHash): ?string
    {
        $raw = base64_decode($sealed, true);
        if ($raw === false) {
            return null;
        }
        try {
            $plain = Wraps::sealOpen($raw, $keypair, 'label');
            $prefix = Encoding::enc('share_label', $idHash);
            return Wraps::field($plain, $prefix, strlen($plain) - strlen($prefix) - 4, 'label');
        } catch (CryptoException | \ValueError) {
            return null;
        }
    }

    private static function hashToken(#[\SensitiveParameter] string $token): string
    {
        if (preg_match(self::TOKEN_PATTERN, $token) !== 1) {
            throw new InvalidArgumentException('Vault share: not a 128-bit hex token');
        }
        return bin2hex(sodium_crypto_generichash(hex2bin($token), '', 32));
    }

    private function fire(string $point): void
    {
        if ($this->hook !== null) {
            ($this->hook)($point);
        }
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
