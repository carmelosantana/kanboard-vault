<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use Kanboard\Core\Base;
use PDO;

// Admin settings (spec: Admin settings), stored in Kanboard's settings table under vault_*. Reads and writes go
// through VaultDb (R13), so they can run inside the vault lock and always see the current row (Kanboard's own
// ConfigModel caches per request). Every change audits policy_change. The recovery policy has one write path,
// RecoveryService::setPolicy, because lowering it must delete wraps in the same transaction; set() routes there.
//
// Kanboard's settings form saves whatever keys it is posted, so an admin can write a vault_* row without coming
// through here. Reads therefore validate too: a stored value that doesn't parse reads as the default, and the
// wraps a policy doesn't allow are also pruned at the next unlock (RecoveryService::reconcileAtUnlock).
//
// The org public key is not a setting: it lives on the vault_meta lock row, written only by vault:org-keygen,
// so the settings form can't swap in a key whose secret someone else holds.
class VaultSettings extends Base
{
    public const POLICY = 'vault_recovery_policy';
    public const POLICY_NONE = 'none';
    public const POLICY_CODE = 'code';
    public const POLICY_CODE_ORG = 'code_org';
    // Rank: lowering means moving to a lower rank.
    public const POLICIES = [self::POLICY_NONE => 0, self::POLICY_CODE => 1, self::POLICY_CODE_ORG => 2];
    public const SHARE_EXPIRIES = [3600, 86400, 604800];

    public const DEFAULTS = [
        self::POLICY => self::POLICY_NONE,
        'vault_hw_required' => 0,
        'vault_idle_timeout' => 15,             // minutes, 5–60
        'vault_share_max_expiry' => 604800,     // seconds: 1 h, 1 d or 7 d
        'vault_reveal_limit' => 20,             // share reveals per client IP per 10 min
        'vault_agent_cap_max' => 60,            // the hard maximum of an agent's reads per hour
        'vault_audit_retention_days' => 365,
        'vault_trusted_proxy_cidrs' => '',
    ];
    private const INT_RANGES = [
        'vault_hw_required' => [0, 1],
        'vault_idle_timeout' => [5, 60],
        'vault_reveal_limit' => [1, 1000],
        'vault_agent_cap_max' => [1, 10000],
        'vault_audit_retention_days' => [1, 3650],
    ];

    private Closure $audit;
    private Closure $clock;

    // $audit is called as ($action, $columns) after a change commits; T10 wires it to the audit log.
    public function __construct($container, ?callable $audit = null, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->audit = $audit !== null ? Closure::fromCallable($audit) : static function (string $action, array $cols): void {};
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    // The typed value: int for numeric keys, string otherwise. A missing or invalid stored value is the default.
    public function get(string $key): mixed
    {
        self::checkKey($key);
        $row = $this->vdb()->fetchOne('SELECT value FROM settings WHERE '.$this->optionColumn().' = ?', [$key]);
        if ($row === null) {
            return self::DEFAULTS[$key];
        }
        try {
            return self::typed($key, self::normalize($key, $row['value']));
        } catch (VaultException) {
            return self::DEFAULTS[$key];
        }
    }

    public function set(string $key, mixed $value, int $actorId): void
    {
        self::checkKey($key);
        $stored = self::normalize($key, $value);
        if ($key === self::POLICY) {
            (new RecoveryService($this->container, null, null, $this->clock, null, $this->audit))->setPolicy($stored, $actorId);
            return;
        }
        (new VaultLock($this->container))->exclusive(fn () => $this->write($this->vdb(), $key, $stored, $actorId));
        $this->changed($actorId);
    }

    // Writes one validated value inside the caller's exclusive transaction. For RecoveryService.
    public function write(VaultDb $db, string $key, string $value, int $actorId): void
    {
        self::checkKey($key);
        $col = $this->optionColumn();
        $now = (int) ($this->clock)();
        if ($db->fetchOne('SELECT value FROM settings WHERE '.$col.' = ?', [$key]) === null) {
            $db->execute('INSERT INTO settings ('.$col.', value, changed_by, changed_on) VALUES (?, ?, ?, ?)', [$key, $value, $actorId, $now]);
        } else {
            $db->execute('UPDATE settings SET value = ?, changed_by = ?, changed_on = ? WHERE '.$col.' = ?', [$value, $actorId, $now, $key]);
        }
    }

    // After a committed change: audit it, and drop Kanboard's per-request config cache so ConfigModel sees it.
    public function changed(int $actorId): void
    {
        if (isset($this->container['memoryCache'])) {
            $this->memoryCache->flush();
        }
        ($this->audit)('policy_change', ['actor_user_id' => $actorId > 0 ? $actorId : null]);
    }

    // The org public key (raw 32 bytes) from the vault_meta row, or null when vault:org-keygen hasn't run.
    public function orgPublicKey(): ?string
    {
        $row = $this->vdb()->fetchOne('SELECT org_pk FROM vault_meta WHERE id = 1');
        $pk = $row === null || $row['org_pk'] === null ? false : base64_decode((string) $row['org_pk'], true);
        return $pk === false || strlen($pk) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES ? null : $pk;
    }

    // payload_invalid for a value the key doesn't accept; the canonical string to store otherwise.
    public static function normalize(string $key, mixed $value): string
    {
        self::checkKey($key);
        if (! is_scalar($value)) {
            throw new VaultException('payload_invalid');
        }
        $value = trim((string) $value);
        if ($key === self::POLICY) {
            if (! isset(self::POLICIES[$value])) {
                throw new VaultException('payload_invalid');
            }
            return $value;
        }
        if ($key === 'vault_share_max_expiry') {
            if (! ctype_digit($value) || ! in_array((int) $value, self::SHARE_EXPIRIES, true)) {
                throw new VaultException('payload_invalid');
            }
            return $value;
        }
        if ($key === 'vault_trusted_proxy_cidrs') {
            $out = [];
            foreach (preg_split('/[\s,]+/', $value, -1, PREG_SPLIT_NO_EMPTY) as $cidr) {
                if (! self::validCidr($cidr)) {
                    throw new VaultException('payload_invalid');
                }
                $out[] = $cidr;
            }
            return implode(',', $out);
        }
        [$min, $max] = self::INT_RANGES[$key];
        if (! preg_match('/^\d{1,9}$/D', $value) || (int) $value < $min || (int) $value > $max) {
            throw new VaultException('payload_invalid');
        }
        return (string) (int) $value;
    }

    private static function typed(string $key, string $value): mixed
    {
        return is_int(self::DEFAULTS[$key]) ? (int) $value : $value;
    }

    private static function validCidr(string $cidr): bool
    {
        $parts = explode('/', $cidr);
        if (count($parts) > 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
            return false;
        }
        if (count($parts) === 1) {
            return true;
        }
        $max = str_contains($parts[0], ':') ? 128 : 32;
        return ctype_digit($parts[1]) && (int) $parts[1] <= $max;
    }

    private static function checkKey(string $key): void
    {
        if (! array_key_exists($key, self::DEFAULTS)) {
            throw new InvalidArgumentException('Vault: unknown setting');
        }
    }

    // "option" is a reserved word in MySQL.
    private function optionColumn(): string
    {
        return $this->db->getConnection()->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql' ? '`option`' : '"option"';
    }

    private function vdb(): VaultDb
    {
        return new VaultDb($this->container);
    }
}
