<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;

// R39: rate_limited is audited once per bucket per window, not once per refused request, so a guessing run can't
// flood vault_audit. The audit bucket is (the principal whose throttle refused, or none for a per-IP bucket; the
// truncated client IP). Refusals are tallied in vault_rate under "audit:rl:<user id or 0>:<ip_trunc>", tokens =
// the count and updated_at = the window's start. A window's row (target_user_id, ip_trunc, count) is written once
// the window has closed: by the next refusal on the same bucket, or by flush(), which the purge runs. vault_audit
// stays append-only: nothing is written there until the count is final.
class RateLimitAudit extends Base
{
    public const WINDOW = 600;
    private const PREFIX = 'audit:rl:';

    private Closure $clock;

    public function __construct($container, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    // One refusal. $targetUserId is the principal the refusing bucket belongs to (null for a per-IP bucket).
    public function note(?int $targetUserId, string $ip): void
    {
        $ipTrunc = (new ClientIp($this->container))->truncate($ip);
        $bucket = self::PREFIX.(($targetUserId ?? 0) > 0 ? $targetUserId : 0).':'.$ipTrunc;
        $this->lock()->exclusive(function () use ($bucket): void {
            $db = $this->vdb();
            $now = $this->now();
            $row = $db->fetchOne('SELECT tokens, updated_at FROM vault_rate WHERE bucket = ?', [$bucket]);
            if ($row !== null && $now < (int) $row['updated_at'] + self::WINDOW) {
                $db->execute('UPDATE vault_rate SET tokens = tokens + 1 WHERE bucket = ?', [$bucket]);
                return;
            }
            if ($row !== null) {
                $this->write($db, $bucket, (int) round((float) $row['tokens']));
                $db->execute('DELETE FROM vault_rate WHERE bucket = ?', [$bucket]);
            }
            $db->insert('vault_rate', ['bucket' => $bucket, 'tokens' => 1, 'updated_at' => $now], null);
        });
    }

    // Writes the row of every window that has closed. Returns how many rows were written.
    public function flush(): int
    {
        return $this->lock()->exclusive(function (): int {
            $db = $this->vdb();
            $rows = $db->fetchAll(
                'SELECT bucket, tokens FROM vault_rate WHERE bucket LIKE ? AND updated_at <= ? ORDER BY updated_at, bucket',
                [self::PREFIX.'%', $this->now() - self::WINDOW]
            );
            foreach ($rows as $r) {
                $this->write($db, (string) $r['bucket'], (int) round((float) $r['tokens']));
                $db->execute('DELETE FROM vault_rate WHERE bucket = ?', [$r['bucket']]);
            }
            return count($rows);
        });
    }

    // Inside the caller's exclusive transaction. A target whose user is gone is recorded as NULL (its FK).
    private function write(VaultDb $db, string $bucket, int $count): void
    {
        $parts = explode(':', $bucket, 4);
        $target = (int) ($parts[2] ?? 0);
        $ipTrunc = (string) ($parts[3] ?? '');
        if ($target > 0 && $db->fetchOne('SELECT id FROM users WHERE id = ?', [$target]) === null) {
            $target = 0;
        }
        AuditModel::of($this->container, $this->clock)->record('rate_limited', [
            'target_user_id' => $target > 0 ? $target : null,
            'ip_trunc' => $ipTrunc === '' ? null : $ipTrunc,
            'count' => max(1, $count),
        ]);
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
