<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use Kanboard\Core\Base;

// Atomic rate state in vault_rate (bucket, tokens, updated_at). Every check and its update run inside
// VaultLock::exclusive, so a read and its write are never separate transactions.
// Bucket keys are opaque; callers keep token buckets and failure counters on distinct keys.
// Statements go through VaultDb (raw PDO), never PicoDb, inside the lock.
class RateLimiter extends Base
{
    public const FREE_FAILURES = 5;
    public const BACKOFF_BASE = 60;
    public const BACKOFF_CAP = 3600;
    private const MAX_BUCKET_BYTES = 191; // the MySQL VARCHAR(191) key
    private const EPSILON = 1e-9;

    private VaultLock $lock;
    private VaultDb $vaultDb;
    private Closure $clock;

    public function __construct($container, ?VaultLock $lock = null, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->lock = $lock ?? new VaultLock($container);
        $this->vaultDb = new VaultDb($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    // Token bucket: starts full, refills continuously at $refillPerSec up to $capacity.
    public function consume(string $bucket, float $capacity, float $refillPerSec, float $cost = 1.0): bool
    {
        return $this->settle($bucket, $capacity, $refillPerSec, $cost, function (float $tokens) use ($cost): array {
            // A small tolerance: float sums (and PDO's 14-digit float binding) must not delay a due token.
            if ($tokens + self::EPSILON >= $cost) {
                return [max(0.0, $tokens - $cost), true];
            }
            return [$tokens, false];
        });
    }

    // Gives back tokens spent by consume(), never above $capacity.
    public function refund(string $bucket, float $capacity, float $refillPerSec, float $cost = 1.0): void
    {
        $this->settle($bucket, $capacity, $refillPerSec, $cost, fn (float $tokens): array => [min($capacity, $tokens + $cost), null]);
    }

    // Reads the bucket, refills it to now and writes back what $apply returns, all under the exclusive lock.
    private function settle(string $bucket, float $capacity, float $refillPerSec, float $cost, callable $apply): mixed
    {
        $this->checkBucket($bucket);
        if (! is_finite($capacity) || $capacity <= 0 || ! is_finite($refillPerSec) || $refillPerSec < 0 || ! is_finite($cost) || $cost <= 0) {
            throw new InvalidArgumentException('Rate limit: invalid bucket parameters');
        }

        return $this->lock->exclusive(function () use ($bucket, $capacity, $refillPerSec, $apply): mixed {
            $now = $this->now();
            $row = $this->read($bucket);
            if ($row === null) {
                $tokens = $capacity;
            } else {
                // A clock that goes backwards never mints tokens.
                $elapsed = max(0, $now - $row['updated_at']);
                $tokens = min($capacity, $row['tokens'] + $elapsed * $refillPerSec);
            }
            [$tokens, $result] = $apply($tokens);
            $this->write($bucket, $tokens, $row === null || $now > $row['updated_at'] ? $now : $row['updated_at'], $row !== null);
            return $result;
        });
    }

    // Seconds the caller must still wait before trying again; 0 when free.
    public function backoffSeconds(string $bucket): int
    {
        $this->checkBucket($bucket);
        // A read only: shared, so it may also run inside a caller's shared lock.
        return $this->lock->shared(function () use ($bucket): int {
            $row = $this->read($bucket);
            if ($row === null) {
                return 0;
            }
            $backoff = self::backoffFor((int) $row['tokens']);
            // Clamped, so a clock that goes backwards can't stretch the wait past the back-off itself.
            return max(0, min($backoff, $row['updated_at'] + $backoff - $this->now()));
        });
    }

    // Counts a failure and returns the back-off it starts (0 for the first four).
    public function recordFailure(string $bucket): int
    {
        $this->checkBucket($bucket);
        return $this->lock->exclusive(function () use ($bucket): int {
            $row = $this->read($bucket);
            $failures = ($row === null ? 0 : (int) $row['tokens']) + 1;
            $this->write($bucket, (float) $failures, $this->now(), $row !== null);
            return self::backoffFor($failures);
        });
    }

    public function recordSuccess(string $bucket): void
    {
        $this->checkBucket($bucket);
        $this->lock->exclusive(function () use ($bucket): void {
            $this->vaultDb->execute('DELETE FROM vault_rate WHERE bucket = ?', [$bucket]);
        });
    }

    // 5 failures allowed; the 5th starts a 60 s back-off, doubling per failure, capped at 1 h.
    public static function backoffFor(int $failures): int
    {
        if ($failures < self::FREE_FAILURES) {
            return 0;
        }
        $doublings = min($failures - self::FREE_FAILURES, 6); // 60 * 2^6 already exceeds the cap
        return min(self::BACKOFF_CAP, self::BACKOFF_BASE * (2 ** $doublings));
    }

    private function now(): int
    {
        return (int) ($this->clock)();
    }

    private function checkBucket(string $bucket): void
    {
        if ($bucket === '' || strlen($bucket) > self::MAX_BUCKET_BYTES) {
            throw new InvalidArgumentException('Rate limit: bucket key must be 1 to 191 bytes');
        }
    }

    /** @return array{tokens: float, updated_at: int}|null */
    private function read(string $bucket): ?array
    {
        $row = $this->vaultDb->fetchOne('SELECT tokens, updated_at FROM vault_rate WHERE bucket = ?', [$bucket]);
        return $row === null ? null : ['tokens' => (float) $row['tokens'], 'updated_at' => (int) $row['updated_at']];
    }

    private function write(string $bucket, float $tokens, int $updatedAt, bool $exists): void
    {
        if ($exists) {
            $this->vaultDb->execute('UPDATE vault_rate SET tokens = ?, updated_at = ? WHERE bucket = ?', [$tokens, $updatedAt, $bucket]);
        } else {
            $this->vaultDb->insert('vault_rate', ['bucket' => $bucket, 'tokens' => $tokens, 'updated_at' => $updatedAt], null);
        }
    }
}
