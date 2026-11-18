<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use Kanboard\Core\Base;
use PDO;

// Atomic rate state in vault_rate (bucket, tokens, updated_at). Every check and its update run inside
// VaultLock::exclusive, so a read and its write are never separate transactions.
// Bucket keys are opaque; callers keep token buckets and failure counters on distinct keys.
// Statements go straight to PDO: PicoDb's statement handler cancels the connection's transaction on an error
// and turns a duplicate key into a silent false, and neither may happen under the vault lock.
class RateLimiter extends Base
{
    public const FREE_FAILURES = 5;
    public const BACKOFF_BASE = 60;
    public const BACKOFF_CAP = 3600;
    private const MAX_BUCKET_BYTES = 191; // the MySQL VARCHAR(191) key

    private VaultLock $lock;
    private Closure $clock;

    public function __construct($container, ?VaultLock $lock = null, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->lock = $lock ?? new VaultLock($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    // Token bucket: starts full, refills continuously at $refillPerSec up to $capacity.
    public function consume(string $bucket, float $capacity, float $refillPerSec, float $cost = 1.0): bool
    {
        $this->checkBucket($bucket);
        if (! is_finite($capacity) || $capacity <= 0 || ! is_finite($refillPerSec) || $refillPerSec < 0 || ! is_finite($cost) || $cost <= 0) {
            throw new InvalidArgumentException('Rate limit: invalid bucket parameters');
        }

        return $this->lock->exclusive(function () use ($bucket, $capacity, $refillPerSec, $cost): bool {
            $now = $this->now();
            $row = $this->read($bucket);
            if ($row === null) {
                $tokens = $capacity;
            } else {
                // A clock that goes backwards never mints tokens.
                $elapsed = max(0, $now - $row['updated_at']);
                $tokens = min($capacity, $row['tokens'] + $elapsed * $refillPerSec);
            }
            $allowed = $tokens >= $cost;
            if ($allowed) {
                $tokens -= $cost;
            }
            $this->write($bucket, $tokens, $row === null || $now > $row['updated_at'] ? $now : $row['updated_at'], $row !== null);
            return $allowed;
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
            $this->run('DELETE FROM vault_rate WHERE bucket = ?', [$bucket]);
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

    private function pdo(): PDO
    {
        return $this->db->getConnection();
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
        $stmt = $this->run('SELECT tokens, updated_at FROM vault_rate WHERE bucket = ?', [$bucket]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();
        return $row === false ? null : ['tokens' => (float) $row['tokens'], 'updated_at' => (int) $row['updated_at']];
    }

    private function write(string $bucket, float $tokens, int $updatedAt, bool $exists): void
    {
        $sql = $exists
            ? 'UPDATE vault_rate SET tokens = ?, updated_at = ? WHERE bucket = ?'
            : 'INSERT INTO vault_rate (tokens, updated_at, bucket) VALUES (?, ?, ?)';
        $this->run($sql, [$tokens, $updatedAt, $bucket]);
    }

    // Fails loudly whatever the connection's error mode, so a failed write can't be committed as a success.
    private function run(string $sql, array $params): \PDOStatement
    {
        $stmt = $this->pdo()->prepare($sql);
        if ($stmt === false || ! $stmt->execute($params)) {
            throw new \RuntimeException('Rate limit: query failed');
        }
        return $stmt;
    }
}
