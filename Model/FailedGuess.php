<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;

// One failed guess at a user's vault secret: a passphrase at unlock or at a passphrase change, or a recovery code
// (spec: Throttling). In one exclusive transaction the failure is counted in the guess's own back-off bucket and
// audited as unlock_failed. The user is emailed when their consecutive failures reach PrincipalModel::NOTIFY_AFTER,
// counting the unlock and recovery-code buckets together, so recovery-code failures count toward the same five.
// The email goes after the commit, exactly once per streak (a success resets its bucket), and never fails the
// caller (Notifier contains its own errors; this guards against a notifier that throws anyway).
class FailedGuess extends Base
{
    private RateLimiter $limiter;
    private Closure $clock;

    public function __construct($container, RateLimiter $limiter, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->limiter = $limiter;
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    // $ip is the client address ('' when there is none), stored truncated.
    public function record(int $userId, string $bucket, string $ip): void
    {
        $streak = (new VaultLock($this->container))->exclusive(function () use ($userId, $bucket, $ip): int {
            $this->limiter->recordFailure($bucket);
            $db = new VaultDb($this->container);
            // An unknown user id is still throttled, but has no users row for the audit's foreign key.
            $known = $db->fetchOne('SELECT id FROM users WHERE id = ?', [$userId]) !== null;
            $ipTrunc = (new ClientIp($this->container))->truncate($ip);
            AuditModel::of($this->container, $this->clock)->record('unlock_failed', [
                'actor_user_id' => $known ? $userId : null,
                'ip_trunc' => $ipTrunc === '' ? null : $ipTrunc,
            ]);
            $n = 0;
            foreach ([UnlockService::userBucket($userId), RecoveryService::userBucket($userId)] as $b) {
                $row = $db->fetchOne('SELECT tokens FROM vault_rate WHERE bucket = ?', [$b]);
                $n += $row === null ? 0 : (int) round((float) $row['tokens']);
            }
            return $known ? $n : 0;
        });
        if ($streak === PrincipalModel::NOTIFY_AFTER) {
            try {
                Notifier::of($this->container)->unlockFailures($userId);
            } catch (\Throwable $e) {
                $this->logger->warning('Vault: the failed-unlock notice could not be sent ('.get_class($e).')');
            }
        }
    }
}
