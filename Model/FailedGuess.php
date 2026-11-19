<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;

// One failed guess at a user's vault secret: a passphrase at unlock or at a passphrase change, or a recovery code
// (spec: Throttling). In one exclusive transaction the failure is counted in the guess's own back-off bucket, added
// to the user's consecutive-failure streak, and audited as unlock_failed.
//
// The streak (R38) is one counter per user, shared by passphrase and recovery-code failures, in its own vault_rate
// row (streakBucket). Any successful unlock or recovery-code use resets it (resetStreak), so a stale back-off bucket
// can neither bring the notice forward nor push the count past the point where it fires. The user is emailed each
// time the streak reaches a multiple of PrincipalModel::NOTIFY_AFTER: the spec says "after 5 consecutive failures,
// the user is notified" and is silent on more, so 10, 15, ... notify again rather than going quiet. record() only
// counts; the caller sends the email with notifyIfDue() once it has released its Argon2 slot (R39), so a slow mail
// server never holds a slot. The email never fails the caller.
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

    public static function streakBucket(int $userId): string
    {
        return 'unlock:streak:'.$userId;
    }

    // The current streak, inside or outside the caller's transaction.
    public static function streak(VaultDb $db, int $userId): int
    {
        $row = $db->fetchOne('SELECT tokens FROM vault_rate WHERE bucket = ?', [self::streakBucket($userId)]);
        return $row === null ? 0 : (int) round((float) $row['tokens']);
    }

    // After a successful unlock or code use, inside the caller's exclusive transaction.
    public static function resetStreak(VaultDb $db, int $userId): void
    {
        $db->execute('DELETE FROM vault_rate WHERE bucket = ?', [self::streakBucket($userId)]);
    }

    // $ip is the client address ('' when there is none), stored truncated. Returns the streak after this failure
    // (0 for an unknown user), for notifyIfDue().
    public function record(int $userId, string $bucket, string $ip): int
    {
        return (new VaultLock($this->container))->exclusive(function () use ($userId, $bucket, $ip): int {
            $this->limiter->recordFailure($bucket);
            $db = new VaultDb($this->container);
            // An unknown user id is still throttled, but has no users row for the audit's foreign key or a notice.
            $known = $db->fetchOne('SELECT id FROM users WHERE id = ?', [$userId]) !== null;
            $ipTrunc = (new ClientIp($this->container))->truncate($ip);
            AuditModel::of($this->container, $this->clock)->record('unlock_failed', [
                'actor_user_id' => $known ? $userId : null,
                'ip_trunc' => $ipTrunc === '' ? null : $ipTrunc,
                'ua_family' => UaFamily::fromRequest($this->request),
            ]);
            if (! $known) {
                return 0;
            }
            $n = self::streak($db, $userId) + 1;
            self::resetStreak($db, $userId);
            $db->insert('vault_rate', ['bucket' => self::streakBucket($userId), 'tokens' => $n, 'updated_at' => (int) ($this->clock)()], null);
            return $n;
        });
    }

    // Emails the user when $streak (from record()) has reached a multiple of NOTIFY_AFTER. Call it after the
    // Argon2 slot is released.
    public function notifyIfDue(int $userId, int $streak): void
    {
        if ($streak > 0 && $streak % PrincipalModel::NOTIFY_AFTER === 0) {
            try {
                Notifier::of($this->container)->unlockFailures($userId);
            } catch (\Throwable $e) {
                $this->logger->warning('Vault: the failed-unlock notice could not be sent ('.get_class($e).')');
            }
        }
    }
}
