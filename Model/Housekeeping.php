<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;
use Throwable;

// Opportunistic work on vault requests, each step best-effort: a failure is logged (the exception class only) and
// never fails the request.
//
//   purge()           Purger::run, at most once a minute (its own throttle), on every vault request (T9 carry).
//   afterUnlock()     drains the user's re-key queue (R28). The unlock itself already ran its bounded rotation step.
//   afterWrite()      continues the user's pending rotation for at most ROTATION_BATCHES sweep batches (R32/R33),
//                     then drains the queue (R28). For the write endpoints (T12 onwards).
//
// The caller fetched $sk with VaultSession::secretKey() before (R18), holds no vault lock and no Argon2 slot, and
// wipes its own copy. Only Rekeyer::drainQueue is used: nothing here re-keys an object that isn't queued (T7).
class Housekeeping extends Base
{
    public const DRAIN_MAX = 50;
    public const ROTATION_BATCHES = UnlockService::ROTATION_BATCHES;

    private Closure $clock;
    private ?RotationService $rotation;

    public function __construct($container, ?callable $clock = null, ?RotationService $rotation = null)
    {
        parent::__construct($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
        $this->rotation = $rotation;
    }

    public function purge(): void
    {
        try {
            (new Purger($this->container))->run($this->now());
        } catch (Throwable $e) {
            $this->logger->warning('Vault: the opportunistic purge failed ('.get_class($e).')');
        }
    }

    public function afterUnlock(int $userId, #[\SensitiveParameter] string $sk): void
    {
        $this->drain($userId, $sk);
    }

    public function afterWrite(int $userId, #[\SensitiveParameter] string $sk): void
    {
        $this->continueRotation($userId, $sk);
        $this->drain($userId, $sk);
    }

    private function drain(int $userId, #[\SensitiveParameter] string $sk): void
    {
        try {
            (new Rekeyer($this->container, $this->clock))->drainQueue($userId, $sk, self::DRAIN_MAX);
        } catch (Throwable $e) {
            $this->logger->warning('Vault: draining the re-key queue failed ('.get_class($e).')');
        }
    }

    // While rotating, the session serves sk2; resume() checks it and opens sk1 through the bridge.
    private function continueRotation(int $userId, #[\SensitiveParameter] string $sk): void
    {
        $rotation = $this->rotation ?? new RotationService($this->container, null, null, $this->clock);
        try {
            if ((new Rekeyer($this->container, $this->clock))->rotation(new VaultDb($this->container), $userId) === null) {
                return;
            }
            $keys = $rotation->resume($userId, $sk);
        } catch (Throwable $e) {
            $this->logger->warning('Vault: a pending key rotation could not resume ('.get_class($e).')');
            return;
        }
        try {
            $rotation->advance($userId, $keys['sk1'], $keys['sk2'], self::ROTATION_BATCHES);
        } catch (Throwable $e) {
            $this->logger->warning('Vault: a pending key rotation stays pending ('.get_class($e).')');
        } finally {
            sodium_memzero($keys['sk1']);
            sodium_memzero($keys['sk2']);
        }
    }

    private function now(): int
    {
        return (int) ($this->clock)();
    }
}
