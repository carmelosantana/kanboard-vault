<?php
namespace Kanboard\Plugin\Vault\Model;

use InvalidArgumentException;
use Kanboard\Core\Base;
use RuntimeException;

// Caps concurrent Argon2 derivations with non-blocking flocks in DATA_DIR/vault/:
// one per principal (p-<id>.lock; busy → 429) and at most SLOTS per install (slot-N.lock; busy → 503).
// A lock dies with its file handle, so a crashed request never holds a slot.
class ArgonSlots extends Base
{
    public const SLOTS = 4;
    public const BUSY_PRINCIPAL = 'principal';
    public const BUSY_GLOBAL = 'global';

    private string $dir;
    private ?string $lastBusy = null;

    public function __construct($container, ?string $dir = null)
    {
        parent::__construct($container);
        $this->dir = rtrim($dir ?? DATA_DIR.'/vault', '/');
    }

    public function directory(): string
    {
        return $this->dir;
    }

    // Why the last acquire() returned null: BUSY_PRINCIPAL, BUSY_GLOBAL, or null after a success.
    public function lastBusy(): ?string
    {
        return $this->lastBusy;
    }

    public function acquire(int $principalId): ?ArgonSlot
    {
        if ($principalId <= 0) {
            throw new InvalidArgumentException('Argon slots: invalid principal id');
        }
        $this->ensureDirectory();
        $this->lastBusy = null;

        $principal = $this->tryLock($this->dir.'/p-'.$principalId.'.lock');
        if ($principal === null) {
            $this->lastBusy = self::BUSY_PRINCIPAL;
            return null;
        }
        for ($n = 0; $n < self::SLOTS; $n++) {
            $slot = $this->tryLock($this->dir.'/slot-'.$n.'.lock');
            if ($slot !== null) {
                return new ArgonSlot($principal, $slot);
            }
        }
        ArgonSlot::unlock($principal);
        $this->lastBusy = self::BUSY_GLOBAL;
        return null;
    }

    /** @return resource|null */
    private function tryLock(string $path)
    {
        $fh = @fopen($path, 'c');
        if ($fh === false) {
            throw new RuntimeException('Argon slots: cannot open a lock file');
        }
        if (! flock($fh, LOCK_EX | LOCK_NB)) {
            fclose($fh);
            return null;
        }
        return $fh;
    }

    private function ensureDirectory(): void
    {
        if (! is_dir($this->dir) && ! @mkdir($this->dir, 0700, true) && ! is_dir($this->dir)) {
            throw new RuntimeException('Argon slots: cannot create the lock directory');
        }
    }
}
