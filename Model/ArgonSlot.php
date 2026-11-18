<?php
namespace Kanboard\Plugin\Vault\Model;

// A held Argon2 slot: the principal's lock plus one global slot. Release it in a finally block;
// dropping the object releases it too.
final class ArgonSlot
{
    /** @var resource|null */
    private $principal;
    /** @var resource|null */
    private $slot;

    /** @param resource $principal @param resource $slot */
    public function __construct($principal, $slot)
    {
        $this->principal = $principal;
        $this->slot = $slot;
    }

    public function release(): void
    {
        // Idempotent.
        if ($this->slot !== null) {
            self::unlock($this->slot);
            $this->slot = null;
        }
        if ($this->principal !== null) {
            self::unlock($this->principal);
            $this->principal = null;
        }
    }

    public function __destruct()
    {
        $this->release();
    }

    /** @param resource $fh */
    public static function unlock($fh): void
    {
        flock($fh, LOCK_UN);
        fclose($fh);
    }
}
