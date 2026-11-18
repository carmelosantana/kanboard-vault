<?php
require_once 'tests/units/Base.php';

use Kanboard\Plugin\Vault\Model\ArgonSlots;
use KanboardTests\units\Base;

class ArgonSlotsTest extends Base
{
    private string $dir;
    private array $held = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->dir = sys_get_temp_dir().'/vault-slots-'.bin2hex(random_bytes(6)).'/vault';
    }

    protected function tearDown(): void
    {
        foreach ($this->held as $slot) {
            $slot->release();
        }
        foreach (glob($this->dir.'/*.lock') ?: [] as $f) {
            unlink($f);
        }
        @rmdir($this->dir);
        @rmdir(dirname($this->dir));
        parent::tearDown();
    }

    private function slots(): ArgonSlots
    {
        return new ArgonSlots($this->container, $this->dir);
    }

    public function testDefaultDirectoryIsUnderDataDir(): void
    {
        $this->assertSame(DATA_DIR.'/vault', (new ArgonSlots($this->container))->directory());
    }

    public function testCreatesPrivateDirectoryAndNamedLockFiles(): void
    {
        $this->held[] = $slot = $this->slots()->acquire(42);
        $this->assertNotNull($slot);
        $this->assertSame(0700, fileperms($this->dir) & 0777);
        $this->assertFileExists($this->dir.'/p-42.lock');
        $this->assertFileExists($this->dir.'/slot-0.lock');
    }

    public function testSecondAcquireSamePrincipalIsNull(): void
    {
        $slots = $this->slots();
        $this->held[] = $first = $slots->acquire(1);
        $this->assertNotNull($first);
        // A separate instance, as a second request would have.
        $other = $this->slots();
        $this->assertNull($other->acquire(1));
        $this->assertSame(ArgonSlots::BUSY_PRINCIPAL, $other->lastBusy());
        // The failed attempt didn't take a global slot: three other principals still fit.
        foreach ([2, 3, 4] as $p) {
            $this->held[] = $s = $slots->acquire($p);
            $this->assertNotNull($s, "principal $p");
        }
    }

    public function testFifthGlobalAcquireIsNull(): void
    {
        $slots = $this->slots();
        foreach ([1, 2, 3, 4] as $p) {
            $this->held[] = $s = $slots->acquire($p);
            $this->assertNotNull($s, "principal $p");
        }
        $this->assertNull($slots->acquire(5));
        $this->assertSame(ArgonSlots::BUSY_GLOBAL, $slots->lastBusy());
        // The failed attempt released principal 5's own lock.
        $this->held[0]->release();
        $this->held[] = $s = $slots->acquire(5);
        $this->assertNotNull($s);
        $this->assertNull($slots->lastBusy());
    }

    public function testReleaseFreesBothLocksAndIsIdempotent(): void
    {
        $slots = $this->slots();
        $slot = $slots->acquire(9);
        $slot->release();
        $slot->release();
        $this->held[] = $again = $slots->acquire(9);
        $this->assertNotNull($again);
    }

    public function testDroppedSlotReleases(): void
    {
        $slots = $this->slots();
        $slot = $slots->acquire(9);
        unset($slot);
        $this->held[] = $again = $slots->acquire(9);
        $this->assertNotNull($again);
    }

    public function testRejectsNonPositivePrincipal(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->slots()->acquire(0);
    }

    // R16(c): lock files are opened close-on-exec. Otherwise a child process started while a slot is held
    // (proc_open, exec, mail) inherits the descriptor, and its copy keeps the flock after the request dies.
    // A forked worker takes a slot, starts a long-lived child and is killed without releasing anything.
    public function testLockFilesAreNotInheritedByChildProcesses(): void
    {
        if (! function_exists('pcntl_fork') || ! function_exists('posix_kill')) {
            $this->markTestSkipped('pcntl and posix are needed for the inheritance test');
        }
        $ready = $this->dir.'.ready';
        $pid = pcntl_fork();
        $this->assertNotSame(-1, $pid, 'fork failed');
        if ($pid === 0) {
            $slot = $this->slots()->acquire(7);
            // The grandchild outlives this worker; its stdio goes nowhere.
            $child = proc_open(['sleep', '5'], [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
            file_put_contents($ready, ($slot !== null && is_resource($child)) ? (string) proc_get_status($child)['pid'] : 'E');
            posix_kill(getmypid(), SIGKILL);
        }
        pcntl_waitpid($pid, $status);
        $grandchild = (int) @file_get_contents($ready);
        @unlink($ready);
        $this->assertGreaterThan(0, $grandchild, 'the worker took a slot and started a child');
        try {
            $slots = $this->slots();
            $this->held[] = $again = $slots->acquire(7);
            $this->assertNotNull($again, 'an inherited descriptor still holds the lock: '.var_export($slots->lastBusy(), true));
        } finally {
            posix_kill($grandchild, SIGKILL);
        }
    }
}
