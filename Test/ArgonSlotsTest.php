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
}
