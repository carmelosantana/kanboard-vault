<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';

use Kanboard\Plugin\Vault\Model\Purger;
use Kanboard\Plugin\Vault\Model\RateLimitAudit;
use KanboardTests\units\Base;

// R39: rate_limited is aggregated, one audit row per bucket per window, not one per refused request. The bucket is
// (target principal or none, truncated IP). A window's row is written when the window has closed, by the next
// refusal on that bucket or by the purge, with count = the refusals in that window.
class RateLimitAuditTest extends Base
{
    use ServiceFixture;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function rl(): RateLimitAudit
    {
        return new RateLimitAudit($this->container, $this->clock());
    }

    // Kills: a row per refusal (3 rows), a row written before the window closes, the count dropped or reset.
    public function testOneRowPerBucketPerWindow(): void
    {
        foreach ([0, 10, 599] as $dt) {
            $this->now = 1_800_000_000 + $dt;
            $this->rl()->note($this->alice, self::IP);
        }
        $this->assertSame([], $this->auditRows('rate_limited'), 'nothing while the window is open');
        $this->now = 1_800_000_000 + RateLimitAudit::WINDOW - 1;
        $this->assertSame(0, $this->rl()->flush());
        $this->now = 1_800_000_000 + RateLimitAudit::WINDOW;
        $this->assertSame(1, $this->rl()->flush());
        $rows = $this->auditRows('rate_limited');
        $this->assertCount(1, $rows);
        $this->assertSame([$this->alice, '203.0.113.0/24', 3, null], [(int) $rows[0]['target_user_id'], $rows[0]['ip_trunc'], (int) $rows[0]['count'], $rows[0]['actor_user_id']]);
        $this->assertSame(0, $this->rl()->flush(), 'flushed once');
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_rate WHERE bucket LIKE 'audit:rl:%'"));
    }

    // A refusal after the window closed writes the old window's row and opens a new window. Buckets are separate
    // per target and per /24. Kills: the old count carried into the new window, buckets merged.
    public function testNextRefusalClosesTheOldWindowAndBucketsAreSeparate(): void
    {
        $this->rl()->note($this->alice, self::IP);
        $this->rl()->note($this->alice, self::IP);
        $this->rl()->note(null, self::IP);
        $this->rl()->note($this->alice, '198.51.100.4');
        $this->now += RateLimitAudit::WINDOW + 5;
        $this->rl()->note($this->alice, self::IP);
        $rows = $this->auditRows('rate_limited');
        $this->assertCount(1, $rows);
        $this->assertSame(2, (int) $rows[0]['count']);
        $this->now += RateLimitAudit::WINDOW;
        $this->assertSame(3, $this->rl()->flush());
        $got = array_map(static fn (array $r): array => [$r['target_user_id'] === null ? null : (int) $r['target_user_id'], $r['ip_trunc'], (int) $r['count']], $this->auditRows('rate_limited'));
        // The closed window first (written by the refusal), then the flush in window-start, bucket order.
        $this->assertSame([[$this->alice, '203.0.113.0/24', 2], [null, '203.0.113.0/24', 1], [$this->alice, '198.51.100.0/24', 1], [$this->alice, '203.0.113.0/24', 1]], $got);
    }

    // The opportunistic purge writes closed windows, and a principal deleted meanwhile leaves target NULL (FK).
    // An actor-less row in a web request is the system (R39). Kills: the purge not flushing; the deleted target
    // breaking the insert.
    public function testPurgeFlushesAndADeletedTargetIsNulled(): void
    {
        $this->rl()->note($this->bob, '');
        $this->container['userModel']->remove($this->bob);
        $this->now += RateLimitAudit::WINDOW;
        $counts = (new Purger($this->container))->run($this->now);
        $this->assertSame(1, $counts['rate_limited']);
        $rows = $this->auditRows('rate_limited');
        $this->assertCount(1, $rows);
        $this->assertNull($rows[0]['target_user_id']);
        $this->assertNull($rows[0]['ip_trunc']);
    }
}
