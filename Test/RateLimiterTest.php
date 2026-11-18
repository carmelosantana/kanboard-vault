<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/FileDb.php';

use Kanboard\Plugin\Vault\Model\RateLimiter;
use KanboardTests\units\Base;

class RateLimiterTest extends Base
{
    private array $files = [];
    private int $now = 1_000_000;

    protected function tearDown(): void
    {
        foreach ($this->files as $f) {
            VaultTestFileDb::remove($f);
        }
        parent::tearDown();
    }

    private function limiter(): RateLimiter
    {
        require_once __DIR__.'/../Schema/Sqlite.php';
        \Kanboard\Plugin\Vault\Schema\version_1($this->container['db']->getConnection());
        return new RateLimiter($this->container, null, fn () => $this->now);
    }

    // Kills a read-then-write outside the lock: forked workers race on one bucket.
    public function testParallelConsumeNeverExceedsCapacity(): void
    {
        if (! function_exists('pcntl_fork') || ! function_exists('posix_kill')) {
            $this->markTestSkipped('pcntl and posix are needed for the parallel consume test');
        }
        $this->files[] = $path = VaultTestFileDb::create();
        // 'fresh' races the first insert; 'seeded' races updates of a full row (kills a lost update).
        VaultTestFileDb::connect($path)->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('seeded', 5, ".time().')');
        $dir = sys_get_temp_dir().'/vault-rl-'.bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        $start = microtime(true) + 0.5;
        $pids = [];
        for ($i = 0; $i < 8; $i++) {
            $pid = pcntl_fork();
            $this->assertNotSame(-1, $pid, 'fork failed');
            if ($pid === 0) {
                // Child: its own connection, a common start line, a result file, then die without shutdown handlers.
                try {
                    $pdo = VaultTestFileDb::connect($path, 20);
                    $rl = new RateLimiter(VaultTestFileDb::container($pdo));
                    while (microtime(true) < $start) {
                        usleep(100);
                    }
                    $out = ($rl->consume('fresh', 5, 0, 1.0) ? '1' : '0').($rl->consume('seeded', 5, 0, 1.0) ? '1' : '0');
                } catch (\Throwable $e) {
                    $out = 'E:'.$e->getMessage();
                }
                file_put_contents("$dir/$i", $out);
                posix_kill(getmypid(), SIGKILL);
            }
            $pids[] = $pid;
        }
        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
        }
        $results = [];
        for ($i = 0; $i < 8; $i++) {
            $results[] = (string) @file_get_contents("$dir/$i");
            @unlink("$dir/$i");
        }
        @rmdir($dir);

        $this->assertSame([], array_values(array_filter($results, fn ($r) => ! preg_match('/^[01]{2}$/D', $r))), 'every worker finished cleanly');
        $this->assertSame(5, count(array_filter($results, fn ($r) => $r[0] === '1')), 'fresh: '.implode(',', $results));
        $this->assertSame(5, count(array_filter($results, fn ($r) => $r[1] === '1')), 'seeded: '.implode(',', $results));
    }

    public function testConsumeRefillsOverTimeUpToCapacity(): void
    {
        $rl = $this->limiter();
        // Burst of 3, one token per 10 s.
        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue($rl->consume('b', 3, 0.1));
        }
        $this->assertFalse($rl->consume('b', 3, 0.1));
        $this->now += 9;
        $this->assertFalse($rl->consume('b', 3, 0.1), '0.9 tokens is not enough');
        $this->now += 1;
        $this->assertTrue($rl->consume('b', 3, 0.1));
        $this->assertFalse($rl->consume('b', 3, 0.1));
        // A long idle period refills to capacity, not beyond.
        $this->now += 100000;
        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue($rl->consume('b', 3, 0.1));
        }
        $this->assertFalse($rl->consume('b', 3, 0.1));
    }

    public function testConsumeHonoursCostAndSeparatesBuckets(): void
    {
        $rl = $this->limiter();
        $this->assertTrue($rl->consume('a', 5, 0, 3.0));
        $this->assertFalse($rl->consume('a', 5, 0, 3.0));
        $this->assertTrue($rl->consume('a', 5, 0, 2.0));
        $this->assertTrue($rl->consume('other', 5, 0, 5.0));
        $this->assertFalse($rl->consume('huge', 5, 0, 6.0));
    }

    public function testClockGoingBackwardsDoesNotMintTokens(): void
    {
        $rl = $this->limiter();
        $this->assertTrue($rl->consume('c', 1, 1));
        $this->now -= 1000;
        $this->assertFalse($rl->consume('c', 1, 1));
    }

    public function testBackoffDoublesAndCaps(): void
    {
        $rl = $this->limiter();
        // Five failures are allowed; the fifth starts the back-off.
        for ($i = 1; $i <= 4; $i++) {
            $this->assertSame(0, $rl->recordFailure('unlock:user:1'), "failure $i");
            $this->assertSame(0, $rl->backoffSeconds('unlock:user:1'));
        }
        $expected = [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600];
        foreach ($expected as $i => $seconds) {
            $this->assertSame($seconds, $rl->recordFailure('unlock:user:1'), 'failure '.($i + 5));
            $this->assertSame($seconds, $rl->backoffSeconds('unlock:user:1'));
        }
        // Many more failures never overflow past the cap.
        for ($i = 0; $i < 100; $i++) {
            $rl->recordFailure('unlock:user:1');
        }
        $this->assertSame(3600, $rl->backoffSeconds('unlock:user:1'));
    }

    public function testBackoffCountsDownAndNeverLocksPermanently(): void
    {
        $rl = $this->limiter();
        for ($i = 0; $i < 5; $i++) {
            $rl->recordFailure('u');
        }
        $this->assertSame(60, $rl->backoffSeconds('u'));
        $this->now += 45;
        $this->assertSame(15, $rl->backoffSeconds('u'));
        $this->now += 15;
        $this->assertSame(0, $rl->backoffSeconds('u'));
        $this->assertSame(0, $rl->backoffSeconds('never-seen'));
        // A clock jump backwards never makes the wait longer than the back-off.
        $this->now -= 100000;
        $this->assertSame(60, $rl->backoffSeconds('u'));
    }

    public function testRecordSuccessResets(): void
    {
        $rl = $this->limiter();
        for ($i = 0; $i < 6; $i++) {
            $rl->recordFailure('u');
            $rl->recordFailure('v');
        }
        $rl->recordSuccess('u');
        $this->assertSame(0, $rl->backoffSeconds('u'));
        $this->assertSame(0, $rl->recordFailure('u'), 'the count starts again');
        $this->assertSame(120, $rl->backoffSeconds('v'), 'other buckets are untouched');
    }

    public static function badBuckets(): array
    {
        return [['', ], [str_repeat('x', 192)]];
    }

    /** @dataProvider badBuckets */
    public function testRejectsBucketKeysThatCannotBeStored(string $bucket): void
    {
        $rl = $this->limiter();
        $this->expectException(\InvalidArgumentException::class);
        $rl->consume($bucket, 1, 1);
    }

    public function testRejectsNonsenseParameters(): void
    {
        $rl = $this->limiter();
        foreach ([[0, 1, 1], [1, -1, 1], [1, 1, 0], [NAN, 1, 1], [1, INF, 1]] as [$cap, $rate, $cost]) {
            try {
                $rl->consume('p', $cap, $rate, $cost);
                $this->fail("accepted $cap/$rate/$cost");
            } catch (\InvalidArgumentException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    // R16(a): PDO binds floats as strings with 14 significant digits, so a stored 1/3 reads back as
    // 0.33333333333333. Three denied checks one second apart then sum to just under 1, although the token
    // is due. A strict `>=` without a tolerance delays it.
    public function testFloatDriftDoesNotDelayADueToken(): void
    {
        $rl = $this->limiter();
        $rate = 1 / 3;
        $this->assertTrue($rl->consume('drift', 1, $rate));
        for ($i = 0; $i < 2; $i++) {
            $this->now++;
            $this->assertFalse($rl->consume('drift', 1, $rate), "second $i");
        }
        $this->now++;
        $this->assertTrue($rl->consume('drift', 1, $rate), 'the token is due after 3 s');
        // The tolerance never grants a token that is not due.
        $this->assertFalse($rl->consume('drift', 1, $rate));
    }

    // Unlock spends an IP token up front (atomic, no overshoot) and gives it back on success, so the IP
    // bucket counts failures and attempts in flight, never successful unlocks.
    public function testRefundReturnsASpentTokenButNeverExceedsCapacity(): void
    {
        $rl = $this->limiter();
        $this->assertTrue($rl->consume('ip', 2, 0));
        $this->assertTrue($rl->consume('ip', 2, 0));
        $this->assertFalse($rl->consume('ip', 2, 0));
        $rl->refund('ip', 2, 0);
        $this->assertTrue($rl->consume('ip', 2, 0), 'the refunded token is usable');
        $this->assertFalse($rl->consume('ip', 2, 0));
        // Refunds on a full or missing bucket never raise it above capacity.
        $rl->refund('fresh', 2, 0);
        $rl->refund('fresh', 2, 0);
        $this->assertTrue($rl->consume('fresh', 2, 0));
        $this->assertTrue($rl->consume('fresh', 2, 0));
        $this->assertFalse($rl->consume('fresh', 2, 0));
    }
}
