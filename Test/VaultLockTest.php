<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/FileDb.php';

use Kanboard\Plugin\Vault\Model\VaultLock;
use KanboardTests\units\Base;

// Pretends to be a MySQL or Postgres PDO and records every statement; the lock row query answers from SQLite.
class VaultLockRecordingPdo extends \PDO
{
    public array $log = [];

    public function __construct(private string $driver, private bool $hasMetaRow = true)
    {
        parent::__construct('sqlite::memory:');
        $this->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    public function getAttribute(int $attribute): mixed
    {
        return $attribute === \PDO::ATTR_DRIVER_NAME ? $this->driver : parent::getAttribute($attribute);
    }

    private bool $open = false;

    public function beginTransaction(): bool { $this->log[] = 'beginTransaction'; return $this->open = true; }
    public function commit(): bool { $this->log[] = 'commit'; $this->open = false; return true; }
    public function rollBack(): bool { $this->log[] = 'rollBack'; $this->open = false; return true; }
    public function inTransaction(): bool { return $this->open; }

    public function exec(string $statement): int|false
    {
        $this->log[] = $statement;
        $this->open = str_starts_with($statement, 'BEGIN') ? true : ($statement === 'COMMIT' || $statement === 'ROLLBACK' ? false : $this->open);
        return 0;
    }

    public function query(string $query, ?int $fetchMode = null, mixed ...$fetchModeArgs): \PDOStatement|false
    {
        $this->log[] = $query;
        return parent::query($this->hasMetaRow ? 'SELECT 1 AS id' : 'SELECT 1 AS id WHERE 0');
    }
}

class VaultLockTest extends Base
{
    private array $files = [];

    protected function tearDown(): void
    {
        foreach ($this->files as $f) {
            VaultTestFileDb::remove($f);
        }
        parent::tearDown();
    }

    private function migrate(): void
    {
        require_once __DIR__.'/Support/Migrate.php';
        vault_test_migrate($this->container['db']->getConnection());
    }

    private function rateRows(\PDO $pdo): int
    {
        return (int) $pdo->query('SELECT COUNT(*) FROM vault_rate')->fetchColumn();
    }

    // Kills a missing ROLLBACK: the open transaction would still show the row on this connection.
    public function testExclusiveRollsBackOnThrow(): void
    {
        $this->migrate();
        $pdo = $this->container['db']->getConnection();
        $lock = new VaultLock($this->container);
        try {
            $lock->exclusive(function () use ($pdo) {
                $pdo->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('b', 1, 1)");
                throw new \RuntimeException('boom');
            });
            $this->fail('exception swallowed');
        } catch (\RuntimeException $e) {
            $this->assertSame('boom', $e->getMessage());
        }
        $this->assertSame(0, $this->rateRows($pdo));
        // The lock is usable again and commits.
        $this->assertSame('ok', $lock->exclusive(function () use ($pdo) {
            $pdo->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('b', 1, 1)");
            return 'ok';
        }));
        $this->assertSame(1, $this->rateRows($pdo));
    }

    // Kills a deferred BEGIN: A takes no row lock before B tries, so only BEGIN IMMEDIATE makes B busy.
    public function testSqliteUsesBeginImmediate(): void
    {
        $this->files[] = $path = VaultTestFileDb::create();
        $a = VaultTestFileDb::connect($path);
        $b = VaultTestFileDb::connect($path, 0);
        $lockA = new VaultLock(VaultTestFileDb::container($a));
        $lockB = new VaultLock(VaultTestFileDb::container($b));

        $busy = $lockA->exclusive(function () use ($lockB) {
            try {
                $lockB->exclusive(fn () => null);
                return false;
            } catch (\PDOException $e) {
                return $e->errorInfo[1] ?? null;
            }
        });
        $this->assertSame(5, $busy, 'B must get SQLITE_BUSY while A holds the exclusive lock');

        // After A commits, B gets the lock.
        $this->assertSame('b', $lockB->exclusive(fn () => 'b'));
    }

    public function testSharedDoesNotBlockSharedAndSeesCommittedRows(): void
    {
        $this->files[] = $path = VaultTestFileDb::create();
        $a = VaultTestFileDb::connect($path);
        $b = VaultTestFileDb::connect($path, 0);
        $lockA = new VaultLock(VaultTestFileDb::container($a));
        $lockB = new VaultLock(VaultTestFileDb::container($b));
        $lockA->exclusive(fn () => $a->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('x', 1, 1)"));

        $n = $lockA->shared(fn () => $lockB->shared(fn () => $this->rateRows($b)));
        $this->assertSame(1, $n);
    }

    public function testNestedExclusiveReusesOuterTransaction(): void
    {
        $this->migrate();
        $pdo = $this->container['db']->getConnection();
        $lock = new VaultLock($this->container);
        $other = new VaultLock($this->container); // nesting is tracked per connection, not per instance
        try {
            $lock->exclusive(function () use ($pdo, $other) {
                $inner = $other->exclusive(function () use ($pdo) {
                    $pdo->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('n', 1, 1)");
                    return 'inner';
                });
                $this->assertSame('inner', $inner);
                throw new \RuntimeException('outer fails');
            });
        } catch (\RuntimeException $e) {
        }
        // The inner write belonged to the outer transaction, so it rolled back with it.
        $this->assertSame(0, $this->rateRows($pdo));
    }

    // PicoDb's statement handler rolls back the connection's transaction on any SQL error (and hides a duplicate
    // key as false). Work that carried on after that ran outside the lock, so the lock must not report success.
    public function testTransactionEndedInsideTheLockFails(): void
    {
        $this->migrate();
        $db = $this->container['db'];
        $pdo = $db->getConnection();
        $pdo->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('dup', 1, 1)");
        $lock = new VaultLock($this->container);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('ended inside');
        $lock->exclusive(function () use ($db) {
            $this->assertFalse($db->table('vault_rate')->insert(['bucket' => 'dup', 'tokens' => 1, 'updated_at' => 1]));
            return 'carried on';
        });
    }

    // R16(b): a nested exclusive() that throws marks the transaction rollback-only. If the outer callable
    // swallows the exception and returns, the outermost call still rolls back and throws, so the inner
    // half-done writes are never committed.
    public function testSwallowedNestedFailureRollsBackTheOuterTransaction(): void
    {
        $this->migrate();
        $pdo = $this->container['db']->getConnection();
        $lock = new VaultLock($this->container);
        $thrown = null;
        try {
            $lock->exclusive(function () use ($pdo, $lock) {
                $pdo->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('outer', 1, 1)");
                try {
                    $lock->exclusive(function () use ($pdo) {
                        $pdo->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('inner-half', 1, 1)");
                        throw new \DomainException('inner fails half way');
                    });
                } catch (\DomainException $swallowed) {
                }
                return 'carried on';
            });
        } catch (\RuntimeException $e) {
            $thrown = $e;
        }
        $this->assertNotNull($thrown, 'the outermost call must not report success');
        $this->assertStringContainsString('rollback-only', $thrown->getMessage());
        $this->assertSame(0, $this->rateRows($pdo));
        $this->assertFalse($pdo->inTransaction());
        // The flag does not leak into the next transaction.
        $this->assertSame('ok', $lock->exclusive(fn () => 'ok'));
    }

    public function testSharedInsideExclusiveIsAllowed(): void
    {
        $lock = new VaultLock($this->container);
        $this->migrate();
        $this->assertSame(7, $lock->exclusive(fn () => $lock->shared(fn () => 7)));
    }

    public function testExclusiveInsideSharedThrows(): void
    {
        $this->migrate();
        $lock = new VaultLock($this->container);
        $this->expectException(\LogicException::class);
        $lock->shared(fn () => $lock->exclusive(fn () => null));
    }

    public function testStateResetsAfterLogicException(): void
    {
        $this->migrate();
        $lock = new VaultLock($this->container);
        try {
            $lock->shared(fn () => $lock->exclusive(fn () => null));
        } catch (\LogicException $e) {
        }
        $this->assertSame('ok', $lock->exclusive(fn () => 'ok'));
    }

    public static function serverDrivers(): array
    {
        return [
            'mysql exclusive' => ['mysql', 'exclusive', 'SELECT id FROM vault_meta WHERE id = 1 FOR UPDATE'],
            'mysql shared' => ['mysql', 'shared', 'SELECT id FROM vault_meta WHERE id = 1 LOCK IN SHARE MODE'],
            'pgsql exclusive' => ['pgsql', 'exclusive', 'SELECT id FROM vault_meta WHERE id = 1 FOR UPDATE'],
            'pgsql shared' => ['pgsql', 'shared', 'SELECT id FROM vault_meta WHERE id = 1 FOR SHARE'],
        ];
    }

    /** @dataProvider serverDrivers */
    public function testServerDatabasesLockTheMetaRow(string $driver, string $mode, string $sql): void
    {
        $pdo = new VaultLockRecordingPdo($driver);
        $lock = new VaultLock(VaultTestFileDb::container($pdo));
        $this->assertSame('r', $lock->$mode(fn () => 'r'));
        $this->assertSame(['beginTransaction', $sql, 'commit'], $pdo->log);

        $pdo->log = [];
        try {
            $lock->$mode(function () { throw new \RuntimeException('x'); });
        } catch (\RuntimeException $e) {
        }
        $this->assertSame(['beginTransaction', $sql, 'rollBack'], $pdo->log);
    }

    public function testServerDatabaseWithoutMetaRowFailsClosed(): void
    {
        $pdo = new VaultLockRecordingPdo('mysql', false);
        $lock = new VaultLock(VaultTestFileDb::container($pdo));
        $ran = false;
        try {
            $lock->exclusive(function () use (&$ran) { $ran = true; });
            $this->fail('no exception');
        } catch (\RuntimeException $e) {
        }
        $this->assertFalse($ran);
        $this->assertSame('rollBack', end($pdo->log));
    }

    public function testSqliteIssuesRawStatements(): void
    {
        $pdo = new VaultLockRecordingPdo('sqlite');
        $lock = new VaultLock(VaultTestFileDb::container($pdo));
        $lock->exclusive(fn () => null);
        $lock->shared(fn () => null);
        $this->assertSame(['BEGIN IMMEDIATE', 'COMMIT', 'BEGIN', 'COMMIT'], $pdo->log);
    }

    public function testUnsupportedDriverThrows(): void
    {
        $lock = new VaultLock(VaultTestFileDb::container(new VaultLockRecordingPdo('odbc')));
        $this->expectException(\RuntimeException::class);
        $lock->exclusive(fn () => null);
    }

    // Task 10: afterCommit inside nested locks runs once, in order, only after the outermost COMMIT, and sees the
    // committed row with no transaction open. Kills: running at the inner level, before the commit, or twice.
    public function testAfterCommitRunsOnceAfterTheOuterCommit(): void
    {
        $this->migrate();
        $pdo = $this->container['db']->getConnection();
        $lock = new VaultLock($this->container);
        $seen = [];
        $lock->exclusive(function () use ($pdo, $lock, &$seen) {
            $lock->exclusive(function () use ($pdo, $lock, &$seen) {
                $pdo->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('ac', 1, 1)");
                $lock->afterCommit(function () use ($pdo, &$seen) {
                    $seen[] = ['first', $pdo->inTransaction(), $this->rateRows($pdo)];
                });
            });
            $lock->afterCommit(function () use (&$seen) { $seen[] = ['second']; });
            $this->assertSame([], $seen, 'nothing runs before the outer commit');
        });
        $this->assertSame([['first', false, 1], ['second']], $seen);
        // The queue is gone with the transaction: a later lock runs nothing again.
        $lock->exclusive(fn () => null);
        $this->assertCount(2, $seen);
    }

    // Kills: running the queue on rollback, or keeping it for the next transaction.
    public function testAfterCommitIsDroppedOnRollback(): void
    {
        $this->migrate();
        $lock = new VaultLock($this->container);
        $ran = 0;
        try {
            $lock->exclusive(function () use ($lock, &$ran) {
                $lock->exclusive(function () use ($lock, &$ran) {
                    $lock->afterCommit(function () use (&$ran) { $ran++; });
                });
                throw new \RuntimeException('boom');
            });
        } catch (\RuntimeException $e) {
        }
        $this->assertSame(0, $ran);
        // A swallowed nested failure makes the transaction rollback-only: its queue goes with it.
        try {
            $lock->exclusive(function () use ($lock, &$ran) {
                $lock->afterCommit(function () use (&$ran) { $ran++; });
                try {
                    $lock->exclusive(function () { throw new \LogicException('inner'); });
                } catch (\LogicException $e) {
                }
            });
            $this->fail('the rollback-only transaction must throw');
        } catch (\RuntimeException $e) {
            $this->assertStringContainsString('rollback-only', $e->getMessage());
        }
        $this->assertSame(0, $ran);
        $lock->exclusive(fn () => null);
        $this->assertSame(0, $ran, 'a dropped callback never runs later');
    }

    public function testAfterCommitWithNoLockRunsAtOnce(): void
    {
        $ran = 0;
        (new VaultLock($this->container))->afterCommit(function () use (&$ran) { $ran++; });
        $this->assertSame(1, $ran);
    }

    // A failing callback can't undo or fail the committed change, the next callback still runs, and the log names the
    // exception class only. Kills: the exception escaping; the message logged.
    public function testThrowingCallbackLeavesTheChangeCommittedAndLogsTheClassOnly(): void
    {
        $this->migrate();
        $logged = [];
        $logger = $this->createMock(\Psr\Log\LoggerInterface::class);
        foreach (['warning', 'error', 'info', 'notice', 'debug', 'critical'] as $level) {
            $logger->method($level)->willReturnCallback(function ($msg) use (&$logged) { $logged[] = (string) $msg; });
        }
        $this->container['logger'] = $logger;
        $pdo = $this->container['db']->getConnection();
        $lock = new VaultLock($this->container);
        $after = 0;
        $result = $lock->exclusive(function () use ($pdo, $lock, &$after) {
            $pdo->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('t', 1, 1)");
            $lock->afterCommit(function () { throw new \DomainException('secret-canary'); });
            $lock->afterCommit(function () use (&$after) { $after++; });
            return 'done';
        });
        $this->assertSame('done', $result);
        $this->assertSame(1, $this->rateRows($pdo));
        $this->assertSame(1, $after);
        $this->assertCount(1, $logged);
        $this->assertStringContainsString('DomainException', $logged[0]);
        $this->assertStringNotContainsString('secret-canary', $logged[0]);
    }
}
