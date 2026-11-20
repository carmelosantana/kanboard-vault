<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/FileDb.php';

use Kanboard\Plugin\Vault\Model\VaultDb;
use Kanboard\Plugin\Vault\Model\VaultLock;
use KanboardTests\units\Base;

// A real SQLite PDO that reports another driver name, to drive VaultDb's per-driver paths.
class VaultDbDriverPdo extends \PDO
{
    public array $prepared = [];

    public function __construct(private string $driver)
    {
        parent::__construct('sqlite::memory:');
    }

    public function getAttribute(int $attribute): mixed
    {
        return $attribute === \PDO::ATTR_DRIVER_NAME ? $this->driver : parent::getAttribute($attribute);
    }

    public function prepare(string $query, array $options = []): \PDOStatement|false
    {
        $this->prepared[] = $query;
        return parent::prepare($query, $options);
    }
}

class VaultDbTest extends Base
{
    private function migrate(): void
    {
        require_once __DIR__.'/Support/Migrate.php';
        vault_test_migrate($this->container['db']->getConnection());
    }

    private function rows(string $table): int
    {
        return (int) $this->container['db']->getConnection()->query("SELECT COUNT(*) FROM $table")->fetchColumn();
    }

    public function testExecuteFetchOneFetchAll(): void
    {
        $this->migrate();
        $db = new VaultDb($this->container);
        $this->assertSame(1, $db->execute('INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES (?, ?, ?)', ['a', 1.5, 10]));
        $db->execute('INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES (?, ?, ?)', ['b', 2, 20]);
        $this->assertSame(2, $db->execute('UPDATE vault_rate SET updated_at = ?', [30]));
        $row = $db->fetchOne('SELECT bucket, updated_at FROM vault_rate WHERE bucket = ?', ['a']);
        $this->assertSame(['bucket', 'updated_at'], array_keys($row), 'associative rows only');
        $this->assertSame('a', $row['bucket']);
        $this->assertEquals(30, $row['updated_at']);
        $this->assertNull($db->fetchOne('SELECT bucket FROM vault_rate WHERE bucket = ?', ['zz']));
        $this->assertSame([['bucket' => 'a'], ['bucket' => 'b']], $db->fetchAll('SELECT bucket FROM vault_rate ORDER BY bucket'));
        $this->assertSame([], $db->fetchAll('SELECT bucket FROM vault_rate WHERE 1 = 0'));
    }

    public function testInsertReturnsLastId(): void
    {
        $this->migrate();
        $db = new VaultDb($this->container);
        $row = ['user_id' => 1, 'purpose' => 'register', 'challenge_hash' => 'h', 'expires_at' => 20];
        $first = $db->insert('vault_challenges', $row);
        $second = $db->insert('vault_challenges', $row);
        $this->assertGreaterThan(0, $first);
        $this->assertSame($first + 1, $second);
        $this->assertSame(0, $db->insert('vault_rate', ['bucket' => 'k', 'tokens' => 1, 'updated_at' => 1], null), 'no id column');
    }

    public function testPostgresInsertUsesReturning(): void
    {
        $pdo = new VaultDbDriverPdo('pgsql');
        $pdo->exec('CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)');
        $db = new VaultDb(VaultTestFileDb::container($pdo));
        $this->assertSame(1, $db->insert('t', ['v' => 'x']));
        $this->assertSame(2, $db->insert('t', ['v' => 'y']));
        $this->assertSame('INSERT INTO t (v) VALUES (?) RETURNING id', end($pdo->prepared));
        $this->assertSame(0, $db->insert('t', ['v' => 'z'], null));
        $this->assertSame('INSERT INTO t (v) VALUES (?)', end($pdo->prepared));
    }

    public function testErrorsThrowWhateverTheConnectionErrorMode(): void
    {
        $this->migrate();
        $pdo = $this->container['db']->getConnection();
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_SILENT);
        $db = new VaultDb($this->container);
        try {
            $db->execute('SELECT nope FROM nowhere');
            $this->fail('no exception');
        } catch (\PDOException $e) {
        }
        $this->assertSame(\PDO::ERRMODE_SILENT, $pdo->getAttribute(\PDO::ATTR_ERRMODE), 'the mode is restored');
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    public function testRejectsUnsafeIdentifiers(): void
    {
        $db = new VaultDb($this->container);
        foreach ([['vault_rate; DROP', ['a' => 1]], ['vault_rate', ['a) VALUES (1); --' => 1]], ['vault_rate', []]] as [$table, $row]) {
            try {
                $db->insert($table, $row);
                $this->fail('accepted '.$table);
            } catch (\InvalidArgumentException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    // The ruling's test: a duplicate key inside the lock throws (not PicoDb's silent false),
    // and the earlier insert in the same callable is rolled back.
    public function testDuplicateKeyInsideLockThrowsAndRollsBack(): void
    {
        $this->migrate();
        $db = new VaultDb($this->container);
        $db->insert('vault_rate', ['bucket' => 'dup', 'tokens' => 1, 'updated_at' => 1], null);
        $lock = new VaultLock($this->container);
        $after = false;
        try {
            $lock->exclusive(function () use ($db, &$after) {
                $db->insert('vault_challenges', ['user_id' => 1, 'purpose' => 'p', 'challenge_hash' => 'h', 'expires_at' => 1]);
                $db->insert('vault_rate', ['bucket' => 'dup', 'tokens' => 2, 'updated_at' => 2], null);
                $after = true;
            });
            $this->fail('duplicate key was not raised');
        } catch (\PDOException $e) {
            $this->assertNotInstanceOf(\PicoDb\SQLException::class, $e);
        }
        $this->assertFalse($after);
        $this->assertSame(0, $this->rows('vault_challenges'));
        $this->assertSame(1, $this->rows('vault_rate'));
    }
}
