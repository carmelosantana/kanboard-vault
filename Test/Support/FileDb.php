<?php

// A file-backed SQLite DB with the vault schema, for tests that need several connections or processes.
// The unit-test container DB is in-memory and can't be shared.
class VaultTestFileDb
{
    public static function create(): string
    {
        require_once __DIR__.'/Migrate.php';
        vault_test_sqlite_only(); // a second connection to the same file: SQLite only
        $path = tempnam(sys_get_temp_dir(), 'vault-test-').'.sqlite';
        $pdo = self::connect($path);
        $pdo->exec('PRAGMA journal_mode=wal'); // Kanboard's default (DB_WAL_MODE).
        vault_test_migrate($pdo);
        // The users columns Vault reads (the unit-test container has Kanboard's own table).
        $pdo->exec('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, is_active INTEGER NOT NULL DEFAULT 1, api_access_token TEXT, email TEXT, name TEXT, role TEXT)');
        return $path;
    }

    public static function connect(string $path, int $timeout = 10): \PDO
    {
        $pdo = new \PDO('sqlite:'.$path, null, null, [\PDO::ATTR_TIMEOUT => $timeout]);
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        return $pdo;
    }

    // A container whose 'db' exposes the given PDO, like PicoDb's Database::getConnection().
    public static function container(\PDO $pdo): \Pimple\Container
    {
        $c = new \Pimple\Container();
        $c['db'] = new class($pdo) {
            public function __construct(private \PDO $pdo) {}
            public function getConnection(): \PDO { return $this->pdo; }
        };
        // What VaultLock's after-commit work (ServerEvents, its failure log) reaches for, as on a real install.
        $c['dispatcher'] = new \Symfony\Component\EventDispatcher\EventDispatcher();
        $c['logger'] = new \Psr\Log\NullLogger();
        return $c;
    }

    public static function remove(string $path): void
    {
        foreach (['', '-wal', '-shm', '-journal'] as $suffix) {
            @unlink($path.$suffix);
        }
        @unlink(substr($path, 0, -strlen('.sqlite')));
    }
}
