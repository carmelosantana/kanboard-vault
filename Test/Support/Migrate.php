<?php

// Runs every schema version of the connection's dialect in order, as Kanboard's SchemaHandler does for a fresh install:
// Schema/Sqlite.php, Mysql.php or Postgres.php (T24: the suite also runs on MariaDB and Postgres). Only one of them
// can be loaded in a process (they share a namespace), so a run uses one driver throughout.
function vault_test_migrate(\PDO $pdo): void
{
    $file = match ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME)) {
        'mysql' => 'Mysql',
        'pgsql' => 'Postgres',
        default => 'Sqlite',
    };
    require_once __DIR__.'/../../Schema/'.$file.'.php';
    for ($v = 1; $v <= \Kanboard\Plugin\Vault\Schema\VERSION; $v++) {
        call_user_func('\Kanboard\Plugin\Vault\Schema\version_'.$v, $pdo);
    }
}

// Skips the calling test when the suite runs on MariaDB or Postgres (run-realdb-tests.sh): it checks SQLite itself
// (PRAGMA, sqlite_master, a file DB, Schema/Sqlite.php loaded by hand, which can't sit beside another dialect's file).
function vault_test_sqlite_only(): void
{
    if (DB_DRIVER !== 'sqlite') {
        throw new \PHPUnit\Framework\SkippedTestError('SQLite-specific; this run is '.DB_DRIVER);
    }
}

// Dialect-aware introspection (T24 fix round 1, I2), so a test that reads the catalogue runs on every driver:
// sqlite_master and PRAGMA on SQLite, information_schema (current database or schema) on MariaDB and Postgres.
function vault_test_tables(\PDO $pdo): array
{
    $sql = match ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME)) {
        'mysql' => "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'",
        'pgsql' => "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'",
        default => "SELECT name FROM sqlite_master WHERE type = 'table'",
    };
    $tables = $pdo->query($sql)->fetchAll(\PDO::FETCH_COLUMN);
    sort($tables);
    return $tables;
}

function vault_test_columns(\PDO $pdo, string $table): array
{
    $driver = $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
    if ($driver === 'sqlite') {
        return array_column($pdo->query('PRAGMA table_info('.$table.')')->fetchAll(\PDO::FETCH_ASSOC), 'name');
    }
    $schema = $driver === 'mysql' ? 'DATABASE()' : 'current_schema()';
    $st = $pdo->prepare("SELECT column_name FROM information_schema.columns WHERE table_schema = $schema AND table_name = ? ORDER BY ordinal_position");
    $st->execute([$table]);
    return $st->fetchAll(\PDO::FETCH_COLUMN);
}

// name => [default, not null, type] per column: PRAGMA table_info on SQLite, information_schema.columns elsewhere.
function vault_test_column_info(\PDO $pdo, string $table): array
{
    $driver = $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME);
    if ($driver === 'sqlite') {
        $rows = $pdo->query('PRAGMA table_info('.$table.')')->fetchAll(\PDO::FETCH_ASSOC);
        return array_combine(array_column($rows, 'name'), array_map(fn ($r) => [(string) $r['dflt_value'], (int) $r['notnull'] === 1, strtolower($r['type'])], $rows));
    }
    $schema = $driver === 'mysql' ? 'DATABASE()' : 'current_schema()';
    $st = $pdo->prepare("SELECT column_name, column_default, is_nullable, data_type FROM information_schema.columns WHERE table_schema = $schema AND table_name = ?");
    $st->execute([$table]);
    $out = [];
    foreach ($st->fetchAll(\PDO::FETCH_ASSOC) as $r) {
        $r = array_change_key_case($r);
        $out[$r['column_name']] = [(string) $r['column_default'], $r['is_nullable'] === 'NO', strtolower($r['data_type'])];
    }
    return $out;
}

// Every row of every table, as JSON: what a stolen logical backup of the database holds.
function vault_test_dump(\PDO $pdo): string
{
    $q = $pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql' ? '`' : '"';
    $dump = '';
    foreach (vault_test_tables($pdo) as $t) {
        $dump .= json_encode($pdo->query('SELECT * FROM '.$q.$t.$q)->fetchAll(\PDO::FETCH_ASSOC));
    }
    return $dump;
}

// Whether the connection enforces foreign keys: SQLite only when PRAGMA foreign_keys is on, MariaDB unless
// foreign_key_checks is off, Postgres always.
function vault_test_foreign_keys_enforced(\PDO $pdo): bool
{
    return match ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME)) {
        'mysql' => (int) $pdo->query('SELECT @@foreign_key_checks')->fetchColumn() === 1,
        'pgsql' => true,
        default => (int) $pdo->query('PRAGMA foreign_keys')->fetchColumn() === 1,
    };
}
