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
