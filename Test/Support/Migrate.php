<?php

// Runs every SQLite schema version in order, as Kanboard's SchemaHandler does for a fresh install.
function vault_test_migrate(\PDO $pdo): void
{
    require_once __DIR__.'/../../Schema/Sqlite.php';
    for ($v = 1; $v <= \Kanboard\Plugin\Vault\Schema\VERSION; $v++) {
        call_user_func('\Kanboard\Plugin\Vault\Schema\version_'.$v, $pdo);
    }
}
