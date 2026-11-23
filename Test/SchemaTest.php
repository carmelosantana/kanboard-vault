<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/Migrate.php';
use KanboardTests\units\Base;

class SchemaTest extends Base
{
    // One minimal valid row per table, in insert order (parents before children).
    private const ROWS = [
        'vault_principals' => ['user_id' => 1, 'kind' => 'human', 'public_key' => 'cGs=', 'key_gen' => 1, 'state' => 'active', 'created_at' => 10],
        'vault_rotations' => ['user_id' => 1, 'old_pk' => 'b2xk', 'new_pk' => 'bmV3', 'bridge_nonce' => 'bm9uY2U=', 'bridge' => 'YnJpZGdl', 'phase' => 'start', 'started_at' => 10],
        'vault_wraps' => ['user_id' => 1, 'method' => 'passphrase', 'credential_id' => null, 'kdf_salt' => 'c2FsdA==', 'kdf_ops' => 3, 'kdf_mem' => 67108864, 'status' => 'active', 'key_gen' => 1, 'nonce' => 'bm9uY2U=', 'wrapped_sk' => 'c2s=', 'crypto_v' => 1, 'created_at' => 10],
        'vault_webauthn' => ['user_id' => 1, 'credential_id' => 'Y3JlZA', 'cose_public_key' => 'Y29zZQ==', 'sign_count' => 0, 'prf_salt' => 'cHJm', 'label' => 'YubiKey', 'origin' => 'https://kb.test', 'rp_id' => 'kb.test', 'created_at' => 10, 'last_used_at' => null],
        'vault_challenges' => ['user_id' => 1, 'purpose' => 'register', 'challenge_hash' => 'abc123', 'expires_at' => 20],
        'vault_groups' => ['owner_id' => 1, 'parent_id' => null, 'kind' => 'normal', 'key_epoch' => 1, 'nonce' => 'bm9uY2U=', 'ciphertext' => 'Y3Q=', 'crypto_v' => 1, 'position' => 0, 'created_at' => 10, 'updated_at' => 10],
        'vault_entries' => ['group_id' => 1, 'owner_id' => 1, 'created_by' => 1, 'version' => 1, 'key_epoch' => 1, 'nonce' => 'bm9uY2U=', 'ciphertext' => 'Y3Q=', 'crypto_v' => 1, 'created_at' => 10, 'updated_at' => 10],
        'vault_grants' => ['subject_type' => 'group', 'subject_id' => 1, 'grantee_id' => 1, 'permission' => 'read', 'granted_by' => 1, 'expires_at' => null, 'created_at' => 10],
        'vault_keys' => ['object_type' => 'entry', 'object_id' => 1, 'principal_id' => 1, 'principal_key_gen' => 1, 'key_epoch' => 1, 'sealed_dek' => 'ZGVr'],
        'vault_rekey_queue' => ['object_type' => 'group', 'object_id' => 1, 'expected_key_epoch' => 2, 'created_at' => 10],
        'vault_sessions' => ['sid_hash' => 'sidhash', 'user_id' => 1, 'nonce' => 'bm9uY2U=', 'enc_sk' => 'ZXNr', 'nonce_next' => null, 'enc_sk_next' => null, 'created_at' => 10, 'last_used_at' => 10, 'idle_expires_at' => 20, 'abs_expires_at' => 30],
        'vault_share_reservations' => ['id_hash' => 'idhash', 'creator_id' => 1, 'sid_hash' => 'sidhash', 'expires_at' => 20],
        'vault_shares' => ['id_hash' => 'idhash', 'burn_hash' => 'burnhash', 'creator_id' => 1, 'ciphertext' => 'Y3Q=', 'iv' => 'aXY=', 'salt' => 'c2FsdA==', 'has_passphrase' => 0, 'sealed_label' => 'bGFiZWw=', 'created_at' => 10, 'expires_at' => 20],
        'vault_audit' => ['created_at' => 10, 'actor_user_id' => 1, 'actor_kind' => 'human', 'action' => 'read', 'object_type' => 'entry', 'object_id' => 1, 'share_hash' => null, 'target_user_id' => null, 'ip_trunc' => '10.0.0.0/24', 'ua_family' => 'Firefox 140 / Linux', 'via' => 'ui', 'count' => null],
        'vault_rate' => ['bucket' => 'unlock:user:1', 'tokens' => 5.0, 'updated_at' => 10],
        'vault_agent_settings' => ['agent_user_id' => 1, 'read_cap_per_hour' => 60],
    ];

    private function migrate(): void
    {
        require_once __DIR__.'/Support/Migrate.php';
        vault_test_migrate($this->container['db']->getConnection());
    }

    public function testCreatesEveryTable(): void
    {
        $this->migrate();
        $db = $this->container['db'];
        foreach (self::ROWS as $table => $row) {
            $this->assertTrue($db->table($table)->insert($row), $table);
            $read = $db->table($table)->findOne();
            $this->assertNotNull($read, $table);
            foreach ($row as $col => $value) {
                $this->assertArrayHasKey($col, $read, "$table.$col");
                $this->assertEquals($value, $read[$col], "$table.$col");
            }
        }
    }

    public function testVaultMetaHasSingletonRow(): void
    {
        $this->migrate();
        $rows = $this->container['db']->table('vault_meta')->findAll();
        $this->assertCount(1, $rows);
        $this->assertSame(1, (int) $rows[0]['id']);
        $this->assertArrayHasKey('schema_note', $rows[0]);
        // The CHECK keeps it a singleton.
        // PicoDb answers false on SQLite and MySQL and throws on Postgres (T24 real-DB run); either way, refused.
        try {
            $inserted = @$this->container['db']->table('vault_meta')->insert(['id' => 2, 'schema_note' => 'x']);
        } catch (\PicoDb\SQLException) {
            $inserted = false;
        }
        $this->assertFalse($inserted);
        $this->assertSame(1, (int) $this->container['db']->getConnection()->query('SELECT COUNT(*) FROM vault_meta')->fetchColumn());
    }

    public function testVaultMetaSeedIsIdempotent(): void
    {
        $this->migrate();
        \Kanboard\Plugin\Vault\Schema\version_1($this->container['db']->getConnection());
        $rows = $this->container['db']->table('vault_meta')->findAll();
        $this->assertCount(1, $rows);
        $this->assertSame(1, (int) $rows[0]['id']);
        foreach (['Sqlite', 'Mysql', 'Postgres'] as $d) {
            $src = file_get_contents(__DIR__."/../Schema/$d.php");
            $this->assertStringContainsString('WHERE NOT EXISTS (SELECT 1 FROM vault_meta WHERE id = 1)', $src, $d);
        }
    }

    // A freed id must never be handed out again: grants and key rows name objects by (type, id) with no FK.
    public function testDeletedObjectIdsAreNeverReused(): void
    {
        $this->migrate();
        $db = $this->container['db'];
        foreach (['vault_groups', 'vault_entries'] as $table) {
            if ($table === 'vault_entries') {
                $db->table('vault_groups')->insert(self::ROWS['vault_groups']);
            }
            $db->table($table)->insert(self::ROWS[$table]);
            $db->table($table)->insert(self::ROWS[$table]);
            $deleted = (int) $db->table($table)->desc('id')->findOneColumn('id');
            $this->assertTrue($db->table($table)->eq('id', $deleted)->remove(), $table);
            $db->table($table)->insert(self::ROWS[$table]);
            $newId = (int) $db->getLastId();
            $this->assertGreaterThan($deleted, $newId, $table);
        }

        $src = file_get_contents(__DIR__.'/../Schema/Sqlite.php');
        $this->assertSame(0, preg_match('/\bid INTEGER PRIMARY KEY,/', $src), 'every SQLite surrogate key is AUTOINCREMENT');
        $this->assertSame(10, substr_count($src, 'id INTEGER PRIMARY KEY AUTOINCREMENT'), 'v1 tables plus the v2 rebuild of vault_grants and the v3 rebuild of vault_audit');
    }

    // R26: deleting a user no longer deletes the principal (the purge must first turn its grants and key rows into
    // re-keys). Its live_user_id becomes NULL, which is how the purge finds it; wraps and sessions still cascade.
    // Deleting the principal then takes its grants and key rows with it.
    public function testUserDeleteOrphansPrincipalAndPrincipalDeleteCascades(): void
    {
        $this->migrate();
        $uid = $this->container['userModel']->create(['username' => 'bob', 'password' => 'secret123']);
        $this->assertSame(2, $uid);
        $db = $this->container['db'];
        $db->table('vault_principals')->insert(['user_id' => 2, 'live_user_id' => 2] + self::ROWS['vault_principals']);
        $db->table('vault_wraps')->insert(['user_id' => 2] + self::ROWS['vault_wraps']);
        $db->table('vault_grants')->insert(['grantee_id' => 2] + self::ROWS['vault_grants']);
        $db->table('vault_keys')->insert(['principal_id' => 2] + self::ROWS['vault_keys']);

        $this->assertTrue($this->container['userModel']->remove(2));
        $p = $db->table('vault_principals')->eq('user_id', 2)->findOne();
        $this->assertNotNull($p, 'the principal outlives the user row');
        $this->assertNull($p['live_user_id']);
        $this->assertSame(0, $db->table('vault_wraps')->eq('user_id', 2)->count(), 'wraps still cascade off users');
        $this->assertSame(1, $db->table('vault_grants')->eq('grantee_id', 2)->count(), 'grants wait for the purge');
        $this->assertSame(1, $db->table('vault_keys')->eq('principal_id', 2)->count(), 'key rows wait for the purge');

        $this->assertTrue($db->table('vault_principals')->eq('user_id', 2)->remove());
        $this->assertSame(0, $db->table('vault_grants')->eq('grantee_id', 2)->count());
        $this->assertSame(0, $db->table('vault_keys')->eq('principal_id', 2)->count());
    }

    // A v1 install migrates to v2 with its rows, ids and AUTOINCREMENT counters intact; live_user_id is filled in.
    public function testVersion2MigratesAVersion1Install(): void
    {
        vault_test_sqlite_only(); // T24: SQLite-specific (PRAGMA, sqlite_master or Schema/Sqlite.php)
        require_once __DIR__.'/../Schema/Sqlite.php';
        $pdo = $this->container['db']->getConnection();
        \Kanboard\Plugin\Vault\Schema\version_1($pdo);
        $db = $this->container['db'];
        $db->table('vault_principals')->insert(self::ROWS['vault_principals']);
        foreach ([1, 2, 3] as $i) {
            $db->table('vault_grants')->insert(['subject_id' => $i] + self::ROWS['vault_grants']);
        }
        $db->table('vault_grants')->eq('id', 3)->remove();
        $db->table('vault_keys')->insert(self::ROWS['vault_keys']);

        \Kanboard\Plugin\Vault\Schema\version_2($pdo);

        $this->assertSame('1', (string) $db->table('vault_principals')->eq('user_id', 1)->findOneColumn('live_user_id'));
        $this->assertSame([1, 2], array_map('intval', $db->table('vault_grants')->asc('id')->findAllByColumn('id')));
        $this->assertSame(1, $db->table('vault_keys')->count());
        $db->table('vault_grants')->insert(['subject_id' => 9] + self::ROWS['vault_grants']);
        $this->assertSame(4, (int) $db->getLastId(), 'the AUTOINCREMENT counter survived the rebuild');
        $this->assertArrayHasKey('org_pk', $db->table('vault_meta')->findOne());
        $fks = $pdo->query('PRAGMA foreign_key_list(vault_grants)')->fetchAll(\PDO::FETCH_ASSOC);
        $this->assertContains(['vault_principals', 'grantee_id', 'CASCADE'], array_map(static fn ($f) => [$f['table'], $f['from'], $f['on_delete']], $fks));
    }

    private function users(string ...$names): void
    {
        foreach ($names as $name) {
            $this->container['userModel']->create(['username' => $name, 'password' => 'secret123']);
        }
    }

    public function testDeletingEditorKeepsEntryInOwnersGroup(): void
    {
        $this->migrate();
        $this->users('owner', 'editor'); // ids 2 and 3
        $db = $this->container['db'];
        $db->table('vault_principals')->insert(['user_id' => 2, 'live_user_id' => 2] + self::ROWS['vault_principals']);
        $db->table('vault_groups')->insert(['owner_id' => 2] + self::ROWS['vault_groups']);
        $db->table('vault_entries')->insert(['owner_id' => 2, 'created_by' => 3] + self::ROWS['vault_entries']);
        $db->table('vault_grants')->insert(['grantee_id' => 2, 'granted_by' => 3] + self::ROWS['vault_grants']);

        $this->assertTrue($this->container['userModel']->remove(3));

        $entry = $db->table('vault_entries')->eq('owner_id', 2)->findOne();
        $this->assertNotNull($entry);
        $this->assertNull($entry['created_by']);
        $grant = $db->table('vault_grants')->eq('grantee_id', 2)->findOne();
        $this->assertNotNull($grant);
        $this->assertNull($grant['granted_by']);
    }

    public function testAuditSurvivesActorDeletion(): void
    {
        $this->migrate();
        $this->users('actor', 'target'); // ids 2 and 3
        $db = $this->container['db'];
        $db->table('vault_audit')->insert(['actor_user_id' => 2, 'target_user_id' => 3, 'action' => 'grant'] + self::ROWS['vault_audit']);

        $this->assertTrue($this->container['userModel']->remove(2));
        $this->assertTrue($this->container['userModel']->remove(3));

        $rows = $db->table('vault_audit')->findAll();
        $this->assertCount(1, $rows);
        $this->assertSame('grant', $rows[0]['action']);
        $this->assertNull($rows[0]['actor_user_id']);
        $this->assertNull($rows[0]['target_user_id']);
    }

    public function testAllThreeDialectsDeclareVersion2(): void
    {
        $tables = array_merge(['vault_meta'], array_keys(self::ROWS));
        foreach (['Sqlite', 'Mysql', 'Postgres'] as $d) {
            $src = file_get_contents(__DIR__."/../Schema/$d.php");
            $this->assertStringContainsString('const VERSION = 4;', $src, $d);
            $this->assertStringContainsString('function version_1($pdo)', $src, $d);
            $this->assertStringContainsString('function version_2($pdo)', $src, $d);
            // Comments mention constraints too; count code only.
            [$v1, $v2] = explode('function version_2($pdo)', explode('function version_3($pdo)', preg_replace('#^\s*//.*$#m', '', $src))[0]);
            foreach ($tables as $t) {
                $this->assertStringContainsString("CREATE TABLE IF NOT EXISTS $t (", $v1, "$d: $t");
            }
            $this->assertStringContainsString('INSERT INTO vault_meta', $v1, $d);
            foreach (['created_by', 'granted_by', 'actor_user_id', 'target_user_id'] as $col) {
                $this->assertMatchesRegularExpression("/FOREIGN KEY\\($col\\) REFERENCES users\\(id\\) ON DELETE SET NULL/", $v1, "$d: $col");
            }
            $this->assertSame(4, substr_count($v1, 'ON DELETE SET NULL'), "$d v1: only provenance columns are SET NULL");
            // v2 (R26): live_user_id SET NULL; grants and key rows cascade off vault_principals.
            $this->assertMatchesRegularExpression('/FOREIGN KEY\\(live_user_id\\) REFERENCES users\\(id\\) ON DELETE SET NULL/', $v2, $d);
            $this->assertMatchesRegularExpression('/FOREIGN KEY\\(grantee_id\\) REFERENCES vault_principals\\(user_id\\) ON DELETE CASCADE/', $v2, $d);
            $this->assertMatchesRegularExpression('/FOREIGN KEY\\(principal_id\\) REFERENCES vault_principals\\(user_id\\) ON DELETE CASCADE/', $v2, $d);
            foreach (['org_pk', 'last_purge_at', 'rotate_requested', 'notices'] as $col) {
                $this->assertStringContainsString($col, $v2, "$d: $col");
            }
        }
        // Final review I1: the FKs to users are found in the catalogue, never dropped by an assumed name.
        $pg = file_get_contents(__DIR__.'/../Schema/Postgres.php');
        $this->assertStringContainsString('pg_constraint', $pg);
        $this->assertStringNotContainsString('_fkey', $pg);
        $this->assertStringContainsString("LOWER(REFERENCED_TABLE_NAME) = 'users'", file_get_contents(__DIR__.'/../Schema/Mysql.php'));
        $mysql = file_get_contents(__DIR__.'/../Schema/Mysql.php');
        $this->assertSame(2, substr_count($mysql, 'ciphertext LONGTEXT NOT NULL'), 'entry and group ciphertext are LONGTEXT');
    }

    // v3 (R39, R32): actor_kind gains 'system' (an actor-less action in a web request) and vault_rotations keeps
    // the sweep cursor. A v2 install keeps its audit rows, ids and AUTOINCREMENT counter. Kills: the CHECK left
    // without 'system' (the insert throws), the cursor columns missing, the rebuild dropping rows or the counter.
    public function testVersion3AllowsSystemActorAndKeepsTheSweepCursor(): void
    {
        vault_test_sqlite_only(); // T24: SQLite-specific (PRAGMA, sqlite_master or Schema/Sqlite.php)
        require_once __DIR__.'/../Schema/Sqlite.php';
        $pdo = $this->container['db']->getConnection();
        \Kanboard\Plugin\Vault\Schema\version_1($pdo);
        \Kanboard\Plugin\Vault\Schema\version_2($pdo);
        $db = $this->container['db'];
        foreach ([1, 2, 3] as $i) {
            $db->table('vault_audit')->insert(['created_at' => $i] + self::ROWS['vault_audit']);
        }
        $db->table('vault_audit')->eq('id', 3)->remove();
        $refused = false;
        try {
            $pdo->exec("INSERT INTO vault_audit (created_at, actor_kind, action, via) VALUES (1, 'system', 'share_expire', 'ui')");
        } catch (\PDOException) {
            $refused = true;
        }
        $this->assertTrue($refused, 'control: v2 refuses actor_kind system');

        \Kanboard\Plugin\Vault\Schema\version_3($pdo);

        $this->assertSame([1, 2], array_map('intval', $db->table('vault_audit')->asc('id')->findAllByColumn('id')));
        $pdo->exec("INSERT INTO vault_audit (created_at, actor_kind, action, via) VALUES (1, 'system', 'share_expire', 'ui')");
        $this->assertSame(4, (int) $pdo->lastInsertId(), 'the AUTOINCREMENT counter survived the rebuild');
        $bad = false;
        try {
            $pdo->exec("INSERT INTO vault_audit (created_at, actor_kind, action, via) VALUES (1, 'robot', 'share_expire', 'ui')");
        } catch (\PDOException) {
            $bad = true;
        }
        $this->assertTrue($bad, 'the CHECK still refuses unknown kinds');
        $cols = array_column($pdo->query('PRAGMA table_info(vault_rotations)')->fetchAll(\PDO::FETCH_ASSOC), 'name');
        $this->assertContains('sweep_type', $cols);
        $this->assertContains('sweep_id', $cols);
        $fks = $pdo->query('PRAGMA foreign_key_list(vault_audit)')->fetchAll(\PDO::FETCH_ASSOC);
        $this->assertCount(2, array_filter($fks, static fn ($f) => $f['table'] === 'users' && $f['on_delete'] === 'SET NULL'));
    }

    // T24: every version of the connection's own dialect, v1 to the latest, in one go, as a fresh install runs them;
    // the suite runs this on SQLite, and run-realdb-tests.sh on MariaDB and Postgres. MariaDB refused v3's DROP
    // CONSTRAINT of its column-level CHECK. Kills: a dialect's migration that fails on its own database, or a v3
    // that leaves the old actor_kind list (system refused) or no list (robot accepted).
    public function testOwnDialectMigratesFromScratchAndChecksActorKind(): void
    {
        $this->migrate();
        $pdo = $this->container['db']->getConnection();
        $pdo->exec("INSERT INTO vault_audit (created_at, actor_kind, action, via) VALUES (1, 'system', 'share_expire', 'ui')");
        $this->assertSame(1, (int) $pdo->query("SELECT COUNT(*) FROM vault_audit WHERE actor_kind = 'system'")->fetchColumn());
        $refused = false;
        try {
            $pdo->exec("INSERT INTO vault_audit (created_at, actor_kind, action, via) VALUES (1, 'robot', 'share_expire', 'ui')");
        } catch (\PDOException) {
            $refused = true;
        }
        $this->assertTrue($refused, 'the CHECK still refuses unknown kinds ('.$pdo->getAttribute(\PDO::ATTR_DRIVER_NAME).')');
    }

    // T24 (found on a real Postgres): Kanboard's users.is_active is a BOOLEAN there, and "is_active = 1" is an error
    // (operator does not exist: boolean = integer), which broke unlock, sharing, the notifier and the purge. Vault's
    // SQL binds the value instead (a bound 1 is a valid boolean on Postgres and an integer elsewhere). Kills: any
    // Kanboard flag compared with a literal 0 or 1 again.
    public function testNoKanboardFlagIsComparedWithAnIntegerLiteral(): void
    {
        $hits = [];
        foreach (['Model', 'Controller', 'Api', 'Console', 'Subscriber'] as $dir) {
            foreach (glob(__DIR__."/../$dir/*.php") as $file) {
                foreach (file($file) as $n => $line) {
                    if (preg_match('/\bis_[a-z_]+\s*(=|<>|!=)\s*[01]\b/', $line)) {
                        $hits[] = basename($file).':'.($n + 1);
                    }
                }
            }
        }
        $this->assertSame([], $hits);
    }

    // The three dialects declare the same v3 change. MySQL and Postgres drop the old CHECK by name and fail loudly
    // (no IF EXISTS) if it isn't there. Real-DB runs belong to T24/T25 (R35).
    public function testAllThreeDialectsDeclareVersion3(): void
    {
        foreach (['Sqlite', 'Mysql', 'Postgres'] as $d) {
            $src = preg_replace('#^\s*//.*$#m', '', file_get_contents(__DIR__."/../Schema/$d.php"));
            $v3 = explode('function version_3($pdo)', $src)[1] ?? '';
            $this->assertStringContainsString("'human', 'agent', 'public', 'cli', 'system'", $v3, $d);
            $this->assertStringContainsString('sweep_type', $v3, $d);
            $this->assertStringContainsString('sweep_id', $v3, $d);
            if ($d !== 'Sqlite') {
                $this->assertStringNotContainsString('IF EXISTS', $v3, "$d drops the old CHECK loudly");
            }
        }
    }

    // v4 (T17): a reservation keeps the share expiry it was made with (that expiry is in the share's AD, so finalize
    // must use exactly it); vault_shares carries crypto_v = 1 like every encrypted row; on MySQL the share ciphertext
    // is MEDIUMTEXT, because a 64 KB payload in base64 is larger than TEXT's 64 KiB. Kills: a dialect missing a change,
    // the MySQL column left TEXT (a 64 KB share would fail or be truncated there).
    public function testVersion4ShareColumns(): void
    {
        require_once __DIR__.'/Support/Migrate.php';
        $pdo = $this->container['db']->getConnection();
        vault_test_migrate($pdo);
        $res = vault_test_column_info($pdo, 'vault_share_reservations');
        $this->assertSame(['0', true], array_slice($res['share_expires_at'], 0, 2));
        $shares = vault_test_column_info($pdo, 'vault_shares');
        $this->assertSame(['1', true], array_slice($shares['crypto_v'], 0, 2));
        if (DB_DRIVER === 'mysql') {
            $this->assertSame('mediumtext', $shares['ciphertext'][2], 'the live MariaDB column holds a 64 KB share');
        }
        foreach (['Sqlite', 'Mysql', 'Postgres'] as $d) {
            $src = preg_replace('#^\s*//.*$#m', '', file_get_contents(__DIR__."/../Schema/$d.php"));
            $v4 = explode('function version_4($pdo)', $src)[1] ?? '';
            // MySQL adds each column through add_column (final review I2: a re-run skips what is there).
            $this->assertMatchesRegularExpression("/ALTER TABLE vault_share_reservations ADD COLUMN share_expires_at \\w+ NOT NULL DEFAULT 0|add_column\\(\\\$pdo, 'vault_share_reservations', 'share_expires_at', '\\w+ NOT NULL DEFAULT 0'\\)/", $v4, $d);
            $this->assertMatchesRegularExpression("/ALTER TABLE vault_shares ADD COLUMN crypto_v \\w+ NOT NULL DEFAULT 1|add_column\\(\\\$pdo, 'vault_shares', 'crypto_v', '\\w+ NOT NULL DEFAULT 1'\\)/", $v4, $d);
        }
        $mysql = explode('function version_4($pdo)', file_get_contents(__DIR__.'/../Schema/Mysql.php'))[1];
        $this->assertStringContainsString('ALTER TABLE vault_shares MODIFY ciphertext MEDIUMTEXT NOT NULL', $mysql);
    }

    // Final review I5: vault_test_dump is the logical backup three secondary backup-theft proofs search. Plain
    // json_encode wrote "/" as "\/", so a base64 needle containing "/" never matched and assertStringNotContainsString
    // passed vacuously; on a non-UTF-8 value it returned false and the whole table vanished from the dump. Kills: the
    // flags dropped (the "/" needle is missed) or a table silently left out.
    public function testDumpKeepsSlashesAndEveryTable(): void
    {
        $this->migrate();
        $pdo = $this->container['db']->getConnection();
        $needle = 'ab/cd+ef/gh==';
        $pdo->prepare('INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES (?, 1, 1)')->execute([$needle]);
        $this->assertStringContainsString($needle, vault_test_dump($pdo));
        if (DB_DRIVER === 'sqlite') {
            // Only SQLite stores invalid UTF-8 in a TEXT column; MariaDB and Postgres refuse it on insert.
            $pdo->prepare('INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES (?, 1, 1)')->execute(["bad\xff"]);
            $this->assertStringContainsString($needle, vault_test_dump($pdo), 'a non-UTF-8 row does not drop the table');
        }
    }

    // FK constraint names from (table, column) to users, read from the catalogue the way an operator would check.
    private static function userFks(\PDO $pdo, string $table, string $column): array
    {
        $sql = match ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME)) {
            'mysql' => "SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE()
                AND LOWER(TABLE_NAME) = LOWER(?) AND COLUMN_NAME = ? AND LOWER(REFERENCED_TABLE_NAME) = 'users'",
            'pgsql' => "SELECT c.conname FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
                WHERE c.contype = 'f' AND n.nspname = current_schema() AND t.relname = ? AND a.attname = ? AND c.confrelid = to_regclass('users')::oid",
        };
        $st = $pdo->prepare($sql);
        $st->execute([$table, $column]);
        return $st->fetchAll(\PDO::FETCH_COLUMN);
    }

    private const USER_FK_COLUMNS = [['vault_principals', 'user_id'], ['vault_grants', 'grantee_id'], ['vault_keys', 'principal_id']];

    private static function requireServerDb(): void
    {
        if (DB_DRIVER === 'sqlite') {
            self::markTestSkipped('MariaDB/Postgres catalogue; this run is sqlite');
        }
    }

    private static function requireMysql(): void
    {
        if (DB_DRIVER !== 'mysql') {
            self::markTestSkipped('MySQL/MariaDB migration chain; this run is '.DB_DRIVER);
        }
    }

    private function loadDialect(\PDO $pdo): void
    {
        require_once __DIR__.'/../Schema/'.($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql' ? 'Mysql' : 'Postgres').'.php';
    }

    // Final review I1 (ledger T9): v2 drops the FKs from vault_principals.user_id, vault_grants.grantee_id and
    // vault_keys.principal_id to users (R26: a deleted user must not cascade away grants and key rows unqueued). Postgres
    // dropped them by an assumed default name with IF EXISTS, so an install whose constraints carry other names kept
    // them and v2 still "succeeded". The v1 FKs here are renamed (Postgres) or re-created under other names (MariaDB)
    // before v2 runs. Kills: a drop by assumed name; a lookup that misses the FK.
    public function testVersion2DropsUserForeignKeysWhateverTheirNames(): void
    {
        self::requireServerDb();
        $pdo = $this->container['db']->getConnection();
        $this->loadDialect($pdo);
        \Kanboard\Plugin\Vault\Schema\version_1($pdo);
        foreach (self::USER_FK_COLUMNS as $i => [$table, $column]) {
            [$name] = self::userFks($pdo, $table, $column);
            if (DB_DRIVER === 'mysql') {
                $pdo->exec("ALTER TABLE $table DROP FOREIGN KEY `$name`");
                $pdo->exec("ALTER TABLE $table ADD CONSTRAINT legacy_user_fk_$i FOREIGN KEY($column) REFERENCES users(id) ON DELETE CASCADE");
            } else {
                $pdo->exec("ALTER TABLE $table RENAME CONSTRAINT \"$name\" TO legacy_user_fk_$i");
            }
            $this->assertSame(["legacy_user_fk_$i"], self::userFks($pdo, $table, $column));
        }
        \Kanboard\Plugin\Vault\Schema\version_2($pdo);
        foreach (self::USER_FK_COLUMNS as [$table, $column]) {
            $this->assertSame([], self::userFks($pdo, $table, $column), "$table.$column still references users");
        }
    }

    // Final review I1: after its drops, v2 checks the catalogue and fails the migration with a PDOException (the one
    // type Kanboard's SchemaHandler catches, rolls back on and re-enables FK checks after) if any FK to users is left.
    // Kills: the post-condition check missing, or throwing another type.
    public function testUserForeignKeyCheckThrowsPdoException(): void
    {
        self::requireServerDb();
        $pdo = $this->container['db']->getConnection();
        $this->loadDialect($pdo);
        \Kanboard\Plugin\Vault\Schema\version_1($pdo);
        foreach (self::USER_FK_COLUMNS as [$table, $column]) {
            try {
                \Kanboard\Plugin\Vault\Schema\assert_no_user_fk($pdo, $table, $column);
                $this->fail("$table.$column: a remaining FK to users is not accepted");
            } catch (\PDOException $e) {
                $this->assertStringContainsString($table, $e->getMessage());
            }
        }
    }

    // Final review I2 (ledger T24 M5). MySQL DDL commits implicitly, and Kanboard's SchemaHandler records the version
    // only after the last one ran, so a failure in v3 leaves v1 and v2 applied with the version still 0, and the next
    // request runs v1 to v4 again. Here v3 fails midway (after its CHECK swap, at the sweep columns: vault_rotations is
    // moved away first), then SchemaHandler migrates from 0. Kills: any MySQL version that isn't idempotent (v2's
    // duplicate ADD COLUMN was the first); a v3 failure thrown as anything but PDOException.
    public function testMysqlChainResumesAfterAFailureMidway(): void
    {
        self::requireMysql();
        $pdo = $this->container['db']->getConnection();
        $this->loadDialect($pdo);
        $p = $pdo->prepare('INSERT INTO users (username, password) VALUES (?, ?)');
        $p->execute(['vault.resume', 'x']);
        $user = (int) $pdo->lastInsertId();
        \Kanboard\Plugin\Vault\Schema\version_1($pdo);
        $pdo->prepare("INSERT INTO vault_principals (user_id, kind, public_key, created_at) VALUES (?, 'human', 'cGs=', 1)")->execute([$user]);
        \Kanboard\Plugin\Vault\Schema\version_2($pdo);
        $pdo->exec('RENAME TABLE vault_rotations TO vault_rotations_moved');
        try {
            \Kanboard\Plugin\Vault\Schema\version_3($pdo);
            $this->fail('v3 fails while vault_rotations is away');
        } catch (\PDOException) {
        }
        $pdo->exec('RENAME TABLE vault_rotations_moved TO vault_rotations');

        $handler = new \Kanboard\Core\Plugin\SchemaHandler($this->container);
        $this->assertSame(0, $handler->getSchemaVersion('Vault'));
        $handler->migrateSchema('Vault');
        $this->assertSame(4, $handler->getSchemaVersion('Vault'));

        $this->assertSame($user, (int) $pdo->query('SELECT live_user_id FROM vault_principals')->fetchColumn());
        foreach (['org_pk', 'last_purge_at'] as $c) {
            $this->assertContains($c, vault_test_columns($pdo, 'vault_meta'));
        }
        foreach (['sweep_type', 'sweep_id'] as $c) {
            $this->assertContains($c, vault_test_columns($pdo, 'vault_rotations'));
        }
        $this->assertContains('share_expires_at', vault_test_columns($pdo, 'vault_share_reservations'));
        foreach (self::USER_FK_COLUMNS as [$table, $column]) {
            $this->assertSame([], self::userFks($pdo, $table, $column));
        }
        $pdo->exec("INSERT INTO vault_audit (created_at, actor_kind, action, via) VALUES (1, 'system', 'share_expire', 'ui')");
        $refused = false;
        try {
            $pdo->exec("INSERT INTO vault_audit (created_at, actor_kind, action, via) VALUES (1, 'robot', 'share_expire', 'ui')");
        } catch (\PDOException) {
            $refused = true;
        }
        $this->assertTrue($refused, 'the actor_kind CHECK survives the resume');

        // Every version runs again over a finished schema without error (each step checks before it alters).
        vault_test_migrate($pdo);
    }

    // Final review I2: v3 on MySQL throws PDOException, never RuntimeException, when the actor_kind CHECK is gone (here
    // removed by hand before v3), so SchemaHandler rolls back and re-enables FK checks. Kills: RuntimeException back.
    public function testMysqlVersion3WithoutActorKindCheckThrowsPdoException(): void
    {
        self::requireMysql();
        $pdo = $this->container['db']->getConnection();
        $this->loadDialect($pdo);
        \Kanboard\Plugin\Vault\Schema\version_1($pdo);
        \Kanboard\Plugin\Vault\Schema\version_2($pdo);
        $pdo->exec('ALTER TABLE vault_audit MODIFY actor_kind VARCHAR(16) NOT NULL');
        $st = $pdo->query("SELECT CONSTRAINT_NAME FROM information_schema.CHECK_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = DATABASE() AND CHECK_CLAUSE LIKE '%actor_kind%'");
        foreach ($st->fetchAll(\PDO::FETCH_COLUMN) as $name) {
            $pdo->exec('ALTER TABLE vault_audit DROP CONSTRAINT `'.$name.'`');
        }
        $this->expectException(\PDOException::class);
        \Kanboard\Plugin\Vault\Schema\version_3($pdo);
    }
}
