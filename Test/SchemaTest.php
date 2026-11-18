<?php
require_once 'tests/units/Base.php';
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
        require_once __DIR__.'/../Schema/Sqlite.php';
        \Kanboard\Plugin\Vault\Schema\version_1($this->container['db']->getConnection());
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
        $this->assertFalse(@$this->container['db']->table('vault_meta')->insert(['id' => 2, 'schema_note' => 'x']));
    }

    public function testCascadeOnUserDelete(): void
    {
        $this->migrate();
        $uid = $this->container['userModel']->create(['username' => 'bob', 'password' => 'secret123']);
        $this->assertSame(2, $uid);
        $db = $this->container['db'];
        $db->table('vault_principals')->insert(['user_id' => 2] + self::ROWS['vault_principals']);
        $this->assertSame(1, $db->table('vault_principals')->eq('user_id', 2)->count());

        $this->assertTrue($this->container['userModel']->remove(2));
        $this->assertSame(0, $db->table('vault_principals')->eq('user_id', 2)->count());
    }

    public function testAllThreeDialectsDeclareVersion1(): void
    {
        $tables = array_merge(['vault_meta'], array_keys(self::ROWS));
        foreach (['Sqlite', 'Mysql', 'Postgres'] as $d) {
            $src = file_get_contents(__DIR__."/../Schema/$d.php");
            $this->assertStringContainsString('const VERSION = 1;', $src, $d);
            $this->assertStringContainsString('function version_1($pdo)', $src, $d);
            foreach ($tables as $t) {
                $this->assertStringContainsString("CREATE TABLE IF NOT EXISTS $t (", $src, "$d: $t");
            }
            $this->assertStringContainsString('INSERT INTO vault_meta', $src, $d);
            $this->assertStringNotContainsString('ON DELETE SET NULL', $src, $d);
        }
        $mysql = file_get_contents(__DIR__.'/../Schema/Mysql.php');
        $this->assertSame(2, substr_count($mysql, 'ciphertext LONGTEXT NOT NULL'), 'entry and group ciphertext are LONGTEXT');
    }
}
