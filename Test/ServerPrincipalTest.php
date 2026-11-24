<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';
require_once __DIR__.'/Support/Migrate.php';

use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\DekContext;
use Kanboard\Plugin\Vault\Model\ServerKeyFile;
use Kanboard\Plugin\Vault\Model\ServerKeyUnavailable;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Model\VaultFailure;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec amendment: Principals (the server kind, reserved id -1), Server key file, security requirement 2 (Server
// opens a DEK only with the key file). Rulings R1 (the field-MAC key, sealed to Server, made at on, gone at off).
class ServerPrincipalTest extends Base
{
    use ServerFixture;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpAgents();
        $this->setUpServer();
    }

    protected function tearDown(): void
    {
        $this->tearDownServer();
        $this->tearDownVault();
        parent::tearDown();
    }

    // Fails when $secret is in $dump raw, hex, base64 or base64url (padded or not).
    private function assertNotInDump(string $secret, string $dump, string $what): void
    {
        $b64 = base64_encode($secret);
        $url = strtr($b64, '+/', '-_');
        foreach (['raw' => $secret, 'hex' => bin2hex($secret), 'HEX' => strtoupper(bin2hex($secret)), 'base64' => $b64,
            'base64 unpadded' => rtrim($b64, '='), 'base64url' => $url, 'base64url unpadded' => rtrim($url, '=')] as $form => $s) {
            $this->assertStringNotContainsString($s, $dump, "$what ($form) in the database");
        }
    }

    // Spec: Principals (server kind, reserved id -1, wrap method server with KEK = BLAKE2b(key = server_file_key,
    // msg = enc("kek", "server", principal_id))). Kills: a KEK without the principal id; a wrap whose AD doesn't bind its
    // wrap id; live_user_id set; a provider other than file; enabling without a key file.
    public function testEnableCreatesThePrincipalWrapAndKeyFile(): void
    {
        $this->enableServer();
        $p = $this->row('SELECT * FROM vault_principals WHERE user_id = ?', [ServerPrincipal::ID]);
        $this->assertSame(['server', null, 'active'], [$p['kind'], $p['live_user_id'], $p['state']]);
        $meta = $this->row('SELECT server_provider, server_wrap_id, server_wrap_nonce, server_wrapped_sk FROM vault_meta WHERE id = 1');
        $this->assertSame(['file', 1], [$meta['server_provider'], (int) $meta['server_wrap_id']]);
        $this->assertSame(0600, fileperms($this->keyPath) & 07777);
        $fileKey = (new ServerKeyFile($this->keyPath))->read();
        $wrap = ['id' => 1, 'user_id' => -1, 'method' => 'server', 'credential_id' => null,
            'nonce' => $meta['server_wrap_nonce'], 'wrapped_sk' => $meta['server_wrapped_sk'], 'crypto_v' => 1];
        $pk = base64_decode($p['public_key']);
        $this->assertSame(32, strlen(Wraps::unwrap($wrap, Kdf::kek($fileKey, 'server', -1), $pk)));
        foreach ([[['id' => 2] + $wrap, Kdf::kek($fileKey, 'server', -1)], [$wrap, Kdf::kek($fileKey, 'server', -2)]] as [$w, $kek]) {
            try {
                Wraps::unwrap($w, $kek, $pk); // the AD binds wrap id 1; the KEK binds principal -1
                $this->fail('a wrap opened under another id');
            } catch (CryptoException) {
            }
        }
        $this->assertTrue($this->server()->isOn());
        $this->assertSame($pk, $this->server()->publicKey());
        $this->assertSame('file', $this->freshProvider()->id());
        $this->assertTrue($this->freshProvider()->healthy());
    }

    // Kills: enabling without a usable key file (the principal or wrap written anyway).
    public function testEnableRefusesAnUnsafeKeyPath(): void
    {
        mkdir($this->serverDir.'/real', 0700);
        symlink($this->serverDir.'/real', $this->serverDir.'/link');
        unset($this->container['vaultServerKeyFile']);
        $this->container['vaultServerKeyFile'] = fn () => new ServerKeyFile($this->serverDir.'/link/vault-server/server.key');
        try {
            $this->enableServer();
            $this->fail('enabled through a symlinked path');
        } catch (ServerKeyUnavailable $e) {
            $this->assertSame([409, 'server_key_unavailable'], VaultFailure::map($e), 'the admin is told, not a bare failure');
        }
        $this->assertFalse($this->server()->isOn());
        $this->assertNull($this->server()->publicKey());
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_principals WHERE user_id = -1'));
        $this->assertNull($this->row('SELECT server_wrapped_sk FROM vault_meta WHERE id = 1')['server_wrapped_sk']);
        $this->assertSame([], $this->auditRows('policy_change'));
        $this->assertFileDoesNotExist($this->serverDir.'/real/vault-server/server.key');
    }

    // A second enable keeps the keypair and wrap; one policy_change per state change (on, off), by the admin.
    // Mutation: re-keying on every enable.
    public function testEnableIsIdempotentAndAudited(): void
    {
        $this->enableServer();
        $pk = $this->row('SELECT public_key FROM vault_principals WHERE user_id = -1')['public_key'];
        $mac = $this->row('SELECT server_field_mac_sealed FROM vault_meta WHERE id = 1')['server_field_mac_sealed'];
        $this->enableServer();
        $this->assertSame($pk, $this->row('SELECT public_key FROM vault_principals WHERE user_id = -1')['public_key']);
        $this->assertSame([1, $mac], array_map(fn ($v) => is_numeric($v) ? (int) $v : $v, array_values($this->row('SELECT server_wrap_id, server_field_mac_sealed FROM vault_meta WHERE id = 1'))));
        $this->assertCount(1, $this->auditRows('policy_change'));

        $this->server()->disable(self::ADMIN);
        $this->server()->disable(self::ADMIN);
        $rows = $this->auditRows('policy_change');
        $this->assertCount(2, $rows, 'on, then off; the second off changed nothing');
        foreach ($rows as $row) {
            $this->assertSame((string) self::ADMIN, (string) $row['actor_user_id']);
        }

        // On again: a new keypair under the next wrap id (never reused).
        $this->enableServer();
        $this->assertNotSame($pk, $this->row('SELECT public_key FROM vault_principals WHERE user_id = -1')['public_key']);
        $this->assertSame(2, (int) $this->row('SELECT server_wrap_id FROM vault_meta WHERE id = 1')['server_wrap_id']);
        $this->assertSame(32, strlen($this->serverSk()));
    }

    // Security requirement 2: a DEK sealed to Server opens only with the key file. Mutation: the file key or the sk
    // stored in vault_meta.
    public function testOpenSealedDekNeedsTheKeyFile(): void
    {
        $this->enableServer();
        $pk = $this->server()->publicKey();
        $dek = random_bytes(32);
        $sealed = Sealer::sealDek($dek, 'entry', 7, 1, -1, $pk);
        $this->assertSame($dek, $this->freshProvider()->openSealedDek($sealed, new DekContext('entry', 7, 1, -1)));
        foreach ([new DekContext('entry', 7, 2, -1), new DekContext('group', 7, 1, -1), new DekContext('entry', 8, 1, -1), new DekContext('entry', 7, 1, $this->alice)] as $ctx) {
            try {
                $this->freshProvider()->openSealedDek($sealed, $ctx);
                $this->fail('opened under another context');
            } catch (ServerKeyUnavailable) {
            }
        }

        $fileKey = (new ServerKeyFile($this->keyPath))->read();
        $sk = $this->serverSk();
        $dump = vault_test_dump($this->pdo());
        $this->assertNotInDump($fileKey, $dump, 'the file key');
        $this->assertNotInDump($sk, $dump, 'the Server sk');

        file_put_contents($this->keyPath, random_bytes(32));
        chmod($this->keyPath, 0600);
        $provider = $this->freshProvider();
        $this->assertFalse($provider->healthy());
        try {
            $provider->openSealedDek($sealed, new DekContext('entry', 7, 1, -1));
            $this->fail('opened with another file key');
        } catch (ServerKeyUnavailable $e) {
            $this->assertNull($e->getPrevious());
        }
        unlink($this->keyPath);
        $this->assertFalse($this->freshProvider()->healthy());
        try {
            $this->freshProvider()->openSealedDek($sealed, new DekContext('entry', 7, 1, -1));
            $this->fail('opened without a key file');
        } catch (ServerKeyUnavailable) {
        }
        $this->assertFileDoesNotExist($this->keyPath, 'a read never creates the key file');
    }

    // R1: the field-MAC key is 32 random bytes sealed to the Server pk in vault_meta, opened through the KeyProvider
    // (so it needs the key file), and deleted when Server goes off. Kills: the key stored plain; a key that doesn't
    // need the key file; a key left behind at off; the same key after off and on.
    public function testFieldMacKeyIsSealedToServerAndDroppedWhenOff(): void
    {
        $this->enableServer();
        $sealed = $this->row('SELECT server_field_mac_sealed FROM vault_meta WHERE id = 1')['server_field_mac_sealed'];
        $raw = base64_decode((string) $sealed, true);
        $this->assertNotFalse($raw);
        $this->assertSame(32 + SODIUM_CRYPTO_BOX_SEALBYTES + strlen(\Kanboard\Plugin\Vault\Crypto\Encoding::enc('fieldmac', -1, '')), strlen($raw));
        $key = $this->freshProvider()->openFieldMacKey();
        $this->assertSame(32, strlen($key));
        $sk = $this->serverSk();
        $kp = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, $this->server()->publicKey());
        $this->assertSame($key, Sealer::openFieldMacKey($raw, $kp, -1), 'sealed to the Server pk with its principal id');
        $this->assertSame($key, $this->freshProvider()->openFieldMacKey(), 'stable while on');
        $this->assertNotInDump($key, vault_test_dump($this->pdo()), 'the field-MAC key');

        rename($this->keyPath, $this->keyPath.'.away');
        try {
            $this->freshProvider()->openFieldMacKey();
            $this->fail('opened without the key file');
        } catch (ServerKeyUnavailable) {
        }
        rename($this->keyPath.'.away', $this->keyPath);

        $this->server()->disable(self::ADMIN);
        $this->assertNull($this->row('SELECT server_field_mac_sealed FROM vault_meta WHERE id = 1')['server_field_mac_sealed']);
        try {
            $this->freshProvider()->openFieldMacKey();
            $this->fail('a field-MAC key after off');
        } catch (ServerKeyUnavailable) {
        }
        $this->enableServer();
        $this->assertNotSame($key, $this->freshProvider()->openFieldMacKey(), 'a new key at the next on');
    }

    // disable: every Server grant through removeSource (key rows dropped, the entry queued at its epoch), the
    // remaining -1 key rows, the wrap (wrap id kept), the field-MAC key, the principal and the srvread buckets.
    // Mutation: deleting only the grant rows.
    public function testDisableRemovesEveryServerKeyRowAndGrant(): void
    {
        $this->enableServer();
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'ops']);
        $e = $this->store()->createEntry($this->alice, $g, Fixtures::entry('Server entry'));
        $epoch = (int) $this->row('SELECT key_epoch FROM vault_entries WHERE id = ?', [$e])['key_epoch'];
        $this->pdo()->prepare("INSERT INTO vault_grants (subject_type, subject_id, grantee_id, permission, granted_by, expires_at, created_at, consumers, fields, rate_per_hour, rate_burst)
            VALUES ('entry', ?, -1, 'read', ?, NULL, ?, '[\"CveHunter\"]', '[\"password\"]', 60, 10)")->execute([$e, $this->alice, $this->now]);
        $sealed = base64_encode(Sealer::sealDek(random_bytes(32), 'entry', $e, $epoch, -1, $this->server()->publicKey()));
        $this->pdo()->prepare("INSERT INTO vault_keys (object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek) VALUES ('entry', ?, -1, 1, ?, ?)")
            ->execute([$e, $epoch, $sealed]);
        $this->pdo()->prepare('INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES (?, 3, ?)')->execute(["srvread:CveHunter:$e", $this->now]);
        $this->pdo()->prepare('INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES (?, 3, ?)')->execute(['unlock:ip:keep', $this->now]);

        $this->server()->disable(self::ADMIN);

        foreach (['vault_grants' => 'grantee_id', 'vault_keys' => 'principal_id', 'vault_principals' => 'user_id'] as $table => $col) {
            $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM $table WHERE $col = -1"), $table);
        }
        $meta = $this->row('SELECT server_provider, server_wrap_id, server_wrap_nonce, server_wrapped_sk, server_field_mac_sealed FROM vault_meta WHERE id = 1');
        $this->assertSame([null, 1, null, null, null], [$meta['server_provider'], (int) $meta['server_wrap_id'], $meta['server_wrap_nonce'], $meta['server_wrapped_sk'], $meta['server_field_mac_sealed']]);
        $q = $this->row("SELECT expected_key_epoch FROM vault_rekey_queue WHERE object_type = 'entry' AND object_id = ?", [$e]);
        $this->assertNotNull($q, 'the entry is queued for re-key');
        $this->assertSame($epoch, (int) $q['expected_key_epoch']);
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_rate WHERE bucket LIKE 'srvread:%'"));
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_rate WHERE bucket = 'unlock:ip:keep'"));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_entries WHERE id = ?', [$e]), 'the entry itself stays');
        $this->assertFalse($this->server()->isOn());
        $this->assertNull($this->server()->publicKey());
    }
}
