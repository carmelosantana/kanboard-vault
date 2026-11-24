<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';
require_once __DIR__.'/Support/Migrate.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec amendment: security requirements 2 and 3. A database backup alone opens nothing sealed to Server: its sk is
// wrapped under the key file, which lives outside DATA_DIR. With the key file too, only the entries an owner shared
// with Server open, never an entry shared with a person or an agent. The attacker below sees only the dumped rows
// (and maybe the key file), and walks the same chain Vault does: vault_meta's Server wrap, each -1 key row, the entry.
class ServerBackupTest extends Base
{
    use ServerFixture;

    private int $a;
    private int $b;
    private int $c;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpAgents();
        $this->principals()->enrolHuman($this->bob, Fixtures::NEW_PASSPHRASE);
        $this->setUpServer();
        $this->enrolDave();
        $this->a = $this->serverShare(['CveHunter'], ['password']);
        $sk = $this->aliceSk();
        $g = $this->store()->createGroup($this->alice, null, ['name' => Fixtures::GROUP_NAME]);
        $this->b = $this->store()->createEntry($this->alice, $g, Fixtures::fullEntry());
        $this->grants()->grant($this->alice, 'entry', $this->b, $this->bob, 'read', null, $sk);
        $this->c = $this->store()->createEntry($this->alice, $g, Fixtures::fullEntry());
        $this->grants()->grant($this->alice, 'entry', $this->c, $this->dave, 'read', null, $sk);
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->serverSecrets()->read('CveHunter', "vault://{$this->a}/password")->reveal());
    }

    protected function tearDown(): void
    {
        $this->tearDownServer();
        $this->tearDownVault();
        parent::tearDown();
    }

    /** @return array<string, list<array<string,mixed>>> every Vault table's rows, as a logical backup holds them */
    private function tables(): array
    {
        $q = $this->pdo()->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql' ? '`' : '"';
        $out = [];
        foreach (vault_test_tables($this->pdo()) as $t) {
            $out[$t] = $this->pdo()->query('SELECT * FROM '.$q.$t.$q)->fetchAll(\PDO::FETCH_ASSOC);
        }
        return $out;
    }

    // The attacker: the decrypted entry ids, from the dumped rows and maybe the key file.
    /** @return list<int> */
    private function decrypt(array $tables, ?string $fileKey): array
    {
        $meta = $tables['vault_meta'][0];
        $principal = array_values(array_filter($tables['vault_principals'], fn (array $p): bool => (int) $p['user_id'] === ServerPrincipal::ID))[0] ?? null;
        $this->assertNotNull($principal, 'the Server principal is in the dump');
        $pk = base64_decode($principal['public_key']);
        try {
            $sk = Wraps::unwrap(['id' => (int) $meta['server_wrap_id'], 'user_id' => ServerPrincipal::ID, 'method' => 'server', 'credential_id' => null,
                'nonce' => $meta['server_wrap_nonce'], 'wrapped_sk' => $meta['server_wrapped_sk'], 'crypto_v' => Wraps::CRYPTO_V],
                Kdf::kek($fileKey ?? random_bytes(32), 'server', ServerPrincipal::ID), $pk);
        } catch (\Throwable) {
            return [];
        }
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, $pk);
        $entries = array_column($tables['vault_entries'], null, 'id');
        $opened = [];
        foreach ($tables['vault_keys'] as $k) {
            if ((int) $k['principal_id'] !== ServerPrincipal::ID || $k['object_type'] !== 'entry') {
                continue;
            }
            $id = (int) $k['object_id'];
            $dek = Sealer::openDek(base64_decode($k['sealed_dek']), $keypair, 'entry', $id, (int) $k['key_epoch'], ServerPrincipal::ID);
            $e = $entries[$id];
            $json = Aead::open(base64_decode($e['nonce']), base64_decode($e['ciphertext']), $dek, ObjectStore::ad('entry', $id, (int) $e['owner_id'], (int) $e['key_epoch']));
            $this->assertSame(Fixtures::ENTRY_PASSWORD, json_decode($json, true)['password']);
            $opened[] = $id;
        }
        sort($opened);
        return $opened;
    }

    // Requirement 2. Kills: the Server sk (or the key file's bytes) stored in the database; any plaintext stored.
    public function testWithoutTheKeyFileNothingDecrypts(): void
    {
        $tables = $this->tables();
        $this->assertSame([], $this->decrypt($tables, null));
        $dump = ['logical dump' => vault_test_dump($this->pdo())];
        $this->assertGreaterThan(0, substr_count($dump['logical dump'], 'ciphertext'), 'the dump has the vault rows');
        $found = [];
        foreach ([...Fixtures::SECRETS, (string) file_get_contents($this->keyPath)] as $i => $secret) {
            foreach (vault_test_hits($dump, $secret) as $hit) {
                $found[] = (isset(Fixtures::SECRETS[$i]) ? $secret : 'the key file').' in '.$hit;
            }
        }
        $this->assertSame([], $found, 'plaintext in the backup');
        $this->assertStringStartsNotWith(realpath(DATA_DIR) ?: DATA_DIR, $this->keyPath, 'the key file lives outside DATA_DIR');
    }

    // Requirement 3. Mutation: sealing to Server on any grant change of other objects.
    public function testWithTheKeyFileOnlyServerSharedEntriesDecrypt(): void
    {
        $tables = $this->tables();
        $this->assertSame([$this->a], $this->decrypt($tables, (string) file_get_contents($this->keyPath)));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE principal_id = -1 AND object_id IN (?, ?)', [$this->b, $this->c]));
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND object_type = 'entry' AND object_id = ?", [$this->bob, $this->b]), 'B is sealed to bob');
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND object_type = 'entry' AND object_id = ?", [$this->dave, $this->c]), 'C is sealed to dave');
    }
}
