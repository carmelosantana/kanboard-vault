<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Model\DekContext;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\RecipientResolver;
use Kanboard\Plugin\Vault\Model\Rekeyer;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Model\VaultDb;
use Kanboard\Plugin\Vault\Model\VaultLock;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec amendment security requirement 7: Server is only ever a seal target. It never processes the re-key queue,
// never owns an object, never reads through the human read path, never takes a human grant or a group grant and never
// unlocks; another recipient's revocation re-seals the entry to Server while its grant lives.
class ServerExclusionTest extends Base
{
    use ServerFixture;

    private int $g;
    private int $e;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpAgents();
        $this->setUpServer();
        $this->enableServer();
        $this->g = $this->store()->createGroup($this->alice, null, ['name' => 'servers']);
        $this->e = $this->store()->createEntry($this->alice, $this->g, Fixtures::entry('server shared'));
    }

    protected function tearDown(): void
    {
        $this->tearDownServer();
        $this->tearDownVault();
        parent::tearDown();
    }

    // Alice shares the entry with Server: the v5-valid grant row, then the current DEK sealed to -1 (Task 7 adds
    // grantServer; until then the row goes in by SQL).
    private function shareWithServer(): void
    {
        $aliceSk = $this->aliceSk();
        (new VaultLock($this->container))->exclusive(function () use ($aliceSk): void {
            $db = new VaultDb($this->container);
            $db->insert('vault_grants', [
                'subject_type' => 'entry', 'subject_id' => $this->e, 'grantee_id' => ServerPrincipal::ID, 'permission' => 'read',
                'granted_by' => $this->alice, 'expires_at' => null, 'created_at' => $this->now,
                'consumers' => '["CveHunter"]', 'fields' => '["password"]', 'rate_per_hour' => 60, 'rate_burst' => 10,
            ]);
            $rekeyer = new Rekeyer($this->container);
            $epoch = $this->epoch();
            $dek = $rekeyer->openDek($db, 'entry', $this->e, $epoch, $this->alice, $aliceSk);
            $this->assertNotNull($dek, "alice's DEK");
            $rekeyer->sealTo($db, 'entry', $this->e, $epoch, $dek, [ServerPrincipal::ID]);
            sodium_memzero($dek);
        });
    }

    private function epoch(): int
    {
        return (int) $this->row('SELECT key_epoch FROM vault_entries WHERE id = ?', [$this->e])['key_epoch'];
    }

    // Mutation: currentPrincipal() accepting kind server.
    public function testServerNeverProcessesTheRekeyQueue(): void
    {
        $this->shareWithServer();
        $epoch = $this->epoch();
        (new VaultLock($this->container))->exclusive(fn () => (new Rekeyer($this->container))->enqueue(new VaultDb($this->container), 'entry', $this->e, $epoch));
        $sk = $this->serverSk();
        $this->assertVaultError('not_found', fn () => (new Rekeyer($this->container))->drainQueue(ServerPrincipal::ID, $sk));
        $this->assertVaultError('not_found', fn () => (new Rekeyer($this->container))->rekey('entry', $this->e, $sk, ServerPrincipal::ID));
        $this->assertSame($epoch, $this->epoch());
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_rekey_queue WHERE object_type = 'entry' AND object_id = ?", [$this->e]));
    }

    // Mutation: ownsHere returning true for a non-agent kind; requirePrincipal letting Server through.
    public function testServerNeverOwns(): void
    {
        $this->assertVaultError('not_enrolled', fn () => $this->store()->createGroup(ServerPrincipal::ID, null, ['name' => 'mine']));
        $this->assertVaultError('not_enrolled', fn () => $this->store()->createEntry(ServerPrincipal::ID, $this->g, Fixtures::entry('mine')));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_groups WHERE owner_id < 0'));

        $this->pdo()->prepare('UPDATE vault_entries SET owner_id = -1 WHERE id = ?')->execute([$this->e]);
        $resolver = new RecipientResolver($this->container);
        $row = $resolver->object('entry', $this->e);
        $recipients = (new VaultLock($this->container))->shared(fn () => $resolver->effective('entry', $this->e, $this->now, $row));
        $this->assertArrayNotHasKey(ServerPrincipal::ID, $recipients);
        // Server's live_user_id is always NULL, so anyGone already empties the list above; ownsHere is the second
        // line, checked on its own.
        $ownsHere = new ReflectionMethod(RecipientResolver::class, 'ownsHere');
        $this->assertFalse($ownsHere->invoke($resolver, new VaultDb($this->container), 'entry', $row, [$this->g]));
    }

    // Mutation: holderKeypairs accepting server.
    public function testServerNeverReadsThroughTheHumanPath(): void
    {
        $this->shareWithServer();
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND principal_id = -1", [$this->e]));
        $sk = $this->serverSk();
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry(ServerPrincipal::ID, $this->e, $sk));
    }

    // Mutation: no kind check in grant().
    public function testServerCannotTakeAHumanGrantOrAGroup(): void
    {
        $sk = $this->aliceSk();
        $this->assertVaultError('payload_invalid', fn () => $this->grants()->grant($this->alice, 'group', $this->g, ServerPrincipal::ID, 'read', null, $sk));
        $this->assertVaultError('payload_invalid', fn () => $this->grants()->grant($this->alice, 'entry', $this->e, ServerPrincipal::ID, 'read', null, $sk));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id < 0'));
    }

    public function testServerNeverUnlocks(): void
    {
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock(ServerPrincipal::ID, Fixtures::PASSPHRASE, self::IP));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_wraps WHERE user_id < 0'));
    }

    // Controller ruling: a human's (or agent's) rotation never writes a wrap of method server. Mutation: checkFactors
    // taking Wraps::METHODS.
    public function testRotationRefusesAServerFactor(): void
    {
        $sk = $this->aliceSk();
        try {
            $this->rotation()->start($this->alice, $sk, [['method' => 'server', 'kek' => random_bytes(32), 'credential_id' => '']]);
            $this->fail('a server factor was accepted');
        } catch (InvalidArgumentException $e) {
            $this->assertSame('Vault rotation: invalid surviving factor', $e->getMessage());
        }
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE method = 'server'"));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rotations'));
    }

    // Mutation: principal() still filtering live_user_id IS NOT NULL (Server left out of the re-key).
    public function testAnotherRecipientsRevocationKeepsServerSealed(): void
    {
        $this->shareWithServer();
        $sk = $this->aliceSk();
        $this->grants()->grant($this->alice, 'entry', $this->e, $this->carol, 'read', null, $sk);
        $before = $this->epoch();
        $this->grants()->revoke($this->alice, 'entry', $this->e, $this->carol, $sk);
        $epoch = $this->epoch();
        $this->assertSame($before + 1, $epoch);

        $key = $this->row("SELECT key_epoch, sealed_dek FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND principal_id = -1", [$this->e]);
        $this->assertNotNull($key, 'Server still holds a key row');
        $this->assertSame($epoch, (int) $key['key_epoch']);
        $dek = $this->freshProvider()->openSealedDek(base64_decode($key['sealed_dek']), new DekContext('entry', $this->e, $epoch, ServerPrincipal::ID));
        $row = $this->row('SELECT nonce, ciphertext FROM vault_entries WHERE id = ?', [$this->e]);
        $json = Aead::open(base64_decode($row['nonce']), base64_decode($row['ciphertext']), $dek, ObjectStore::ad('entry', $this->e, $this->alice, $epoch));
        $this->assertSame('server shared', json_decode($json, true)['title']);
    }
}
