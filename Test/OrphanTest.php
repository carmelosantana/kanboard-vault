<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';

use Kanboard\Event\GenericEvent;
use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Model\DekContext;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\OrphanService;
use Kanboard\Plugin\Vault\Model\Purger;
use Kanboard\Plugin\Vault\Model\Rekeyer;
use Kanboard\Plugin\Vault\Model\ServerEvents;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Model\VaultDb;
use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec amendment: security requirement 14 with Codex NEW-02 (quarantine wins). A deleted owner's Server-shared entries
// outlive the purge with their ancestor groups and the owner's principal as a tombstone (state 'orphaned'), readable by
// nobody, until an admin holding a grant claims one by a full re-key or destroys it. Everything else the owner had goes.
class OrphanTest extends Base
{
    use ServerFixture;

    private const ADMIN_PASSPHRASE = 'VaultFixtureSecret-adminphrase-Vq3mK8';
    private const ROTATED_PASSPHRASE = 'VaultFixtureSecret-rotatedphrase-Bc5wN2';

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpAgents();
        $this->principals()->enrolHuman($this->bob, Fixtures::NEW_PASSPHRASE);
        $this->principals()->enrolHuman(self::ADMIN, self::ADMIN_PASSPHRASE);
        $this->setUpServer();
        $this->enableServer();
    }

    protected function tearDown(): void
    {
        $this->tearDownServer();
        $this->tearDownVault();
        parent::tearDown();
    }

    private function adminSk(): string
    {
        return $this->skFor(self::ADMIN, self::ADMIN_PASSPHRASE);
    }

    private function bobSk(): string
    {
        return $this->skFor($this->bob, Fixtures::NEW_PASSPHRASE);
    }

    private function orphans(): OrphanService
    {
        return new OrphanService($this->container, $this->clock());
    }

    private function purge(): void
    {
        (new Purger($this->container))->run($this->now, true);
    }

    private function deleteAlice(): void
    {
        $this->assertTrue($this->container['userModel']->remove($this->alice));
    }

    private function adminGroup(): int
    {
        return $this->store()->createGroup(self::ADMIN, null, ['name' => 'claimed']);
    }

    // Alice's g1 holds e1 (shared with Server for CveHunter's password) and e2; her g2 holds e3.
    /** @return array{0:int,1:int,2:int,3:int,4:int} [g1, e1, e2, g2, e3] */
    private function aliceTree(): array
    {
        $g1 = $this->store()->createGroup($this->alice, null, ['name' => 'g1']);
        $e1 = $this->store()->createEntry($this->alice, $g1, Fixtures::fullEntry());
        $e2 = $this->store()->createEntry($this->alice, $g1, Fixtures::entry('e2'));
        $g2 = $this->store()->createGroup($this->alice, null, ['name' => 'g2']);
        $e3 = $this->store()->createEntry($this->alice, $g2, Fixtures::entry('e3'));
        $this->shareWithServer($e1);
        return [$g1, $e1, $e2, $g2, $e3];
    }

    private function shareWithServer(int $entryId): void
    {
        $this->grants()->grantServer($this->alice, $entryId, ['CveHunter'], ['password'], null, null, $this->aliceSk());
    }

    private function serverRead(int $entryId): string
    {
        return $this->serverSecrets()->read('CveHunter', "vault://$entryId/password")->reveal();
    }

    private function assertServerRefused(string $reason, int $entryId): void
    {
        try {
            $this->serverRead($entryId);
            $this->fail("expected $reason");
        } catch (ServiceSecretException $e) {
            $this->assertSame($reason, $e->reason());
        }
    }

    private function principalRow(int $id): ?array
    {
        return $this->row('SELECT user_id, state, live_user_id FROM vault_principals WHERE user_id = ?', [$id]);
    }

    private function exists(string $table, int $id): bool
    {
        return $this->row('SELECT id FROM '.$table.' WHERE id = ?', [$id]) !== null;
    }

    private function keyRows(int $entryId, int $principalId): int
    {
        return $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND principal_id = ?", [$entryId, $principalId]);
    }

    private function serverGrants(int $entryId): int
    {
        return $this->countRows("SELECT COUNT(*) FROM vault_grants WHERE subject_type = 'entry' AND subject_id = ? AND grantee_id = ?", [$entryId, ServerPrincipal::ID]);
    }

    /** @return array<string, list<array>> */
    private function snapshot(): array
    {
        $out = [];
        foreach ([
            'entries' => 'SELECT id, owner_id, group_id, key_epoch, nonce, ciphertext FROM vault_entries ORDER BY id',
            'groups' => 'SELECT id, owner_id, parent_id FROM vault_groups ORDER BY id',
            'principals' => 'SELECT user_id, state, live_user_id FROM vault_principals ORDER BY user_id',
            'keys' => 'SELECT object_type, object_id, principal_id, key_epoch FROM vault_keys ORDER BY object_type, object_id, principal_id, principal_key_gen',
            'grants' => 'SELECT id, subject_type, subject_id, grantee_id FROM vault_grants ORDER BY id',
            'audit' => "SELECT id, action FROM vault_audit WHERE action LIKE 'orphan%' ORDER BY id",
        ] as $name => $sql) {
            $s = $this->pdo()->prepare($sql);
            $s->execute();
            $out[$name] = $s->fetchAll(\PDO::FETCH_ASSOC);
        }
        return $out;
    }

    // Requirement 14, first half. Mutations killed: quarantining every owned entry (e2 survives); not keeping g1 (e1
    // cascades with it); deleting the principal (e1 cascades off owner_id).
    public function testDeletingAnOwnerQuarantinesOnlyServerSharedEntries(): void
    {
        [$g1, $e1, $e2, $g2, $e3] = $this->aliceTree();
        $this->deleteAlice();
        $this->assertServerRefused('orphaned', $e1);

        $this->purge();
        $this->assertSame($this->alice, (int) $this->row('SELECT owner_id FROM vault_entries WHERE id = ?', [$e1])['owner_id']);
        $this->assertSame($this->alice, (int) $this->row('SELECT owner_id FROM vault_groups WHERE id = ?', [$g1])['owner_id']);
        $this->assertFalse($this->exists('vault_entries', $e2), 'e2 is not Server-shared');
        $this->assertFalse($this->exists('vault_entries', $e3));
        $this->assertFalse($this->exists('vault_groups', $g2));
        $this->assertSame('orphaned', $this->principalRow($this->alice)['state']);
        $this->assertSame(1, $this->keyRows($e1, ServerPrincipal::ID), 'the Server key row is kept for a claim');
        $this->assertSame(1, $this->serverGrants($e1));
        $rows = $this->auditRows('orphan_quarantine');
        $this->assertCount(1, $rows);
        $this->assertSame(['system', null, 'entry', $e1, $this->alice],
            [$rows[0]['actor_kind'], $rows[0]['actor_user_id'], $rows[0]['object_type'], (int) $rows[0]['object_id'], (int) $rows[0]['old_owner_id']]);
        $this->assertServerRefused('orphaned', $e1);

        $before = $this->snapshot();
        $this->purge();
        $this->assertSame($before, $this->snapshot(), 'a second purge changes nothing');
    }

    // Quarantine: a grantee (here through the group) reads nothing, Server is refused as orphaned, and no holder's queue
    // drain re-keys the entry.
    public function testQuarantineRefusesServerAndHumans(): void
    {
        [$g1, $e1] = $this->aliceTree();
        $this->grants()->grant($this->alice, 'group', $g1, $this->bob, 'read', null, $this->aliceSk());
        $this->grants()->grant($this->alice, 'entry', $e1, self::ADMIN, 'read', null, $this->aliceSk());
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->store()->readEntry($this->bob, $e1, $this->bobSk())['payload']['password']);
        $this->deleteAlice();
        foreach (['before the purge', 'after the purge'] as $when) {
            $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->bob, $e1, $this->bobSk()));
            $this->assertVaultError('not_found', fn () => $this->store()->readEntry(self::ADMIN, $e1, $this->adminSk()));
            $this->assertServerRefused('orphaned', $e1);
            $this->purge();
        }
        $epoch = (int) $this->row('SELECT key_epoch FROM vault_entries WHERE id = ?', [$e1])['key_epoch'];
        (new Rekeyer($this->container, $this->clock()))->drainQueue(self::ADMIN, $this->adminSk());
        (new Rekeyer($this->container, $this->clock()))->drainQueue($this->bob, $this->bobSk());
        $this->assertSame($epoch, (int) $this->row('SELECT key_epoch FROM vault_entries WHERE id = ?', [$e1])['key_epoch'], 'not re-keyed');
    }

    // Requirement 14, second half. Mutation killed: a claim that only changes owner_id and re-seals the same DEK (the
    // old DEKs would open the new ciphertext).
    public function testAdminWithAGrantClaimsAsARekey(): void
    {
        [$g1, $e1] = $this->aliceTree();
        $this->grants()->grant($this->alice, 'entry', $e1, self::ADMIN, 'read', null, $this->aliceSk());
        $epoch = (int) $this->row('SELECT key_epoch FROM vault_entries WHERE id = ?', [$e1])['key_epoch'];
        $adminDek = (new Rekeyer($this->container, $this->clock()))->openDek(new VaultDb($this->container), 'entry', $e1, $epoch, self::ADMIN, $this->adminSk());
        $this->assertNotNull($adminDek);
        $srv = $this->row('SELECT sealed_dek FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ?', ['entry', $e1, ServerPrincipal::ID]);
        $serverDek = $this->freshProvider()->openSealedDek(base64_decode($srv['sealed_dek']), new DekContext('entry', $e1, $epoch, ServerPrincipal::ID));
        $adminGroup = $this->adminGroup();

        $this->deleteAlice();
        $this->purge();
        $this->assertSame($epoch + 1, $this->orphans()->claim(self::ADMIN, $e1, $adminGroup, $this->adminSk()));

        $row = $this->row('SELECT * FROM vault_entries WHERE id = ?', [$e1]);
        $this->assertSame([self::ADMIN, $adminGroup, $epoch + 1], [(int) $row['owner_id'], (int) $row['group_id'], (int) $row['key_epoch']]);
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_grants WHERE subject_type = 'entry' AND subject_id = ? AND grantee_id = ?", [$e1, self::ADMIN]), 'no direct grant to the new owner');
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND principal_id = ? AND key_epoch = ?", [$e1, ServerPrincipal::ID, $epoch + 1]));
        $this->assertSame(0, $this->keyRows($e1, $this->alice));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND key_epoch <> ?", [$e1, $epoch + 1]), 'every key row is at the new epoch');
        $this->assertFalse((new Rekeyer($this->container))->isQueued(new VaultDb($this->container), 'entry', $e1));

        foreach (['the admin DEK' => $adminDek, 'the Server DEK' => $serverDek] as $what => $dek) {
            foreach ([ObjectStore::ad('entry', $e1, self::ADMIN, $epoch + 1), ObjectStore::ad('entry', $e1, $this->alice, $epoch + 1)] as $ad) {
                try {
                    Aead::open(base64_decode($row['nonce']), base64_decode($row['ciphertext']), $dek, $ad);
                    $this->fail("$what opens the new ciphertext");
                } catch (CryptoException) {
                    $this->addToAssertionCount(1);
                }
            }
        }

        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->serverRead($e1));
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->store()->readEntry(self::ADMIN, $e1, $this->adminSk())['payload']['password']);
        $claims = $this->auditRows('orphan_claim');
        $this->assertCount(1, $claims);
        $this->assertSame([self::ADMIN, 'entry', $e1, $this->alice, self::ADMIN, $epoch + 1],
            [(int) $claims[0]['actor_user_id'], $claims[0]['object_type'], (int) $claims[0]['object_id'], (int) $claims[0]['old_owner_id'], (int) $claims[0]['new_owner_id'], (int) $claims[0]['key_epoch']]);

        $this->purge();
        $this->assertNull($this->principalRow($this->alice), 'the tombstone goes once it owns no entry');
        $this->assertFalse($this->exists('vault_groups', $g1));
        $this->assertTrue($this->exists('vault_entries', $e1));
    }

    /** @return array<string, array{0:string, 1:callable}> code => arrange(test, e1, e4, adminGroup): [actor, entry, group, sk] */
    public static function claimRefusals(): array
    {
        return [
            'a grantee who is not an admin' => ['not_allowed', static fn (self $t, int $e1, int $e4, int $ag): array => [$t->bob, $e1, $ag, $t->bobSk()]],
            'the admin with no grant' => ['not_allowed', static fn (self $t, int $e1, int $e4, int $ag): array => [self::ADMIN, $e4, $ag, $t->adminSk()]],
            // The key row is still there (no purge since): a key row alone is no grant.
            'the admin whose grant expired' => ['not_allowed', static function (self $t, int $e1, int $e4, int $ag): array {
                $t->pdo()->prepare("UPDATE vault_grants SET expires_at = ? WHERE subject_type = 'entry' AND subject_id = ? AND grantee_id = ?")->execute([$t->now, $e1, self::ADMIN]);
                $t->assertSame(1, $t->keyRows($e1, self::ADMIN));
                return [self::ADMIN, $e1, $ag, $t->adminSk()];
            }],
            'a live entry' => ['not_found', static function (self $t, int $e1, int $e4, int $ag): array {
                $g = $t->store()->createGroup($t->carol, null, ['name' => 'carol']);
                $e = $t->store()->createEntry($t->carol, $g, Fixtures::entry('live'));
                $t->grants()->grant($t->carol, 'entry', $e, self::ADMIN, 'read', null, $t->carolSk());
                return [self::ADMIN, $e, $ag, $t->adminSk()];
            }],
            'a group the admin does not own' => ['not_found', static function (self $t, int $e1, int $e4, int $ag): array {
                return [self::ADMIN, $e1, $t->store()->createGroup($t->carol, null, ['name' => 'carol']), $t->adminSk()];
            }],
            'a locked admin (wrong sk)' => ['not_found', static fn (self $t, int $e1, int $e4, int $ag): array => [self::ADMIN, $e1, $ag, $t->bobSk()]],
        ];
    }

    // Each refusal: the code, one orphan_claim_denied row (written although the claim rolled back) and the row unchanged.
    /** @dataProvider claimRefusals */
    public function testClaimRefusals(string $code, callable $arrange): void
    {
        [$g1, $e1] = $this->aliceTree();
        $e4 = $this->store()->createEntry($this->alice, $g1, Fixtures::entry('e4'));
        $this->shareWithServer($e4);
        $this->grants()->grant($this->alice, 'group', $g1, $this->bob, 'read', null, $this->aliceSk());
        $this->grants()->grant($this->alice, 'entry', $e1, self::ADMIN, 'read', null, $this->aliceSk());
        $adminGroup = $this->adminGroup();
        $this->deleteAlice();
        $this->purge();
        [$actor, $entry, $group, $sk] = $arrange($this, $e1, $e4, $adminGroup);
        $before = $this->snapshot();

        $this->assertVaultError($code, fn () => $this->orphans()->claim($actor, $entry, $group, $sk));

        $denied = $this->auditRows('orphan_claim_denied');
        $this->assertCount(1, $denied);
        $this->assertSame([$actor, 'entry', $entry, $code], [(int) $denied[0]['actor_user_id'], $denied[0]['object_type'], (int) $denied[0]['object_id'], $denied[0]['reason']]);
        $after = $this->snapshot();
        $after['audit'] = array_values(array_filter($after['audit'], static fn (array $r): bool => $r['action'] !== 'orphan_claim_denied'));
        $this->assertSame($before, $after, 'nothing else changed');
        $this->assertSame([], $this->auditRows('orphan_claim'));
    }

    public function testDestroyRemovesTheOrphan(): void
    {
        $revoked = [];
        $this->container['dispatcher']->addListener(ServerEvents::REVOKED, function (GenericEvent $event) use (&$revoked) {
            $revoked[] = $event->getAll();
        });
        [$g1, $e1] = $this->aliceTree();
        $this->deleteAlice();
        $this->purge();

        $this->assertVaultError('not_allowed', fn () => $this->orphans()->destroy($this->bob, $e1));
        $this->assertTrue($this->exists('vault_entries', $e1));
        $this->assertSame(['not_allowed'], array_column($this->auditRows('orphan_destroy_denied'), 'reason'));

        $this->orphans()->destroy(self::ADMIN, $e1);
        $this->assertFalse($this->exists('vault_entries', $e1));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_grants WHERE subject_type = 'entry' AND subject_id = ?", [$e1]));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE object_type = 'entry' AND object_id = ?", [$e1]));
        $this->assertSame([['entry_id' => $e1]], $revoked);
        $rows = $this->auditRows('orphan_destroy');
        $this->assertCount(1, $rows);
        $this->assertSame([self::ADMIN, 'entry', $e1, $this->alice], [(int) $rows[0]['actor_user_id'], $rows[0]['object_type'], (int) $rows[0]['object_id'], (int) $rows[0]['old_owner_id']]);

        $this->purge();
        $this->assertNull($this->principalRow($this->alice));
        $this->assertFalse($this->exists('vault_groups', $g1));

        $g = $this->store()->createGroup($this->carol, null, ['name' => 'carol']);
        $live = $this->store()->createEntry($this->carol, $g, Fixtures::entry('live'));
        $this->assertVaultError('not_found', fn () => $this->orphans()->destroy(self::ADMIN, $live));
        $this->assertTrue($this->exists('vault_entries', $live));
        $this->assertSame(['not_allowed', 'not_found'], array_column($this->auditRows('orphan_destroy_denied'), 'reason'));
        $this->assertCount(1, $this->auditRows('orphan_destroy'));
    }

    public function testAtRisk(): void
    {
        [$g1, $e1] = $this->aliceTree();
        $this->assertSame([['entry_id' => $e1, 'owner_id' => $this->alice, 'reason' => 'no_successor']], $this->orphans()->atRisk());
        $this->grants()->grant($this->alice, 'entry', $e1, self::ADMIN, 'read', null, $this->aliceSk());
        $this->assertSame([], $this->orphans()->atRisk());
        $this->assertTrue($this->container['userModel']->disable($this->alice));
        $this->assertSame([['entry_id' => $e1, 'owner_id' => $this->alice, 'reason' => 'owner_disabled']], $this->orphans()->atRisk());
        $this->assertSame([['entry_id' => $e1, 'owner_id' => $this->alice, 'reason' => 'owner_disabled']], $this->orphans()->atRisk($this->alice));
        $this->assertSame([], $this->orphans()->atRisk($this->bob));
    }

    public function testOrphansAreListedForAdminsOnly(): void
    {
        [$g1, $e1] = $this->aliceTree();
        $this->assertSame([], $this->orphans()->orphans(self::ADMIN), 'a live owner has no orphans');
        $this->deleteAlice();
        $this->purge();
        $this->assertSame([['entry_id' => $e1, 'old_owner_id' => $this->alice, 'consumers' => ['CveHunter']]], $this->orphans()->orphans(self::ADMIN));
        $this->assertSame([], $this->orphans()->orphans($this->bob));
        $this->assertSame([], $this->orphans()->orphans($this->carol));
    }

    /** @return array<string, array{0:callable}> arrange(test): runs a loser-reconciliation path against the quarantined e1 */
    public static function loserPaths(): array
    {
        return [
            'an expired grant (GrantModel::removeSource)' => [static function (self $t, int $e1): void {
                $t->now += 200;
                $t->purge();
                $t->assertSame(0, $t->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$t->bob]), 'bob\'s grant expired');
                $t->assertSame(0, $t->keyRows($e1, $t->bob));
            }],
            'a key rotation (RotationService)' => [static function (self $t, int $e1): void {
                $t->rotation()->rotateWithPassphrase($t->bob, $t->bobSk(), Fixtures::NEW_PASSPHRASE, self::ROTATED_PASSPHRASE, self::IP);
                $t->assertSame(0, $t->keyRows($e1, $t->bob));
            }],
            'an agent re-enrolment (AgentVault)' => [static function (self $t, int $e1): void {
                $t->agentVault()->reenrol($t->carol, $t->dave, $t->carolSk());
                $t->assertSame(0, $t->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$t->dave]));
                $t->assertSame(0, $t->keyRows($e1, $t->dave));
            }],
        ];
    }

    // Carry (b): the paths that drop the key rows of principals who lost access keep a quarantined orphan's Server key
    // row and grant (and the claiming admin's key row), so a claim still restores Server reads.
    /** @dataProvider loserPaths */
    public function testLoserReconciliationKeepsTheOrphansServerKey(callable $path): void
    {
        $this->roster([$this->dave => $this->carol]);
        $this->agentVault()->enrol($this->carol, $this->dave, $this->carolSk());
        [$g1, $e1] = $this->aliceTree();
        $this->grants()->grant($this->alice, 'entry', $e1, self::ADMIN, 'read', null, $this->aliceSk());
        $this->grants()->grant($this->alice, 'group', $g1, $this->bob, 'read', $this->now + 100, $this->aliceSk());
        $this->grants()->grant($this->alice, 'group', $g1, $this->dave, 'read', null, $this->aliceSk());
        $adminGroup = $this->adminGroup();
        $this->deleteAlice();
        $this->purge();

        $path($this, $e1);

        $this->assertSame(1, $this->keyRows($e1, ServerPrincipal::ID), 'the Server key row survives');
        $this->assertSame(1, $this->serverGrants($e1), 'the Server grant survives');
        $this->assertSame(1, $this->keyRows($e1, self::ADMIN), 'the claiming admin\'s key row survives');
        $this->assertServerRefused('orphaned', $e1);
        $this->orphans()->claim(self::ADMIN, $e1, $adminGroup, $this->adminSk());
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->serverRead($e1));
    }

    // Carry (c): kept groups hold on while any quarantined entry is still in them, and go with the tombstone after.
    public function testAKeptGroupLivesUntilItsLastOrphanIsReleased(): void
    {
        [$g1, $e1] = $this->aliceTree();
        $e4 = $this->store()->createEntry($this->alice, $g1, Fixtures::fullEntry());
        $this->shareWithServer($e4);
        $this->grants()->grant($this->alice, 'entry', $e1, self::ADMIN, 'read', null, $this->aliceSk());
        $adminGroup = $this->adminGroup();
        $this->deleteAlice();
        $this->purge();
        $this->assertCount(2, $this->auditRows('orphan_quarantine'));

        $this->orphans()->claim(self::ADMIN, $e1, $adminGroup, $this->adminSk());
        $this->purge();
        $this->assertSame('orphaned', $this->principalRow($this->alice)['state']);
        $this->assertTrue($this->exists('vault_groups', $g1), 'g1 still holds e4');
        $this->assertSame($g1, (int) $this->row('SELECT group_id FROM vault_entries WHERE id = ?', [$e4])['group_id']);
        $this->assertServerRefused('orphaned', $e4);
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->serverRead($e1));

        $this->orphans()->destroy(self::ADMIN, $e4);
        $this->purge();
        $this->assertNull($this->principalRow($this->alice));
        $this->assertFalse($this->exists('vault_groups', $g1));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_entries WHERE group_id = ?', [$g1]));
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->serverRead($e1));
    }
}
