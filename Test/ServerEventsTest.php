<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';

use Kanboard\Event\GenericEvent;
use Kanboard\Plugin\Vault\Model\ServerEvents;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Model\VaultDb;
use Kanboard\Plugin\Vault\Model\VaultLock;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec amendment: Rotation and revocation; frozen events. Saving an entry dispatches vault.secret.changed (entry_id,
// version); losing a Server grant (revoke, Server off, the entry deleted) dispatches vault.secret.revoked (entry_id).
// Both after the commit, never with a title, owner, consumer, field or value; a listener can't fail the change.
class ServerEventsTest extends Base
{
    use ServerFixture;

    /** @var array<string, list<array{payload: array, inTx: bool}>> */
    private array $events = [ServerEvents::CHANGED => [], ServerEvents::REVOKED => []];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpAgents();
        $this->setUpServer();
        foreach (array_keys($this->events) as $name) {
            $this->container['dispatcher']->addListener($name, function (GenericEvent $event) use ($name) {
                $this->events[$name][] = ['payload' => $event->getAll(), 'inTx' => $this->pdo()->inTransaction()];
            });
        }
    }

    protected function tearDown(): void
    {
        $this->tearDownServer();
        $this->tearDownVault();
        parent::tearDown();
    }

    private function payloads(string $name): array
    {
        return array_column($this->events[$name], 'payload');
    }

    // Kills: no dispatch; dispatch inside the transaction; a payload with more or other keys, or the old version.
    public function testUpdateEntryDispatchesChangedAfterCommitWithIdAndVersionOnly(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $payload = Fixtures::fullEntry();
        $payload['password'] = Fixtures::UPDATED_PASSWORD;
        $this->assertSame(2, $this->store()->updateEntry($this->alice, $e, 1, $payload, $this->aliceSk()));

        $this->assertCount(1, $this->events[ServerEvents::CHANGED]);
        [$event] = $this->events[ServerEvents::CHANGED];
        $this->assertFalse($event['inTx'], 'dispatched after the commit');
        $this->assertSame(['entry_id', 'version'], array_keys($event['payload']));
        $this->assertSame([$e, 2], array_values($event['payload']));
        $json = json_encode($event['payload']);
        foreach ([Fixtures::ENTRY_TITLE, Fixtures::ENTRY_PASSWORD, Fixtures::UPDATED_PASSWORD, 'CveHunter'] as $s) {
            $this->assertStringNotContainsString($s, $json);
        }
        $this->assertSame([], $this->events[ServerEvents::REVOKED]);
    }

    public function testConflictingUpdateDispatchesNothing(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->store()->updateEntry($this->alice, $e, 1, Fixtures::fullEntry(), $this->aliceSk());
        $this->events[ServerEvents::CHANGED] = [];
        $this->assertVaultError('conflict', fn () => $this->store()->updateEntry($this->alice, $e, 1, Fixtures::fullEntry(), $this->aliceSk()));
        $this->assertSame([], $this->events[ServerEvents::CHANGED]);
    }

    // Kills: no dispatch on revoke; a second dispatch from the re-key that follows the removal.
    public function testRevokingTheServerGrantDispatchesRevokedOnce(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->grants()->revoke($this->alice, 'entry', $e, ServerPrincipal::ID, $this->aliceSk());
        $this->assertSame([['entry_id' => $e]], $this->payloads(ServerEvents::REVOKED));
        $this->assertFalse($this->events[ServerEvents::REVOKED][0]['inTx']);
    }

    // Server off drops every Server grant: one event per entry that had one. Kills: no dispatch on disable; one per
    // removal path (removeSource and the -1 key sweep both firing).
    public function testDisableDispatchesRevokedOncePerSharedEntry(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->server()->disable(self::ADMIN);
        $this->assertSame([['entry_id' => $e]], $this->payloads(ServerEvents::REVOKED));
    }

    // Kills: no dispatch on delete (purgeRefs deletes the grant without removeSource); a double dispatch.
    public function testDeletingTheSharedEntryDispatchesRevokedOnce(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->store()->deleteObject($this->alice, 'entry', $e, $this->aliceSk());
        $this->assertSame([['entry_id' => $e]], $this->payloads(ServerEvents::REVOKED));
    }

    // A group delete takes its entries: only the Server-shared one is reported.
    public function testDeletingAGroupDispatchesRevokedForItsSharedEntryOnly(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $g = (int) $this->row('SELECT group_id FROM vault_entries WHERE id = ?', [$e])['group_id'];
        $this->store()->createEntry($this->alice, $g, Fixtures::entry('unshared'));
        $this->store()->deleteObject($this->alice, 'group', $g, $this->aliceSk());
        $this->assertSame([['entry_id' => $e]], $this->payloads(ServerEvents::REVOKED));
    }

    // The orphan sweep's deleteOwnedBy, inside the caller's lock: reported after that lock commits.
    public function testDeleteOwnedByDispatchesRevokedAfterTheCallersCommit(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->store()->createEntry($this->alice, (int) $this->row('SELECT group_id FROM vault_entries WHERE id = ?', [$e])['group_id'], Fixtures::entry('unshared'));
        (new VaultLock($this->container))->exclusive(function () {
            $this->store()->deleteOwnedBy(new VaultDb($this->container), $this->alice);
            $this->assertSame([], $this->events[ServerEvents::REVOKED], 'not before the commit');
        });
        $this->assertSame([['entry_id' => $e]], $this->payloads(ServerEvents::REVOKED));
    }

    // Kills: revoked dispatched for every grantee.
    public function testRevokingAHumanGrantDispatchesNothing(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->grants()->grant($this->alice, 'entry', $e, $this->carol, 'read', null, $this->aliceSk());
        $this->grants()->revoke($this->alice, 'entry', $e, $this->carol, $this->aliceSk());
        $this->assertSame([], $this->events[ServerEvents::REVOKED]);
    }

    // Kills: a listener's exception escaping updateEntry or undoing the save.
    public function testThrowingListenerDoesNotFailTheUpdate(): void
    {
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        $this->container['dispatcher']->addListener(ServerEvents::CHANGED, function () {
            throw new \RuntimeException('listener down');
        });
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->assertSame(2, $this->store()->updateEntry($this->alice, $e, 1, Fixtures::fullEntry(), $this->aliceSk()));
        $this->assertSame(2, (int) $this->row('SELECT version FROM vault_entries WHERE id = ?', [$e])['version']);
    }
}
