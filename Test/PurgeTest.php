<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Plugin\Vault\Console\PurgeCommand;
use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\Purger;
use Kanboard\Plugin\Vault\Model\Rekeyer;
use KanboardTests\units\Base;
use Symfony\Component\Console\Tester\CommandTester;

// Spec: Data model → Purge ("expired grants (deleted the same way as removals while nobody is unlocked), sessions,
// challenges, reservations and shares, plus audit rows past retention, … at most once a minute", and the
// vault:purge command), Entries, groups and grants → removals while nobody is unlocked (a deleted grantee), the
// expiry reconciliation on write ("A test edits immediately after expiry while the purge is throttled"), R26
// (a deleted Kanboard user's principal is swept into re-keys) and R8(b) (orphaned polymorphic rows).
//
// Alice owns g1 > g2 > g3, with entry e1 in g1 and e3 in g3. Bob, Carol: other principals.
class PurgeTest extends Base
{
    use VaultFixture;

    private int $carol;
    /** @var array<int,string> */
    private array $sk = [];
    private int $g1;
    private int $g2;
    private int $g3;
    private int $e1;
    private int $e3;
    /** @var list<array{0:string,1:array}> */
    private array $audits = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->carol = (int) $this->container['userModel']->create(['username' => 'carol', 'password' => 'carol login password 1']);
        foreach ([$this->alice, $this->bob, $this->carol] as $id) {
            $kp = $this->principalWithWrap($id, 'unused passphrase '.$id, 1, 8192);
            $this->sk[$id] = sodium_crypto_box_secretkey($kp);
        }
        $s = $this->store();
        $this->g1 = $s->createGroup($this->alice, null, ['name' => 'g1']);
        $this->g2 = $s->createGroup($this->alice, $this->g1, ['name' => 'g2']);
        $this->g3 = $s->createGroup($this->alice, $this->g2, ['name' => 'g3']);
        $this->e1 = $s->createEntry($this->alice, $this->g1, ['title' => 'e1', 'password' => 'pw-e1']);
        $this->e3 = $s->createEntry($this->alice, $this->g3, ['title' => 'e3', 'password' => 'pw-e3']);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function store(): ObjectStore
    {
        return new ObjectStore($this->container, fn () => $this->now);
    }

    private function grants(): GrantModel
    {
        return new GrantModel($this->container, fn () => $this->now);
    }

    private function purger(): Purger
    {
        return new Purger($this->container, function (string $action, array $cols): void {
            $this->audits[] = [$action, $cols];
        });
    }

    private function epoch(string $type, int $id): int
    {
        return (int) $this->row('SELECT key_epoch FROM '.($type === 'entry' ? 'vault_entries' : 'vault_groups').' WHERE id = ?', [$id])['key_epoch'];
    }

    private function keyRows(int $principalId): int
    {
        return $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE principal_id = ?', [$principalId]);
    }

    private function queued(): array
    {
        $rows = $this->pdo()->query('SELECT object_type, object_id, expected_key_epoch FROM vault_rekey_queue ORDER BY object_type, object_id')->fetchAll(\PDO::FETCH_ASSOC);
        return array_map(static fn ($r) => [$r['object_type'], (int) $r['object_id'], (int) $r['expected_key_epoch']], $rows);
    }

    // The DEK a principal could recover from a backup taken now (their sealed key row, opened with their sk).
    private function dekOf(int $principalId, string $type, int $id): string
    {
        $r = $this->row('SELECT key_epoch, sealed_dek FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ?', [$type, $id, $principalId]);
        $this->assertNotNull($r, "principal $principalId holds a key row for $type $id");
        $kp = sodium_crypto_box_keypair_from_secretkey_and_publickey($this->sk[$principalId], sodium_crypto_box_publickey_from_secretkey($this->sk[$principalId]));
        return Sealer::openDek(base64_decode($r['sealed_dek']), $kp, $type, $id, (int) $r['key_epoch'], $principalId);
    }

    private function assertDekCannotDecrypt(string $dek, int $entryId): void
    {
        $row = $this->row('SELECT * FROM vault_entries WHERE id = ?', [$entryId]);
        try {
            Aead::open(base64_decode($row['nonce']), base64_decode($row['ciphertext']), $dek, ObjectStore::ad('entry', $entryId, (int) $row['owner_id'], (int) $row['key_epoch']));
            $this->fail('the old DEK still decrypts the entry');
        } catch (CryptoException) {
            $this->addToAssertionCount(1);
        }
    }

    private function subtreeOfG1(): array
    {
        return [['entry', $this->e1], ['entry', $this->e3], ['group', $this->g1], ['group', $this->g2], ['group', $this->g3]];
    }

    // Spec: expired grants are purged "the same way as removals while nobody is unlocked": every object the
    // source covers loses the grantee's key rows and is queued, and only then is the source deleted. Kills: a bare
    // DELETE of the grant (keys stay, nothing queued), queueing only the subject, purging live grants.
    public function testPurgeRemovesExpiredViaRemovalProcedure(): void
    {
        $this->grants()->grant($this->alice, 'group', $this->g1, $this->bob, 'read', $this->now + 10, $this->sk[$this->alice]);
        $this->grants()->grant($this->alice, 'group', $this->g2, $this->carol, 'read', null, $this->sk[$this->alice]);
        $this->assertSame(5, $this->keyRows($this->bob));
        $carolRows = $this->keyRows($this->carol);

        $this->now += 10;
        $counts = $this->purger()->run($this->now);
        $this->assertTrue($counts['ran']);
        $this->assertSame(1, $counts['expired_grants']);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$this->bob]));
        $this->assertSame(0, $this->keyRows($this->bob), "the grantee's key rows went with the source");
        $expected = array_map(fn ($o) => [$o[0], $o[1], $this->epoch($o[0], $o[1])], $this->subtreeOfG1());
        $this->assertSame($expected, $this->queued(), 'every covered object is queued at its current epoch');
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$this->carol]), 'a live grant stays');
        $this->assertSame($carolRows, $this->keyRows($this->carol));
    }

    // "At most once a minute": a second run inside 60 s does nothing, vault:purge runs regardless. Kills: no
    // throttle, a throttle that the command also obeys, a throttle longer than a minute.
    public function testPurgeRunsAtMostOncePerMinuteUnlessForced(): void
    {
        $this->assertTrue($this->purger()->run($this->now)['ran']);
        $this->grants()->grant($this->alice, 'entry', $this->e1, $this->bob, 'read', $this->now + 5, $this->sk[$this->alice]);
        $this->now += 30;
        $this->assertSame(['ran' => false], $this->purger()->run($this->now));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_grants'));

        $tester = new CommandTester(new PurgeCommand($this->container, fn () => $this->purger(), fn () => $this->now));
        $this->assertSame(0, $tester->execute([]));
        $this->assertStringContainsString('expired_grants: 1', $tester->getDisplay());
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants'));

        $this->now += 59;
        $this->assertFalse($this->purger()->run($this->now)['ran'], 'the command run counts as the last purge');
        $this->now += 1;
        $this->assertTrue($this->purger()->run($this->now)['ran']);
    }

    // T7 gap: a write right after a GRANDPARENT group grant expired, while the purge is throttled. The write
    // reconciles the expiry for the whole subtree and re-keys the entry inline, so the expired grantee's DEK (from
    // a backup taken before) can't read the edit. Kills: reconciling only the object's own grants or its parent's.
    public function testWriteRightAfterGrandparentGrantExpiredWhilePurgeThrottled(): void
    {
        $this->grants()->grant($this->alice, 'group', $this->g1, $this->bob, 'read', $this->now + 5, $this->sk[$this->alice]);
        $bobDek = $this->dekOf($this->bob, 'entry', $this->e3);
        $this->assertTrue($this->purger()->run($this->now)['ran']);
        $this->now += 10;
        $this->assertFalse($this->purger()->run($this->now)['ran'], 'the purge is throttled');
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$this->bob]));

        $epoch = $this->epoch('entry', $this->e3);
        $this->store()->updateEntry($this->alice, $this->e3, 1, ['title' => 'e3', 'password' => 'pw-e3-new'], $this->sk[$this->alice]);
        $this->assertSame($epoch + 1, $this->epoch('entry', $this->e3));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$this->bob]));
        $this->assertSame(0, $this->keyRows($this->bob));
        $this->assertDekCannotDecrypt($bobDek, $this->e3);
    }

    // T7 gap: creating an entry right after a group grant expired, while the purge is throttled. The expired
    // grantee gets no key row for the new entry, and the expiry is reconciled (source gone, group queued). Kills:
    // createEntry not reconciling, or sealing to the expired grantee.
    public function testCreateEntryRightAfterGroupGrantExpiredWhilePurgeThrottled(): void
    {
        $this->grants()->grant($this->alice, 'group', $this->g2, $this->bob, 'edit', $this->now + 5, $this->sk[$this->alice]);
        $this->assertTrue($this->purger()->run($this->now)['ran']);
        $this->now += 10;
        $this->assertFalse($this->purger()->run($this->now)['ran']);

        $new = $this->store()->createEntry($this->alice, $this->g2, ['title' => 'new', 'password' => 'pw-new']);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ?', ['entry', $new, $this->bob]));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$this->bob]));
        $this->assertContains(['group', $this->g2, $this->epoch('group', $this->g2)], $this->queued());
        $this->assertVaultError('not_found', fn () => $this->store()->createEntry($this->bob, $this->g2, ['title' => 'late', 'password' => 'x']));
    }

    // R26: deleting a Kanboard user who was a grantee. The principal outlives the user row; the purge queues every
    // object it held a key or grant source on (at the current epoch), then deletes the principal, which takes its
    // grants and key rows. Until the re-key runs the write barrier holds: the owner's next edit re-keys first, so
    // the deleted user's DEK can't read it. Kills: no sweep, sweeping without queueing, queueing only the subject.
    public function testDeletedGranteeIsSweptQueuedAndBarred(): void
    {
        $this->grants()->grant($this->alice, 'group', $this->g1, $this->bob, 'read', null, $this->sk[$this->alice]);
        $bobDek = $this->dekOf($this->bob, 'entry', $this->e1);
        // A key row with no grant source behind it (a stale row): the object it names must be queued too.
        $g4 = $this->store()->createGroup($this->alice, null, ['name' => 'g4']);
        $this->pdo()->prepare("INSERT INTO vault_keys (object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek) VALUES ('group', ?, ?, 1, 1, 'eA==')")->execute([$g4, $this->bob]);
        // And a covered object where bob's key row is already gone: the grant source alone must queue it.
        $this->pdo()->prepare("DELETE FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND principal_id = ?")->execute([$this->e3, $this->bob]);
        $this->assertTrue($this->container['userModel']->remove($this->bob));
        $this->assertSame(5, $this->keyRows($this->bob), 'nothing cascaded off the user row');
        $this->assertSame([], $this->queued());

        $counts = $this->purger()->run($this->now, true);
        $this->assertSame(1, $counts['orphan_principals']);
        $this->assertNull($this->row('SELECT * FROM vault_principals WHERE user_id = ?', [$this->bob]));
        $this->assertSame(0, $this->keyRows($this->bob));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$this->bob]));
        $expected = array_map(fn ($o) => [$o[0], $o[1], $this->epoch($o[0], $o[1])], array_merge($this->subtreeOfG1(), [['group', $g4]]));
        sort($expected);
        $this->assertSame($expected, $this->queued());

        $epoch = $this->epoch('entry', $this->e1);
        $this->store()->updateEntry($this->alice, $this->e1, 1, ['title' => 'e1', 'password' => 'pw-e1-new'], $this->sk[$this->alice]);
        $this->assertSame($epoch + 1, $this->epoch('entry', $this->e1), 'the write barrier re-keyed before the edit');
        $this->assertNotContains(['entry', $this->e1, $epoch], $this->queued());
        $this->assertDekCannotDecrypt($bobDek, $this->e1);
    }

    // The purge may not have run yet when the owner writes: the write sweeps deleted principals itself (like the
    // expiry reconciliation), so the edit is never encrypted under a DEK the deleted user holds. Kills: relying on
    // the purge alone.
    public function testWriteBeforePurgeSweepsDeletedGrantee(): void
    {
        $this->grants()->grant($this->alice, 'entry', $this->e1, $this->bob, 'read', null, $this->sk[$this->alice]);
        $bobDek = $this->dekOf($this->bob, 'entry', $this->e1);
        $this->assertTrue($this->container['userModel']->remove($this->bob));

        $this->store()->updateEntry($this->alice, $this->e1, 1, ['title' => 'e1', 'password' => 'pw-e1-new'], $this->sk[$this->alice]);
        $this->assertNull($this->row('SELECT * FROM vault_principals WHERE user_id = ?', [$this->bob]));
        $this->assertDekCannotDecrypt($bobDek, $this->e1);
    }

    // Nothing is ever sealed to a deleted user's principal, even by a path that doesn't sweep first (a direct
    // re-key). Kills: Rekeyer::principal() returning principals whose user row is gone.
    public function testNothingIsSealedToADeletedUsersPrincipal(): void
    {
        $this->grants()->grant($this->alice, 'entry', $this->e1, $this->bob, 'read', null, $this->sk[$this->alice]);
        $this->assertTrue($this->container['userModel']->remove($this->bob));
        (new Rekeyer($this->container, fn () => $this->now))->rekey('entry', $this->e1, $this->sk[$this->alice], $this->alice);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND key_epoch = ?', [$this->bob, $this->epoch('entry', $this->e1)]));
        $this->assertVaultError('not_enrolled', fn () => $this->grants()->grant($this->alice, 'entry', $this->e3, $this->bob, 'read', null, $this->sk[$this->alice]));
    }

    // R8(b): grant, key and re-key queue rows whose object no longer exists are removed; rows for live objects stay.
    // Kills: leaving orphans, or deleting by type alone.
    public function testPurgeRemovesOrphanedPolymorphicRows(): void
    {
        $pdo = $this->pdo();
        $pdo->prepare("INSERT INTO vault_grants (subject_type, subject_id, grantee_id, permission, created_at) VALUES ('entry', 9999, ?, 'read', ?)")->execute([$this->bob, $this->now]);
        $pdo->prepare("INSERT INTO vault_keys (object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek) VALUES ('group', 9999, ?, 1, 1, 'eA==')")->execute([$this->bob]);
        $pdo->prepare("INSERT INTO vault_keys (object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek) VALUES ('entry', 9998, ?, 1, 1, 'eA==')")->execute([$this->bob]);
        $pdo->prepare("INSERT INTO vault_rekey_queue (object_type, object_id, expected_key_epoch, created_at) VALUES ('entry', 9997, 1, ?)")->execute([$this->now]);
        $pdo->prepare("INSERT INTO vault_rekey_queue (object_type, object_id, expected_key_epoch, created_at) VALUES ('group', ?, 1, ?)")->execute([$this->g2, $this->now]);
        $keysBefore = $this->countRows('SELECT COUNT(*) FROM vault_keys');

        $counts = $this->purger()->run($this->now, true);
        $this->assertSame(4, $counts['orphan_rows']);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants'));
        $this->assertSame($keysBefore - 2, $this->countRows('SELECT COUNT(*) FROM vault_keys'));
        $this->assertSame([['group', $this->g2, 1]], $this->queued());
    }

    // The rest of the purge: expired sessions, challenges, reservations and shares, and audit rows past retention
    // (365 days by default). Each share expiry is audited for its creator. Kills: off-by-one at the boundary
    // (a row expiring exactly now is gone), purging live rows.
    public function testPurgeExpiresSessionsChallengesReservationsSharesAndAudit(): void
    {
        $pdo = $this->pdo();
        $now = $this->now;
        foreach ([['s-idle', $now, $now + 100], ['s-abs', $now + 100, $now], ['s-live', $now + 1, $now + 100]] as [$sid, $idle, $abs]) {
            $pdo->prepare("INSERT INTO vault_sessions (sid_hash, user_id, nonce, enc_sk, created_at, last_used_at, idle_expires_at, abs_expires_at) VALUES (?, ?, 'bg==', 'ZQ==', ?, ?, ?, ?)")
                ->execute([$sid, $this->alice, $now - 10, $now - 10, $idle, $abs]);
        }
        foreach ([[$now], [$now + 1]] as [$exp]) {
            $pdo->prepare("INSERT INTO vault_challenges (user_id, purpose, challenge_hash, expires_at) VALUES (?, 'register', 'h', ?)")->execute([$this->alice, $exp]);
        }
        foreach ([['r-old', $now], ['r-live', $now + 1]] as [$id, $exp]) {
            $pdo->prepare("INSERT INTO vault_share_reservations (id_hash, creator_id, sid_hash, expires_at) VALUES (?, ?, 's', ?)")->execute([$id, $this->alice, $exp]);
        }
        foreach ([['sh-old', $now], ['sh-live', $now + 1]] as [$id, $exp]) {
            $pdo->prepare("INSERT INTO vault_shares (id_hash, burn_hash, creator_id, ciphertext, iv, salt, created_at, expires_at) VALUES (?, 'b', ?, 'c', 'i', 's', ?, ?)")->execute([$id, $this->bob, $now - 10, $exp]);
        }
        $day = 86400;
        foreach ([$now - 365 * $day - 1, $now - 365 * $day + 1] as $at) {
            $pdo->prepare("INSERT INTO vault_audit (created_at, actor_kind, action, via) VALUES (?, 'human', 'unlock', 'ui')")->execute([$at]);
        }

        $counts = $this->purger()->run($now, true);
        $this->assertSame(['s-live'], $pdo->query('SELECT sid_hash FROM vault_sessions')->fetchAll(\PDO::FETCH_COLUMN));
        $this->assertSame([(string) ($now + 1)], array_map('strval', $pdo->query('SELECT expires_at FROM vault_challenges')->fetchAll(\PDO::FETCH_COLUMN)));
        $this->assertSame(['r-live'], $pdo->query('SELECT id_hash FROM vault_share_reservations')->fetchAll(\PDO::FETCH_COLUMN));
        $this->assertSame(['sh-live'], $pdo->query('SELECT id_hash FROM vault_shares')->fetchAll(\PDO::FETCH_COLUMN));
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_audit WHERE action = 'unlock' AND via = 'ui'"));
        $this->assertSame([2, 1, 1, 1, 1], [$counts['sessions'], $counts['challenges'], $counts['reservations'], $counts['shares'], $counts['audit']]);
        $this->assertSame([['share_expire', ['target_user_id' => $this->bob, 'share_hash' => 'sh-old']]], $this->audits);
    }
}
