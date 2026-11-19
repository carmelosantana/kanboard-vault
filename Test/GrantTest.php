<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\RecipientResolver;
use Kanboard\Plugin\Vault\Model\Rekeyer;
use KanboardTests\units\Base;

// Spec: Entries, groups and grants, from "Adding a recipient" through "Edit permission": grant sources,
// effective recipients, revocation, removals, the re-key queue, expiry reconciliation, the write barrier and
// moves. Alice owns everything; Bob, Carol and Dave are grantees.
class GrantTest extends Base
{
    use VaultFixture;

    private int $carol;
    private int $dave;
    private string $aliceSk;
    private string $bobSk;
    private string $carolSk;
    private string $daveSk;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->carol = (int) $this->container['userModel']->create(['username' => 'carol', 'password' => 'carol login password 1']);
        $this->dave = (int) $this->container['userModel']->create(['username' => 'dave', 'password' => 'dave login password 1']);
        $this->aliceSk = $this->enrol($this->alice);
        $this->bobSk = $this->enrol($this->bob);
        $this->carolSk = $this->enrol($this->carol);
        $this->daveSk = $this->enrol($this->dave);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function enrol(int $userId): string
    {
        $keypair = sodium_crypto_box_keypair();
        $this->pdo()->prepare("INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at, live_user_id) VALUES (?, 'human', ?, 1, 'active', ?, ?)")
            ->execute([$userId, base64_encode(sodium_crypto_box_publickey($keypair)), $this->now, $userId]);
        return sodium_crypto_box_secretkey($keypair);
    }

    private function store(): ObjectStore
    {
        return new ObjectStore($this->container, fn () => $this->now);
    }

    private function grants(): GrantModel
    {
        return new GrantModel($this->container, fn () => $this->now);
    }

    private function rekeyer(): Rekeyer
    {
        return new Rekeyer($this->container, fn () => $this->now);
    }

    private function group(?int $parent = null, string $name = 'g'): int
    {
        return $this->store()->createGroup($this->alice, $parent, ['name' => $name]);
    }

    private function entry(int $group, string $title = 'e', string $password = 'pw'): int
    {
        return $this->store()->createEntry($this->alice, $group, ['title' => $title, 'password' => $password]);
    }

    private function grant(string $type, int $id, int $grantee, string $perm = 'read', ?int $expiresAt = null): void
    {
        $this->grants()->grant($this->alice, $type, $id, $grantee, $perm, $expiresAt, $this->aliceSk);
    }

    private function title(int $actor, int $entry, string $sk): string
    {
        return $this->store()->readEntry($actor, $entry, $sk)['payload']['title'];
    }

    private function epoch(string $type, int $id): int
    {
        $table = $type === 'entry' ? 'vault_entries' : 'vault_groups';
        return (int) $this->row("SELECT key_epoch FROM $table WHERE id = ?", [$id])['key_epoch'];
    }

    private function queued(string $type, int $id): ?int
    {
        $r = $this->row('SELECT expected_key_epoch FROM vault_rekey_queue WHERE object_type = ? AND object_id = ?', [$type, $id]);
        return $r === null ? null : (int) $r['expected_key_epoch'];
    }

    private function keyRows(string $type, int $id, int $principal): int
    {
        return $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ?', [$type, $id, $principal]);
    }

    private function keypair(string $sk): string
    {
        return sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, sodium_crypto_box_publickey_from_secretkey($sk));
    }

    // What a principal could keep from a backup: their sealed DEK, opened with their sk.
    private function stolenDek(string $type, int $id, int $principal, string $sk): string
    {
        $r = $this->row('SELECT key_epoch, sealed_dek FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ?', [$type, $id, $principal]);
        $this->assertNotNull($r, "a key row for $principal on $type $id");
        return Sealer::openDek(base64_decode($r['sealed_dek']), $this->keypair($sk), $type, $id, (int) $r['key_epoch'], $principal);
    }

    // Does $dek open the object's current ciphertext? Tried under the current AD and every earlier epoch's AD.
    private function opens(string $type, int $id, string $dek): bool
    {
        $table = $type === 'entry' ? 'vault_entries' : 'vault_groups';
        $r = $this->row("SELECT * FROM $table WHERE id = ?", [$id]);
        for ($epoch = 1; $epoch <= (int) $r['key_epoch']; $epoch++) {
            try {
                Aead::open(base64_decode($r['nonce']), base64_decode($r['ciphertext']), $dek, ObjectStore::ad($type, $id, (int) $r['owner_id'], $epoch));
                return true;
            } catch (\Kanboard\Plugin\Vault\Crypto\CryptoException) {
            }
        }
        return false;
    }

    // Revoking one source keeps access granted by another. Kills: a revoke that drops the grantee's key rows
    // (or re-seals) without recomputing the effective recipients from the remaining live sources.
    public function testOverlappingSourcesSurviveOneRevoke(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'shared');
        $this->grant('entry', $e, $this->carol);
        $this->grant('group', $g, $this->carol);
        $this->grants()->revoke($this->alice, 'entry', $e, $this->carol, $this->aliceSk);

        $this->assertSame(2, $this->epoch('entry', $e), 'revocation re-keyed the entry');
        $this->assertSame('shared', $this->title($this->carol, $e, $this->carolSk));
        $this->assertSame(1, $this->keyRows('entry', $e, $this->carol));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_grants WHERE subject_type = 'entry'"));
        // The group source still covers Carol: revoking it now takes her access away.
        $this->grants()->revoke($this->alice, 'group', $g, $this->carol, $this->aliceSk);
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->carol, $e, $this->carolSk));
        $this->assertVaultError('not_found', fn () => $this->grants()->revoke($this->alice, 'group', $g, $this->carol, $this->aliceSk));
    }

    // A grant on a group reaches entries and groups any depth below it, sealed while Carol is offline.
    // Kills: an ancestor walk that stops at the direct parent, and sealing only to the granted object.
    public function testNestedGroupGrant(): void
    {
        $top = $this->group(null, 'top');
        $mid = $this->group($top, 'mid');
        $leaf = $this->group($mid, 'leaf');
        $deep = $this->entry($leaf, 'deep');
        $side = $this->group(null, 'side');
        $other = $this->entry($side, 'other');
        $this->grant('group', $top, $this->carol);

        $this->assertSame('deep', $this->title($this->carol, $deep, $this->carolSk));
        $this->assertSame('mid', $this->store()->readGroup($this->carol, $mid, $this->carolSk)['payload']['name']);
        $this->assertSame(['deep'], array_column($this->store()->listEntries($this->carol, $leaf, $this->carolSk), 'title'));
        foreach ([['group', $top], ['group', $mid], ['group', $leaf], ['entry', $deep]] as [$t, $id]) {
            $this->assertSame(1, $this->keyRows($t, $id, $this->carol), "$t $id sealed to Carol");
        }
        $this->assertSame(0, $this->keyRows('entry', $other, $this->carol));
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->carol, $other, $this->carolSk));
        $this->assertSame([$this->alice => 'owner', $this->carol => 'read'], (new RecipientResolver($this->container))->effective('entry', $deep, $this->now));
    }

    // Kills: ignoring expires_at on the read path, and an off-by-one at the expiry instant.
    public function testExpiredGrantRefusedOnRead(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'timed');
        $this->grant('group', $g, $this->carol, 'read', $this->now + 100);
        $this->now += 99;
        $this->assertSame('timed', $this->title($this->carol, $e, $this->carolSk));
        $this->now += 1;
        // The key rows are still there (no purge ran, nothing was written): the live grant check refuses.
        $this->assertSame(1, $this->keyRows('entry', $e, $this->carol));
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->carol, $e, $this->carolSk));
        $this->assertVaultError('not_found', fn () => $this->store()->readGroup($this->carol, $g, $this->carolSk));
        $this->assertVaultError('not_found', fn () => $this->store()->listEntries($this->carol, $g, $this->carolSk));
        $this->assertSame([$this->alice => 'owner'], (new RecipientResolver($this->container))->effective('entry', $e, $this->now));
    }

    // A valid sealed DEK with no grant behind it opens nothing. Kills: a read path that trusts the key row.
    public function testKeyRowAloneDoesNotGrant(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'mine');
        $dek = $this->stolenDek('entry', $e, $this->alice, $this->aliceSk);
        $pk = sodium_crypto_box_publickey_from_secretkey($this->carolSk);
        foreach ([['entry', $e, $dek], ['group', $g, $this->stolenDek('group', $g, $this->alice, $this->aliceSk)]] as [$t, $id, $d]) {
            $this->pdo()->prepare('INSERT INTO vault_keys (object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek) VALUES (?, ?, ?, 1, 1, ?)')
                ->execute([$t, $id, $this->carol, base64_encode(Sealer::sealDek($d, $t, $id, 1, $this->carol, $pk))]);
        }
        $this->assertSame($dek, $this->stolenDek('entry', $e, $this->carol, $this->carolSk), 'the stray row really opens');
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->carol, $e, $this->carolSk));
        $this->assertVaultError('not_found', fn () => $this->store()->readGroup($this->carol, $g, $this->carolSk));
        $this->assertVaultError('not_found', fn () => $this->store()->listEntries($this->carol, $g, $this->carolSk));
        $this->assertVaultError('not_found', fn () => $this->store()->updateEntry($this->carol, $e, 1, ['title' => 'x'], $this->carolSk));
        $this->assertVaultError('not_found', fn () => $this->rekeyer()->rekey('entry', $e, $this->carolSk, $this->carol));
    }

    // Revocation re-keys the object and the whole subtree: a new DEK and key_epoch + 1 over the current payload,
    // sealed to the remaining recipients. Kills: deleting the grant and key rows without re-keying, re-using the
    // DEK, re-keying only the granted group, and dropping a remaining recipient.
    public function testRevokeRekeys(): void
    {
        $g = $this->group(null, 'top');
        $child = $this->group($g, 'child');
        $e = $this->entry($child, 'secret', 'hunter2');
        $this->grant('group', $g, $this->carol);
        $this->grant('group', $g, $this->dave, 'edit');
        $this->store()->updateEntry($this->dave, $e, 1, ['title' => 'secret', 'password' => 'edited'], $this->daveSk);
        $old = $this->stolenDek('entry', $e, $this->carol, $this->carolSk);
        $oldGroup = $this->stolenDek('group', $child, $this->carol, $this->carolSk);
        $this->assertTrue($this->opens('entry', $e, $old), 'control: the DEK opens the current ciphertext');

        $this->grants()->revoke($this->alice, 'group', $g, $this->carol, $this->aliceSk);

        foreach ([['group', $g], ['group', $child], ['entry', $e]] as [$t, $id]) {
            $this->assertSame(2, $this->epoch($t, $id), "$t $id re-keyed");
            $this->assertSame(0, $this->keyRows($t, $id, $this->carol));
            $this->assertNull($this->queued($t, $id), "$t $id needs no queued re-key");
        }
        $this->assertFalse($this->opens('entry', $e, $old), 'the old DEK opens nothing new');
        $this->assertFalse($this->opens('group', $child, $oldGroup));
        $this->assertNotSame($old, $this->stolenDek('entry', $e, $this->dave, $this->daveSk));
        $this->assertSame('edited', $this->store()->readField($this->dave, $e, 'password', $this->daveSk));
        $this->assertSame('edited', $this->store()->readField($this->alice, $e, 'password', $this->aliceSk));
        $this->assertSame(2, $this->store()->readEntry($this->alice, $e, $this->aliceSk)['version'], 're-keying is not an edit');
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->carol, $e, $this->carolSk));
    }

    // Kills: write gates that accept read (update, create in the group), however the read was granted.
    public function testReadOnlyCannotEdit(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'ro');
        $this->grant('group', $g, $this->carol);
        $this->grant('entry', $e, $this->bob);
        foreach ([[$this->carol, $this->carolSk], [$this->bob, $this->bobSk]] as [$who, $sk]) {
            $this->assertSame('ro', $this->title($who, $e, $sk));
            $this->assertVaultError('not_found', fn () => $this->store()->updateEntry($who, $e, 1, ['title' => 'pwned'], $sk));
            $this->assertVaultError('not_found', fn () => $this->store()->createEntry($who, $g, ['title' => 'planted']));
        }
        $this->assertSame(1, (int) $this->row('SELECT version FROM vault_entries WHERE id = ?', [$e])['version']);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
    }

    // Edit is not ownership. Kills: grant, revoke, move or delete gates that accept edit.
    public function testEditCannotGrant(): void
    {
        $g = $this->group();
        $h = $this->group(null, 'h');
        $e = $this->entry($g, 'x');
        $this->grant('group', $g, $this->bob, 'edit');
        $this->grant('group', $h, $this->bob, 'edit');
        $this->grant('entry', $e, $this->dave);
        $gm = $this->grants();
        $this->assertSame(2, $this->store()->updateEntry($this->bob, $e, 1, ['title' => 'bob was here'], $this->bobSk));
        $this->assertVaultError('not_found', fn () => $gm->grant($this->bob, 'entry', $e, $this->carol, 'read', null, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $gm->grant($this->bob, 'group', $g, $this->carol, 'edit', null, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $gm->revoke($this->bob, 'entry', $e, $this->dave, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $gm->move($this->bob, 'entry', $e, $h, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $this->store()->deleteObject($this->bob, 'entry', $e, $this->bobSk));
        $this->assertSame(3, $this->countRows('SELECT COUNT(*) FROM vault_grants'));
        $this->assertSame(0, $this->keyRows('entry', $e, $this->carol));
        $this->assertSame($g, (int) $this->row('SELECT group_id FROM vault_entries WHERE id = ?', [$e])['group_id']);
        // The owner, by contrast, may.
        $gm->grant($this->alice, 'entry', $e, $this->carol, 'read', null, $this->aliceSk);
        $this->assertSame('bob was here', $this->title($this->carol, $e, $this->carolSk));
    }

    // Kills: a new entry owned by its creator, and sealing it only to the creator (or the owner).
    public function testEntryAddedByEditorOwnedByGroupOwner(): void
    {
        $g = $this->group();
        $this->grant('group', $g, $this->bob, 'edit');
        $this->grant('group', $g, $this->carol);
        $e = $this->store()->createEntry($this->bob, $g, ['title' => 'from bob', 'password' => 'p']);
        $row = $this->row('SELECT owner_id, created_by FROM vault_entries WHERE id = ?', [$e]);
        $this->assertSame([$this->alice, $this->bob], [(int) $row['owner_id'], (int) $row['created_by']]);
        foreach ([[$this->alice, $this->aliceSk], [$this->bob, $this->bobSk], [$this->carol, $this->carolSk]] as [$who, $sk]) {
            $this->assertSame('from bob', $this->title($who, $e, $sk));
        }
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->dave, $e, $this->daveSk));
        // Owned by Alice: Bob can't delete or re-share it, Alice can.
        $this->assertVaultError('not_found', fn () => $this->store()->deleteObject($this->bob, 'entry', $e, $this->bobSk));
        $this->grants()->grant($this->alice, 'entry', $e, $this->dave, 'read', null, $this->aliceSk);
        $this->assertSame('from bob', $this->title($this->dave, $e, $this->daveSk));
    }

    // A move is one authorisation change over the moved subtree: added recipients get keys, removed ones lose
    // their key rows, and every object that lost someone is queued at its current epoch. Kills: a move that only
    // changes parent_id, one that handles only the moved object (not its subtree), and a missing queue row.
    public function testMoveOutOfSharedGroupRemovesAccessAndQueues(): void
    {
        $shared = $this->group(null, 'shared');
        $private = $this->group(null, 'private');
        $e = $this->entry($shared, 'moving');
        $sub = $this->group($shared, 'sub');
        $deep = $this->entry($sub, 'deep');
        $this->grant('group', $shared, $this->carol);
        $this->grant('group', $private, $this->dave);

        $this->grants()->move($this->alice, 'entry', $e, $private, $this->aliceSk);
        $this->assertSame($private, (int) $this->row('SELECT group_id FROM vault_entries WHERE id = ?', [$e])['group_id']);
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->carol, $e, $this->carolSk));
        $this->assertSame(0, $this->keyRows('entry', $e, $this->carol));
        $this->assertSame(1, $this->queued('entry', $e));
        $this->assertSame('moving', $this->title($this->dave, $e, $this->daveSk), 'the new group grantee was sealed in');
        $this->assertSame('moving', $this->title($this->alice, $e, $this->aliceSk));

        // A group subtree moves as one.
        $this->grants()->move($this->alice, 'group', $sub, $private, $this->aliceSk);
        foreach ([['group', $sub], ['entry', $deep]] as [$t, $id]) {
            $this->assertSame(0, $this->keyRows($t, $id, $this->carol), "$t $id");
            $this->assertSame(1, $this->queued($t, $id), "$t $id");
            $this->assertSame(1, $this->keyRows($t, $id, $this->dave), "$t $id");
        }
        $this->assertSame('deep', $this->title($this->dave, $deep, $this->daveSk));
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->carol, $deep, $this->carolSk));
        // Moving to the top level is allowed for groups; into one's own subtree, or someone else's group, is not.
        $this->assertVaultError('invalid_move', fn () => $this->grants()->move($this->alice, 'group', $private, $sub, $this->aliceSk));
        $this->assertVaultError('invalid_move', fn () => $this->grants()->move($this->alice, 'group', $sub, $sub, $this->aliceSk));
        $this->assertVaultError('invalid_move', fn () => $this->grants()->move($this->alice, 'entry', $e, null, $this->aliceSk));
        $bobs = $this->store()->createGroup($this->bob, null, ['name' => 'bobs']);
        $this->assertVaultError('not_found', fn () => $this->grants()->move($this->alice, 'entry', $e, $bobs, $this->aliceSk));
        $this->grants()->move($this->alice, 'group', $sub, null, $this->aliceSk);
        $this->assertNull($this->row('SELECT parent_id FROM vault_groups WHERE id = ?', [$sub])['parent_id']);
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->dave, $deep, $this->daveSk));
        // A move without the owner's current key changes nothing.
        $this->assertVaultError('not_found', fn () => $this->grants()->move($this->alice, 'entry', $e, $shared, $this->bobSk));
        $this->assertSame($private, (int) $this->row('SELECT group_id FROM vault_entries WHERE id = ?', [$e])['group_id']);
    }

    // A queued object takes no payload update until re-keyed, and the writer re-keys it inline in the same
    // transaction. Kills: a missing barrier (the edit lands under the DEK the removed principal still holds).
    public function testWriteBarrierRekeysQueuedObject(): void
    {
        $shared = $this->group(null, 'shared');
        $private = $this->group(null, 'private');
        $e = $this->entry($shared, 'before');
        $this->grant('group', $shared, $this->carol);
        $this->grant('group', $private, $this->bob, 'edit');
        $carolCopy = $this->stolenDek('entry', $e, $this->carol, $this->carolSk);
        $this->grants()->move($this->alice, 'entry', $e, $private, $this->aliceSk);
        $this->assertSame(1, $this->queued('entry', $e));
        $this->assertTrue($this->opens('entry', $e, $carolCopy), 'the move alone does not re-key');

        $this->assertSame(2, $this->store()->updateEntry($this->bob, $e, 1, ['title' => 'after'], $this->bobSk));
        $this->assertSame(2, $this->epoch('entry', $e));
        $this->assertNull($this->queued('entry', $e));
        $this->assertFalse($this->opens('entry', $e, $carolCopy), 'data written after the removal is out of reach of the old DEK');
        $this->assertSame('after', $this->title($this->alice, $e, $this->aliceSk));
        $this->assertSame('after', $this->title($this->bob, $e, $this->bobSk));
    }

    // Expiry is reconciled by the write itself, under its lock, without waiting for the purge (none runs here).
    // Kills: a write path that skips expiry reconciliation, so the edit lands under the expired grantee's DEK.
    public function testEditImmediatelyAfterExpiryRekeysFirst(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'v1');
        $this->grant('entry', $e, $this->carol, 'read', $this->now + 60);
        $carolCopy = $this->stolenDek('entry', $e, $this->carol, $this->carolSk);
        $this->now += 60;

        $this->store()->updateEntry($this->alice, $e, 1, ['title' => 'v2'], $this->aliceSk);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants'), 'the expired source was removed');
        $this->assertSame(0, $this->keyRows('entry', $e, $this->carol));
        $this->assertSame(2, $this->epoch('entry', $e));
        $this->assertNull($this->queued('entry', $e));
        $this->assertFalse($this->opens('entry', $e, $carolCopy));
        $this->assertSame('v2', $this->title($this->alice, $e, $this->aliceSk));
    }

    // Entry A's edit reconciles an expired grant on the shared group, which must queue sibling B (and the
    // group) too; B's next edit then re-keys first. Kills: removing a group source for the triggering subject
    // only, and deleting the source before queueing its subtree.
    public function testTwoSiblingExpiry(): void
    {
        $g = $this->group();
        $a = $this->entry($g, 'A');
        $b = $this->entry($g, 'B');
        $this->grant('group', $g, $this->carol, 'read', $this->now + 10);
        $carolB = $this->stolenDek('entry', $b, $this->carol, $this->carolSk);
        $this->now += 10;

        $this->store()->updateEntry($this->alice, $a, 1, ['title' => 'A2'], $this->aliceSk);
        $this->assertSame(2, $this->epoch('entry', $a));
        $this->assertSame(1, $this->queued('entry', $b), 'the sibling carries the barrier');
        $this->assertSame(1, $this->queued('group', $g));
        $this->assertSame(0, $this->keyRows('entry', $b, $this->carol));
        $this->assertSame(0, $this->keyRows('group', $g, $this->carol));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants'));

        $this->store()->updateEntry($this->alice, $b, 1, ['title' => 'B2'], $this->aliceSk);
        $this->assertSame(2, $this->epoch('entry', $b), 'B was re-keyed before its edit');
        $this->assertNull($this->queued('entry', $b));
        $this->assertFalse($this->opens('entry', $b, $carolB));
        $this->assertSame('B2', $this->title($this->alice, $b, $this->aliceSk));
    }

    // A queue item re-keys only if key_epoch still equals the epoch it was queued at, and the row goes either
    // way. Kills: re-keying regardless of the epoch (a second re-key), and leaving the row behind.
    public function testQueueIdempotentOnEpochChange(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'q');
        $f = $this->entry($g, 'r');
        $this->pdo()->prepare("INSERT INTO vault_rekey_queue (object_type, object_id, expected_key_epoch, created_at) VALUES ('entry', ?, 1, ?), ('entry', ?, 1, ?)")
            ->execute([$e, $this->now, $f, $this->now]);
        // $e was re-keyed by other means since it was queued (its epoch moved on, the queue row stayed).
        $this->rekeyer()->rekey('entry', $e, $this->aliceSk, $this->alice);
        $this->assertSame(2, $this->epoch('entry', $e));
        $this->pdo()->prepare("INSERT INTO vault_rekey_queue (object_type, object_id, expected_key_epoch, created_at) VALUES ('entry', ?, 1, ?)")
            ->execute([$e, $this->now]);

        $this->assertSame(2, $this->rekeyer()->drainQueue($this->alice, $this->aliceSk));
        $this->assertSame(2, $this->epoch('entry', $e), 'a stale item is dropped, not re-keyed again');
        $this->assertSame(2, $this->epoch('entry', $f), 'a current item is re-keyed once');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rekey_queue'));
        $this->assertSame(0, $this->rekeyer()->drainQueue($this->alice, $this->aliceSk));
        $this->assertSame(2, $this->epoch('entry', $f));
        $this->assertSame('r', $this->title($this->alice, $f, $this->aliceSk));
    }

    // Only a live recipient holding the DEK can process an item; anyone else leaves it queued.
    // Kills: draining with a key the holder doesn't have, or for a holder who lost access.
    public function testDrainSkipsWhatHolderCannotOpen(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'q');
        $this->grant('group', $g, $this->carol, 'read', $this->now + 5);
        $this->grant('group', $g, $this->dave);
        $this->pdo()->prepare("INSERT INTO vault_rekey_queue (object_type, object_id, expected_key_epoch, created_at) VALUES ('entry', ?, 1, ?)")->execute([$e, $this->now]);
        $this->now += 5;
        $this->assertSame(0, $this->rekeyer()->drainQueue($this->carol, $this->carolSk), 'an expired grantee cannot re-key');
        $this->assertSame(0, $this->rekeyer()->drainQueue($this->bob, $this->bobSk), 'a non-holder cannot re-key');
        $this->assertVaultError('not_found', fn () => $this->rekeyer()->drainQueue($this->dave, $this->bobSk));
        $this->assertSame(1, $this->queued('entry', $e));
        $this->assertSame(1, $this->rekeyer()->drainQueue($this->dave, $this->daveSk));
        $this->assertSame(2, $this->epoch('entry', $e));
        $this->assertSame(0, $this->keyRows('entry', $e, $this->carol), 'the re-key seals to live recipients only');
        $this->assertSame('q', $this->title($this->dave, $e, $this->daveSk));
    }

    // T7 minor: drainQueue skips items this holder can't re-key and goes on to the ones it can, so one stuck item
    // can't block the holder's queue. Kills: the LIMIT taken over every item the holder has a key row on (the
    // expired item first in the queue would use up max = 1 and nothing would be cleared).
    public function testDrainContinuesPastItemsTheHolderCannotRekey(): void
    {
        $g1 = $this->group(null, 'g1');
        $g2 = $this->group(null, 'g2');
        $e1 = $this->entry($g1, 'stuck');
        $e2 = $this->entry($g2, 'ok');
        $this->grant('group', $g1, $this->carol, 'read', $this->now + 5);
        $this->grant('group', $g2, $this->carol);
        $this->pdo()->prepare("INSERT INTO vault_rekey_queue (object_type, object_id, expected_key_epoch, created_at) VALUES ('entry', ?, 1, ?), ('entry', ?, 1, ?)")
            ->execute([$e1, $this->now, $e2, $this->now]);
        $this->now += 5;
        $this->assertSame(1, $this->rekeyer()->drainQueue($this->carol, $this->carolSk, 1));
        $this->assertSame(1, $this->queued('entry', $e1), 'the item carol cannot re-key stays');
        $this->assertNull($this->queued('entry', $e2));
        $this->assertSame(2, $this->epoch('entry', $e2));
    }

    // The highest live permission wins across sources. Kills: first-source-wins and direct-only resolution.
    public function testHighestPermissionWins(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'x');
        $this->grant('entry', $e, $this->carol, 'read');
        $this->grant('group', $g, $this->carol, 'edit', $this->now + 50);
        $r = new RecipientResolver($this->container);
        $this->assertSame([$this->alice => 'owner', $this->carol => 'edit'], $r->effective('entry', $e, $this->now));
        $this->assertSame(2, $this->store()->updateEntry($this->carol, $e, 1, ['title' => 'y'], $this->carolSk));
        $this->now += 50;
        $this->assertSame([$this->alice => 'owner', $this->carol => 'read'], $r->effective('entry', $e, $this->now));
        $this->assertVaultError('not_found', fn () => $this->store()->updateEntry($this->carol, $e, 2, ['title' => 'z'], $this->carolSk));
        $this->assertSame('y', $this->title($this->carol, $e, $this->carolSk));
    }

    // Grantees must be enrolled; bad input is refused without writing anything.
    public function testGrantValidation(): void
    {
        $g = $this->group();
        $eve = (int) $this->container['userModel']->create(['username' => 'eve', 'password' => 'eve login password 1']);
        $gm = $this->grants();
        $this->assertVaultError('not_enrolled', fn () => $gm->grant($this->alice, 'group', $g, $eve, 'read', null, $this->aliceSk));
        $this->assertVaultError('payload_invalid', fn () => $gm->grant($this->alice, 'group', $g, $this->carol, 'owner', null, $this->aliceSk));
        $this->assertVaultError('payload_invalid', fn () => $gm->grant($this->alice, 'group', $g, $this->alice, 'read', null, $this->aliceSk));
        $this->assertVaultError('payload_invalid', fn () => $gm->grant($this->alice, 'group', $g, $this->carol, 'read', $this->now, $this->aliceSk));
        $this->assertVaultError('not_found', fn () => $gm->grant($this->alice, 'group', $g, $this->carol, 'read', null, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $gm->grant($this->alice, 'group', 9999, $this->carol, 'read', null, $this->aliceSk));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants'));
        // A repeat grant updates the one source row.
        $gm->grant($this->alice, 'group', $g, $this->carol, 'read', null, $this->aliceSk);
        $gm->grant($this->alice, 'group', $g, $this->carol, 'edit', $this->now + 9, $this->aliceSk);
        $row = $this->row('SELECT permission, expires_at, granted_by FROM vault_grants');
        $this->assertSame(['edit', $this->now + 9, $this->alice], [$row['permission'], (int) $row['expires_at'], (int) $row['granted_by']]);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_grants'));
        $this->expectException(\InvalidArgumentException::class);
        $gm->grant($this->alice, 'share', $g, $this->carol, 'read', null, $this->aliceSk);
    }

    // Granting on a queued object re-keys it first, so the new grantee never gets the DEK a removed
    // principal still holds. Kills: sealing the stale DEK to a newcomer.
    public function testGrantOnQueuedObjectRekeysFirst(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'x');
        $this->grant('entry', $e, $this->carol, 'read', $this->now + 1);
        $carolCopy = $this->stolenDek('entry', $e, $this->carol, $this->carolSk);
        $this->now += 1;
        $this->grants()->removeSource((int) $this->row('SELECT id FROM vault_grants')['id']);
        $this->assertSame(1, $this->queued('entry', $e));
        $this->grant('entry', $e, $this->dave);
        $this->assertNull($this->queued('entry', $e));
        $this->assertNotSame($carolCopy, $this->stolenDek('entry', $e, $this->dave, $this->daveSk));
        $this->assertFalse($this->opens('entry', $e, $carolCopy));
    }

    // R8: a grant on an object that no longer exists is ignored, and removing it just deletes the row.
    public function testGrantOnMissingObjectIgnored(): void
    {
        $g = $this->group();
        $e = $this->entry($g, 'x');
        $this->grant('entry', $e, $this->carol);
        $this->pdo()->prepare('DELETE FROM vault_entries WHERE id = ?')->execute([$e]);
        $this->assertSame([], (new RecipientResolver($this->container))->effective('entry', $e, $this->now));
        $this->grants()->removeSource((int) $this->row('SELECT id FROM vault_grants')['id']);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants'));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rekey_queue'));
        $this->grants()->removeSource(424242);
    }

    // R23: the list shows only rows the caller is entitled to; an entitled row that fails to decrypt is marked
    // integrity_error (no data) instead of failing the page.
    public function testListMarksIntegrityErrorPerRow(): void
    {
        $g = $this->group();
        $good = $this->entry($g, 'good');
        $bad = $this->entry($g, 'bad');
        $this->grant('group', $g, $this->carol);
        $this->pdo()->prepare("UPDATE vault_entries SET ciphertext = 'AAAA' WHERE id = ?")->execute([$bad]);
        $list = $this->store()->listEntries($this->carol, $g, $this->carolSk);
        $this->assertCount(2, $list);
        $this->assertSame('good', $list[0]['title']);
        $this->assertSame(['id' => $bad, 'group_id' => $g, 'integrity_error' => true], $list[1]);
    }

    // R45: a group's name and metadata are a payload write like an entry's: the gate is edit (owner or an edit
    // grantee), never read. A refused rename changes nothing. Kills: updateGroup gated on read; the gate dropped.
    public function testReadGranteeCannotRenameGroup(): void
    {
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'Infra', 'icon' => 'server', 'notes' => 'racks']);
        $this->grant('group', $g, $this->carol, 'read');
        $this->grant('group', $g, $this->bob, 'edit');
        $before = $this->row('SELECT nonce, ciphertext, key_epoch FROM vault_groups WHERE id = ?', [$g]);
        $this->assertVaultError('not_found', fn () => $this->store()->updateGroup($this->carol, $g, ['name' => 'hijacked'], $this->carolSk));
        $this->assertVaultError('not_found', fn () => $this->store()->updateGroup($this->dave, $g, ['name' => 'hijacked'], $this->daveSk));
        $this->assertSame($before, $this->row('SELECT nonce, ciphertext, key_epoch FROM vault_groups WHERE id = ?', [$g]));

        $this->store()->updateGroup($this->bob, $g, ['name' => 'Infra 2'], $this->bobSk);
        $this->assertSame(['name' => 'Infra 2', 'icon' => 'server', 'notes' => 'racks'], $this->store()->readGroup($this->carol, $g, $this->carolSk)['payload'], 'a rename keeps the icon and notes');
        $this->store()->updateGroup($this->alice, $g, ['notes' => 'cages'], $this->aliceSk);
        $this->assertSame(['name' => 'Infra 2', 'icon' => 'server', 'notes' => 'cages'], $this->store()->readGroup($this->alice, $g, $this->aliceSk)['payload']);
        $this->assertVaultError('payload_invalid', fn () => $this->store()->updateGroup($this->alice, $g, ['name' => ''], $this->aliceSk));
        $this->assertVaultError('payload_invalid', fn () => $this->store()->updateGroup($this->alice, $g, ['title' => 'x'], $this->aliceSk));
        $this->assertSame(2, count(array_filter($this->auditActionsFor('group', $g), fn (string $a): bool => $a === 'update')));
    }

    // R45 (the T7 carry): a group edit goes through beforeWrite, so a queued group is re-keyed inline before the new
    // name is written, and an expired grant on it (or an ancestor) is reconciled first. Kills: updateGroup skipping
    // beforeWrite (the new name lands under the DEK the removed principal still holds).
    public function testGroupRenameRekeysQueuedGroupFirst(): void
    {
        $parent = $this->group(null, 'parent');
        $g = $this->group($parent, 'child');
        $this->grant('group', $parent, $this->carol, 'read', $this->now + 30);
        $this->grant('group', $g, $this->bob, 'edit');
        $carolCopy = $this->stolenDek('group', $g, $this->carol, $this->carolSk);
        $this->now += 30;

        $this->store()->updateGroup($this->bob, $g, ['name' => 'renamed'], $this->bobSk);
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?", [$this->carol]), 'the expired ancestor grant was reconciled');
        $this->assertSame(2, $this->epoch('group', $g), 're-keyed before the write');
        $this->assertNull($this->queued('group', $g));
        $this->assertFalse($this->opens('group', $g, $carolCopy), 'the new name is out of reach of the old DEK');
        $this->assertSame('renamed', $this->store()->readGroup($this->alice, $g, $this->aliceSk)['payload']['name']);
    }

    // Spec, Agents (decision 5): agents read what they are granted and never overwrite what a human shared, so a grant
    // to an agent is read only, whatever path makes it. Kills: an edit grant to an agent accepted; read refused too.
    public function testGrantToAgentIsReadOnly(): void
    {
        $this->pdo()->prepare("UPDATE vault_principals SET kind = 'agent' WHERE user_id = ?")->execute([$this->dave]);
        $g = $this->group();
        $this->assertVaultError('agent_read_only', fn () => $this->grant('group', $g, $this->dave, 'edit'));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants'));
        $this->grant('group', $g, $this->dave, 'read');
        $this->assertVaultError('agent_read_only', fn () => $this->grant('group', $g, $this->dave, 'edit'));
        $this->assertSame('read', $this->row('SELECT permission FROM vault_grants')['permission'], 'an upgrade is refused too');
    }

    /** @return list<string> */
    private function auditActionsFor(string $type, int $id): array
    {
        $s = $this->pdo()->prepare('SELECT action FROM vault_audit WHERE object_type = ? AND object_id = ? ORDER BY id');
        $s->execute([$type, $id]);
        return array_column($s->fetchAll(\PDO::FETCH_ASSOC), 'action');
    }

    public function testSecretParametersAreSensitive(): void
    {
        $expected = [
            [GrantModel::class, 'grant', 'ownerSk'],
            [GrantModel::class, 'revoke', 'ownerSk'],
            [GrantModel::class, 'move', 'ownerSk'],
            [Rekeyer::class, 'rekey', 'anyHolderSk'],
            [Rekeyer::class, 'drainQueue', 'holderSk'],
            [ObjectStore::class, 'beforeWrite', 'sk'],
        ];
        foreach ($expected as [$class, $method, $param]) {
            $found = null;
            foreach ((new \ReflectionMethod($class, $method))->getParameters() as $p) {
                if ($p->getName() === $param) {
                    $found = $p;
                }
            }
            $this->assertNotNull($found, "$class::$method has \$$param");
            $this->assertCount(1, $found->getAttributes(\SensitiveParameter::class), "$class::$method \$$param");
        }
        // Every other method taking an sk, a DEK, a keypair or a payload is marked too.
        foreach ([GrantModel::class, Rekeyer::class, RecipientResolver::class, ObjectStore::class] as $class) {
            foreach ((new \ReflectionClass($class))->getMethods() as $m) {
                if ($m->getDeclaringClass()->getName() !== $class) {
                    continue;
                }
                foreach ($m->getParameters() as $p) {
                    if (preg_match('/(^sk$|Sk$|^dek$|Dek$|^keypair$|^payload$|^json$)/', $p->getName())) {
                        $this->assertCount(1, $p->getAttributes(\SensitiveParameter::class), "$class::{$m->getName()} \${$p->getName()}");
                    }
                }
            }
        }
    }
}
