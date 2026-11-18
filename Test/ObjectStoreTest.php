<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Model\EntryPayload;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use KanboardTests\units\Base;

// Spec: Entries, groups and grants (objects, AD binding, read path, optimistic versions). Owner only until T7.
class ObjectStoreTest extends Base
{
    use VaultFixture;

    private string $aliceSk;
    private string $bobSk;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->aliceSk = $this->enrol($this->alice);
        $this->bobSk = $this->enrol($this->bob);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    // A principal row with a fresh keypair (no wrap: these tests hand sk in directly). Returns sk.
    private function enrol(int $userId, int $keyGen = 1): string
    {
        $keypair = sodium_crypto_box_keypair();
        $this->pdo()->prepare("INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at) VALUES (?, 'human', ?, ?, 'active', ?)")
            ->execute([$userId, base64_encode(sodium_crypto_box_publickey($keypair)), $keyGen, $this->now]);
        return sodium_crypto_box_secretkey($keypair);
    }

    private function store(): ObjectStore
    {
        return new ObjectStore($this->container, fn () => $this->now);
    }

    private function aliceGroup(?int $parent = null, string $name = 'Servers'): int
    {
        return $this->store()->createGroup($this->alice, $parent, ['name' => $name]);
    }

    private function keypair(string $sk): string
    {
        return sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, sodium_crypto_box_publickey_from_secretkey($sk));
    }

    // Kills: a lossy JSON encoding (escaped unicode is fine, but a mangled or truncated value is not), and a
    // payload column too small for 100 KB. Every string comes back byte-identical.
    public function testRoundTripUnicodeTabsEmoji(): void
    {
        $g = $this->aliceGroup();
        $title = "Ünïcode\t🔑";
        $notes = str_repeat("line ünï 🔑\t\"q\" \\ / </script>\n", 4000);
        $this->assertGreaterThan(100 * 1024, strlen($notes));
        $payload = [
            'title' => $title,
            'username' => "root\u{0000}x",
            'password' => "p\u{00e4}ss 🔑 \t\\\"",
            'url' => 'https://example.com/a/b?c=d',
            'notes' => $notes,
            'tags' => ['prod', 'ü'],
            'expires_at' => 1_900_000_000,
            'otp' => 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP',
            'fields' => [['name' => 'PIN 🔢', 'value' => "12\t34", 'protected' => true]],
        ];
        $id = $this->store()->createEntry($this->alice, $g, $payload);
        $e = $this->store()->readEntry($this->alice, $id, $this->aliceSk);

        $this->assertSame($id, $e['id']);
        $this->assertSame($g, $e['group_id']);
        $this->assertSame(1, $e['version']);
        $this->assertSame($payload, $e['payload']);
        $this->assertSame($title, $e['payload']['title']);
        $this->assertSame($notes, $e['payload']['notes']);
        $this->assertSame("p\u{00e4}ss 🔑 \t\\\"", $this->store()->readField($this->alice, $id, 'password', $this->aliceSk));
        $this->assertSame("12\t34", $this->store()->readField($this->alice, $id, 'field:PIN 🔢', $this->aliceSk));
    }

    // Missing keys come back with their defaults, so every reader sees one shape.
    public function testMinimalPayloadIsNormalised(): void
    {
        $id = $this->store()->createEntry($this->alice, $this->aliceGroup(), ['title' => 'x']);
        $this->assertSame(
            ['title' => 'x', 'username' => '', 'password' => '', 'url' => '', 'notes' => '', 'tags' => [], 'expires_at' => null, 'otp' => '', 'fields' => []],
            $this->store()->readEntry($this->alice, $id, $this->aliceSk)['payload']
        );
    }

    // Kills: storing the payload (or its base64) in clear, and an unencrypted group name.
    public function testCiphertextHasNoPlaintext(): void
    {
        $g = $this->aliceGroup(null, 'GroupNameSentinel');
        $id = $this->store()->createEntry($this->alice, $g, ['title' => 'TitleSentinel-github', 'username' => 'UserSentinel', 'password' => 'PassSentinel']);
        $this->store()->updateEntry($this->alice, $id, 1, ['title' => 'TitleSentinel-github', 'password' => 'PassSentinel2'], $this->aliceSk);

        $dump = '';
        foreach (['vault_groups', 'vault_entries', 'vault_keys'] as $table) {
            foreach ($this->pdo()->query('SELECT * FROM '.$table)->fetchAll(\PDO::FETCH_ASSOC) as $row) {
                foreach ($row as $value) {
                    $dump .= $value."\n";
                    $decoded = base64_decode((string) $value, true);
                    if ($decoded !== false) {
                        $dump .= $decoded."\n";
                    }
                }
            }
        }
        $this->assertNotSame('', $dump);
        foreach (['GroupNameSentinel', 'TitleSentinel', 'UserSentinel', 'PassSentinel'] as $needle) {
            $this->assertStringNotContainsString($needle, $dump);
        }
        $row = $this->row('SELECT crypto_v, key_epoch, version FROM vault_entries WHERE id = ?', [$id]);
        $this->assertSame([1, 1, 2], array_map('intval', array_values($row)));
        $this->assertSame(1, (int) $this->row('SELECT crypto_v FROM vault_groups WHERE id = ?', [$g])['crypto_v']);
    }

    // Kills: a read path that trusts the key row (or the actor id) alone, a missing sk/pk check, and leaking
    // "exists but not yours" as a different error from "no such entry".
    public function testOtherUserCannotRead(): void
    {
        $g = $this->aliceGroup();
        $id = $this->store()->createEntry($this->alice, $g, ['title' => 'mine', 'password' => 'secret']);
        $s = $this->store();

        $this->assertVaultError('not_found', fn () => $s->readEntry($this->bob, $id, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $s->readField($this->bob, $id, 'password', $this->bobSk));
        // Bob holding Alice's sk is still not Alice.
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->bob, $id, $this->aliceSk));
        // Alice's id with the wrong sk.
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, $id, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, $id, 'short'));
        // A key row for Bob (as a stale grant might leave) does not grant access on its own.
        $this->pdo()->prepare("INSERT INTO vault_keys (object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek) VALUES ('entry', ?, ?, 1, 1, ?)")
            ->execute([$id, $this->bob, base64_encode(Sealer::sealDek($this->dekOf('entry', $id), 'entry', $id, 1, $this->bob, sodium_crypto_box_publickey_from_secretkey($this->bobSk)))]);
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->bob, $id, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $s->listEntries($this->bob, $g, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $s->readGroup($this->bob, $g, $this->bobSk));
        $this->assertVaultError('not_found', fn () => $s->updateEntry($this->bob, $id, 1, ['title' => 'pwned'], $this->bobSk));
        $this->assertVaultError('not_found', fn () => $s->deleteObject($this->bob, 'entry', $id));
        $this->assertVaultError('not_found', fn () => $s->createEntry($this->bob, $g, ['title' => 'in your group']));
        $this->assertVaultError('not_found', fn () => $s->createGroup($this->bob, $g, ['name' => 'child']));
        // An entry that never existed looks the same.
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, 99999, $this->aliceSk));
        $this->assertSame('mine', $s->readEntry($this->alice, $id, $this->aliceSk)['payload']['title']);
    }

    public function testUnenrolledActorCannotCreate(): void
    {
        $carol = (int) $this->container['userModel']->create(['username' => 'carol', 'password' => 'carol login password']);
        $this->assertVaultError('not_enrolled', fn () => $this->store()->createGroup($carol, null, ['name' => 'x']));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_groups'));
    }

    // Kills: no version check, a check that compares against the wrong column, and a version that doesn't advance.
    public function testStaleVersionConflicts(): void
    {
        $id = $this->store()->createEntry($this->alice, $this->aliceGroup(), ['title' => 'v1']);
        $s = $this->store();
        $this->assertSame(2, $s->updateEntry($this->alice, $id, 1, ['title' => 'v2'], $this->aliceSk));
        $this->assertVaultError('conflict', fn () => $s->updateEntry($this->alice, $id, 1, ['title' => 'stale'], $this->aliceSk));
        $this->assertVaultError('conflict', fn () => $s->updateEntry($this->alice, $id, 3, ['title' => 'future'], $this->aliceSk));
        $e = $s->readEntry($this->alice, $id, $this->aliceSk);
        $this->assertSame('v2', $e['payload']['title']);
        $this->assertSame(2, $e['version']);
        $this->assertSame(3, $s->updateEntry($this->alice, $id, 2, ['title' => 'v3'], $this->aliceSk));
        $this->assertSame('v3', $s->readEntry($this->alice, $id, $this->aliceSk)['payload']['title']);
        // An update with the wrong sk is refused before anything is written.
        $this->assertVaultError('not_found', fn () => $s->updateEntry($this->alice, $id, 3, ['title' => 'x'], $this->bobSk));
        $this->assertSame(3, (int) $this->row('SELECT version FROM vault_entries WHERE id = ?', [$id])['version']);
    }

    // Kills: a limit of characters instead of bytes, an off-by-one (> vs >=), and a limit on the input rather
    // than on the JSON that gets encrypted.
    public function testPayloadTooLarge(): void
    {
        $g = $this->aliceGroup();
        $base = strlen(EntryPayload::encode(EntryPayload::validate(['title' => 't', 'notes' => ''])));
        $fits = ['title' => 't', 'notes' => str_repeat('a', EntryPayload::MAX_BYTES - $base)];
        $over = ['title' => 't', 'notes' => str_repeat('a', EntryPayload::MAX_BYTES - $base + 1)];
        $this->assertSame(EntryPayload::MAX_BYTES, strlen(EntryPayload::encode(EntryPayload::validate($fits))));
        $this->assertSame(262144, EntryPayload::MAX_BYTES);

        $id = $this->store()->createEntry($this->alice, $g, $fits);
        $this->assertVaultError('payload_too_large', fn () => $this->store()->createEntry($this->alice, $g, $over));
        $this->assertVaultError('payload_too_large', fn () => $this->store()->updateEntry($this->alice, $id, 1, $over, $this->aliceSk));
        // 'é' is two bytes: under the limit in characters, over it in bytes.
        $this->assertVaultError('payload_too_large', fn () => EntryPayload::validate(['notes' => str_repeat('é', 140000)]));
        // Escaping counts: a quote encodes as two bytes.
        $this->assertVaultError('payload_too_large', fn () => EntryPayload::validate(['notes' => str_repeat('"', 140000)]));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
        $this->assertSame(1, (int) $this->row('SELECT version FROM vault_entries WHERE id = ?', [$id])['version']);
    }

    public static function invalidPayloads(): array
    {
        return [
            'unknown key' => [['title' => 'x', 'colour' => 'red']],
            'non-string title' => [['title' => 5]],
            'array password' => [['password' => ['a']]],
            'invalid utf-8' => [['notes' => "bad \xC3\x28"]],
            'tags not a list' => [['tags' => ['a' => 'b']]],
            'non-string tag' => [['tags' => [1]]],
            'expires_at string' => [['expires_at' => '2030-01-01']],
            'negative expires_at' => [['expires_at' => -1]],
            'fields not a list' => [['fields' => ['x' => ['name' => 'a', 'value' => 'b', 'protected' => false]]]],
            'field extra key' => [['fields' => [['name' => 'a', 'value' => 'b', 'protected' => false, 'html' => '<b>']]]],
            'field missing key' => [['fields' => [['name' => 'a', 'value' => 'b']]]],
            'field protected not bool' => [['fields' => [['name' => 'a', 'value' => 'b', 'protected' => 1]]]],
            'field empty name' => [['fields' => [['name' => '', 'value' => 'b', 'protected' => false]]]],
            'field duplicate name' => [['fields' => [['name' => 'a', 'value' => 'b', 'protected' => false], ['name' => 'a', 'value' => 'c', 'protected' => true]]]],
            'field value not string' => [['fields' => [['name' => 'a', 'value' => 1, 'protected' => false]]]],
        ];
    }

    /** @dataProvider invalidPayloads */
    public function testPayloadInvalid(array $payload): void
    {
        $this->assertVaultError('payload_invalid', fn () => EntryPayload::validate($payload));
        $this->assertVaultError('payload_invalid', fn () => $this->store()->createEntry($this->alice, $this->aliceGroup(), $payload));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
    }

    public function testGroupPayloadIsValidated(): void
    {
        $this->assertVaultError('payload_invalid', fn () => $this->store()->createGroup($this->alice, null, ['name' => '']));
        $this->assertVaultError('payload_invalid', fn () => $this->store()->createGroup($this->alice, null, ['name' => 'x', 'owner' => 1]));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_groups'));
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'Ops 🔧', 'notes' => "a\tb"]);
        $this->assertSame(['name' => 'Ops 🔧', 'icon' => '', 'notes' => "a\tb"], $this->store()->readGroup($this->alice, $g, $this->aliceSk)['payload']);
    }

    // Opens an object's DEK with Alice's keypair (the test plays the owner).
    private function dekOf(string $type, int $id): string
    {
        $k = $this->row('SELECT sealed_dek, key_epoch FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ?', [$type, $id, $this->alice]);
        return Sealer::openDek(base64_decode($k['sealed_dek']), $this->keypair($this->aliceSk), $type, $id, (int) $k['key_epoch'], $this->alice);
    }

    private function setDek(string $type, int $id, int $principal, string $sk, int $epoch, string $dek): void
    {
        $this->pdo()->prepare('UPDATE vault_keys SET sealed_dek = ?, key_epoch = ? WHERE object_type = ? AND object_id = ? AND principal_id = ?')
            ->execute([base64_encode(Sealer::sealDek($dek, $type, $id, $epoch, $principal, sodium_crypto_box_publickey_from_secretkey($sk))), $epoch, $type, $id, $principal]);
    }

    // Entry 2's key row is re-sealed to hold entry 1's DEK, so only the AD stands between a copied ciphertext
    // and a successful read. Kills: dropping entry_id, owner_id or key_epoch from the AD (each case alone).
    public function testAdBinding(): void
    {
        $g = $this->aliceGroup();
        $s = $this->store();
        $e1 = $s->createEntry($this->alice, $g, ['title' => 'one']);
        $e2 = $s->createEntry($this->alice, $g, ['title' => 'two']);
        $dek1 = $this->dekOf('entry', $e1);
        $src = $this->row('SELECT nonce, ciphertext FROM vault_entries WHERE id = ?', [$e1]);

        // Control: with the same DEK and an honest AD, the copied ciphertext would decrypt.
        $this->setDek('entry', $e2, $this->alice, $this->aliceSk, 1, $dek1);
        $this->pdo()->prepare('UPDATE vault_entries SET nonce = ?, ciphertext = ? WHERE id = ?')->execute([$src['nonce'], $src['ciphertext'], $e2]);
        $this->assertSame('one', json_decode(Aead::open(base64_decode($src['nonce']), base64_decode($src['ciphertext']), $dek1, Encoding::enc('entry', 1, $e1, $this->alice, 1)), true)['title']);
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, $e2, $this->aliceSk));
        $this->assertVaultError('not_found', fn () => $s->listEntries($this->alice, $g, $this->aliceSk));

        // key_epoch: entry 1 moved to epoch 2 with the same DEK sealed for epoch 2.
        $this->pdo()->prepare('DELETE FROM vault_entries WHERE id = ?')->execute([$e2]);
        $this->pdo()->prepare('UPDATE vault_entries SET key_epoch = 2 WHERE id = ?')->execute([$e1]);
        $this->setDek('entry', $e1, $this->alice, $this->aliceSk, 2, $dek1);
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, $e1, $this->aliceSk));

        // owner_id: entry 1 handed to Bob, with Bob given the same DEK.
        $this->pdo()->prepare('UPDATE vault_entries SET key_epoch = 1, owner_id = ? WHERE id = ?')->execute([$this->bob, $e1]);
        $this->pdo()->prepare("INSERT INTO vault_keys (object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek) VALUES ('entry', ?, ?, 1, 1, '')")->execute([$e1, $this->bob]);
        $this->setDek('entry', $e1, $this->bob, $this->bobSk, 1, $dek1);
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->bob, $e1, $this->bobSk));
    }

    // The group payload is bound the same way. Kills: an AD that names "entry" (or omits the type) for groups.
    public function testGroupAdBinding(): void
    {
        $s = $this->store();
        $g1 = $s->createGroup($this->alice, null, ['name' => 'one']);
        $g2 = $s->createGroup($this->alice, null, ['name' => 'two']);
        $e = $s->createEntry($this->alice, $g1, ['title' => 'entry']);
        $dek = $this->dekOf('group', $g1);
        $this->setDek('group', $g2, $this->alice, $this->aliceSk, 1, $dek);
        $src = $this->row('SELECT nonce, ciphertext FROM vault_groups WHERE id = ?', [$g1]);
        $this->pdo()->prepare('UPDATE vault_groups SET nonce = ?, ciphertext = ? WHERE id = ?')->execute([$src['nonce'], $src['ciphertext'], $g2]);
        $this->assertVaultError('not_found', fn () => $s->readGroup($this->alice, $g2, $this->aliceSk));
        $this->assertSame('one', $s->readGroup($this->alice, $g1, $this->aliceSk)['payload']['name']);

        // A group ciphertext dropped into an entry row, with the entry keyed to the group's DEK.
        $this->setDek('entry', $e, $this->alice, $this->aliceSk, 1, $dek);
        $this->pdo()->prepare('UPDATE vault_entries SET nonce = ?, ciphertext = ? WHERE id = ?')->execute([$src['nonce'], $src['ciphertext'], $e]);
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, $e, $this->aliceSk));
    }

    // Kills: skipping the key_epoch equality check on the key row, and reading a key row of an older key_gen.
    public function testKeyRowMustMatchEpochAndKeyGen(): void
    {
        $s = $this->store();
        $id = $s->createEntry($this->alice, $this->aliceGroup(), ['title' => 'x']);
        $this->assertSame(1, (int) $this->row('SELECT principal_key_gen FROM vault_keys WHERE object_id = ?', [$id])['principal_key_gen']);
        $this->pdo()->prepare('UPDATE vault_keys SET key_epoch = 2 WHERE object_id = ?')->execute([$id]);
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, $id, $this->aliceSk));
        $this->pdo()->prepare('UPDATE vault_keys SET key_epoch = 1 WHERE object_id = ?')->execute([$id]);
        $this->assertSame('x', $s->readEntry($this->alice, $id, $this->aliceSk)['payload']['title']);
        // The principal moved on to key_gen 2: the gen-1 row is not the current key.
        $this->pdo()->prepare('UPDATE vault_principals SET key_gen = 2 WHERE user_id = ?')->execute([$this->alice]);
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, $id, $this->aliceSk));
        // New objects are sealed under the principal's current key_gen.
        $g2 = $s->createGroup($this->alice, null, ['name' => 'n']);
        $this->assertSame(2, (int) $this->row("SELECT principal_key_gen FROM vault_keys WHERE object_type = 'group' AND object_id = ?", [$g2])['principal_key_gen']);
    }

    // Kills: listing returning the payload, or any secret value, and a list that ignores the group.
    public function testListIsMetadataOnly(): void
    {
        $s = $this->store();
        $g = $this->aliceGroup();
        $other = $this->aliceGroup(null, 'Other');
        $id = $s->createEntry($this->alice, $g, [
            'title' => 'GitHub', 'username' => 'octo', 'password' => 'PassSentinel', 'url' => 'https://github.com',
            'notes' => 'NotesSentinel', 'otp' => 'OtpSentinel', 'expires_at' => 1_900_000_000,
            'fields' => [['name' => 'Recovery', 'value' => 'FieldValueSentinel', 'protected' => true]],
        ]);
        $s->createEntry($this->alice, $other, ['title' => 'elsewhere']);

        $list = $s->listEntries($this->alice, $g, $this->aliceSk);
        $this->assertCount(1, $list);
        $this->assertSame([
            'id' => $id, 'group_id' => $g, 'title' => 'GitHub', 'username' => 'octo', 'url' => 'https://github.com',
            'field_names' => ['Recovery'], 'expires_at' => 1_900_000_000, 'version' => 1, 'updated_at' => $this->now,
        ], $list[0]);
        $this->assertArrayNotHasKey('password', $list[0]);
        $flat = json_encode($list, JSON_UNESCAPED_UNICODE);
        foreach (['PassSentinel', 'NotesSentinel', 'OtpSentinel', 'FieldValueSentinel'] as $secret) {
            $this->assertStringNotContainsString($secret, $flat);
        }
    }

    // Kills: no default limit, a default other than 200, a caller-chosen limit above 200, and a broken offset.
    public function testListPaginates200(): void
    {
        $s = $this->store();
        $g = $this->aliceGroup();
        $ids = [];
        for ($i = 0; $i < 201; $i++) {
            $ids[] = $s->createEntry($this->alice, $g, ['title' => 't'.$i]);
        }
        $page1 = $s->listEntries($this->alice, $g, $this->aliceSk);
        $this->assertCount(200, $page1);
        $this->assertSame(array_slice($ids, 0, 200), array_column($page1, 'id'));
        $page2 = $s->listEntries($this->alice, $g, $this->aliceSk, 200);
        $this->assertSame([$ids[200]], array_column($page2, 'id'));
        $this->assertSame('t200', $page2[0]['title']);
        $this->assertCount(200, $s->listEntries($this->alice, $g, $this->aliceSk, 0, 1000));
        $this->assertSame(array_slice($ids, 5, 3), array_column($s->listEntries($this->alice, $g, $this->aliceSk, 5, 3), 'id'));
        $this->assertSame([], $s->listEntries($this->alice, $g, $this->aliceSk, 500));
    }

    // R6/R8: deleting an object removes its key, grant and re-key queue rows in model code, for a group's whole
    // subtree, and leaves other objects' rows alone. Kills: deleting only the object row, deleting only the
    // top group's rows, and a type-blind cleanup.
    public function testDeleteCleansUpPolymorphicRows(): void
    {
        $s = $this->store();
        $root = $this->aliceGroup(null, 'root');
        $child = $this->aliceGroup($root, 'child');
        $grandchild = $this->aliceGroup($child, 'grandchild');
        $eRoot = $s->createEntry($this->alice, $root, ['title' => 'r']);
        $eDeep = $s->createEntry($this->alice, $grandchild, ['title' => 'd']);
        $keep = $this->aliceGroup(null, 'keep');
        $eKeep = $s->createEntry($this->alice, $keep, ['title' => 'k']);
        // Fresh sequences make the kept entry's id equal a deleted group's id: its rows must survive (per-type cleanup).
        $this->assertSame($grandchild, $eKeep);
        foreach ([['group', $root], ['group', $child], ['group', $grandchild], ['entry', $eRoot], ['entry', $eDeep], ['group', $keep], ['entry', $eKeep]] as [$type, $id]) {
            $this->pdo()->prepare('INSERT INTO vault_grants (subject_type, subject_id, grantee_id, permission, granted_by, created_at) VALUES (?, ?, ?, ?, ?, ?)')
                ->execute([$type, $id, $this->bob, 'read', $this->alice, $this->now]);
            $this->pdo()->prepare('INSERT INTO vault_rekey_queue (object_type, object_id, expected_key_epoch, created_at) VALUES (?, ?, 1, ?)')
                ->execute([$type, $id, $this->now]);
        }

        $this->assertVaultError('not_found', fn () => $s->deleteObject($this->alice, 'group', 99999));
        $s->deleteObject($this->alice, 'group', $root);

        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_groups WHERE id IN (?, ?, ?)', [$root, $child, $grandchild]));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_entries WHERE id IN (?, ?)', [$eRoot, $eDeep]));
        foreach (['vault_keys' => 'object', 'vault_grants' => 'subject', 'vault_rekey_queue' => 'object'] as $table => $col) {
            $left = $this->pdo()->query("SELECT {$col}_type, {$col}_id FROM $table ORDER BY {$col}_type, {$col}_id")->fetchAll(\PDO::FETCH_NUM);
            $this->assertSame([['entry', $eKeep], ['group', $keep]], array_map(fn ($r) => [$r[0], (int) $r[1]], $left), $table);
        }
        $this->assertSame('k', $s->readEntry($this->alice, $eKeep, $this->aliceSk)['payload']['title']);

        $s->deleteObject($this->alice, 'entry', $eKeep);
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE object_type = 'entry'"));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_grants WHERE subject_type = 'entry' AND subject_id = ?", [$eKeep]));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_rekey_queue WHERE object_type = 'entry' AND object_id = ?", [$eKeep]));
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, $eKeep, $this->aliceSk));
        $this->expectException(\InvalidArgumentException::class);
        $s->deleteObject($this->alice, 'share', $keep);
    }

    // R8: a key row left behind for an object that no longer exists (a DB cascade bypassed the model) is ignored.
    public function testOrphanKeyRowIsIgnored(): void
    {
        $s = $this->store();
        $g = $this->aliceGroup();
        $id = $s->createEntry($this->alice, $g, ['title' => 'x']);
        $this->pdo()->prepare('DELETE FROM vault_entries WHERE id = ?')->execute([$id]);
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE object_type = 'entry' AND object_id = ?", [$id]));
        $this->assertVaultError('not_found', fn () => $s->readEntry($this->alice, $id, $this->aliceSk));
        $this->assertSame([], $s->listEntries($this->alice, $g, $this->aliceSk));
        // AUTOINCREMENT: the next entry never takes the orphan's id.
        $this->assertGreaterThan($id, $s->createEntry($this->alice, $g, ['title' => 'y']));
    }

    // Kills: a write outside the exclusive lock (insert, encrypt-and-update and the key row would commit
    // separately) and partial rows left by a failed create. The key row insert is made to collide.
    public function testCreateIsAtomic(): void
    {
        $s = $this->store();
        $g = $this->aliceGroup();
        $first = $s->createEntry($this->alice, $g, ['title' => 'first']);
        $this->pdo()->prepare("INSERT INTO vault_keys (object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek) VALUES ('entry', ?, ?, 1, 1, 'planted')")
            ->execute([$first + 1, $this->alice]);
        try {
            $s->createEntry($this->alice, $g, ['title' => 'second']);
            $this->fail('the colliding key row should abort the create');
        } catch (\PDOException) {
        }
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
        $this->assertSame('planted', $this->row("SELECT sealed_dek FROM vault_keys WHERE object_type = 'entry' AND object_id = ?", [$first + 1])['sealed_dek']);
        $this->assertFalse($this->pdo()->inTransaction());
    }

    public function testSecretParametersAreSensitive(): void
    {
        $expected = [
            [ObjectStore::class, 'createGroup', 'payload'],
            [ObjectStore::class, 'createEntry', 'payload'],
            [ObjectStore::class, 'readEntry', 'sk'],
            [ObjectStore::class, 'readGroup', 'sk'],
            [ObjectStore::class, 'readField', 'sk'],
            [ObjectStore::class, 'updateEntry', 'payload'],
            [ObjectStore::class, 'updateEntry', 'sk'],
            [ObjectStore::class, 'listEntries', 'sk'],
            [EntryPayload::class, 'validate', 'p'],
            [EntryPayload::class, 'validateGroup', 'p'],
            [EntryPayload::class, 'encode', 'p'],
            [\Kanboard\Plugin\Vault\Model\VaultSession::class, 'setCookie', 'value'],
            [\Kanboard\Plugin\Vault\Model\CookieJar::class, 'set', 'value'],
        ];
        foreach ($expected as [$class, $method, $param]) {
            $found = null;
            foreach ((new \ReflectionMethod($class, $method))->getParameters() as $p) {
                if ($p->getName() === $param) {
                    $found = $p;
                }
            }
            $this->assertNotNull($found, "$class::$method has \$$param");
            $this->assertCount(1, $found->getAttributes(\SensitiveParameter::class), "$class::$method \$$param is #[\\SensitiveParameter]");
        }
    }

    // The sk and payload never appear in a trace, however deep the failure.
    public function testSecretsAbsentFromTraces(): void
    {
        $old = ini_get('zend.exception_ignore_args');
        ini_set('zend.exception_ignore_args', '0');
        try {
            $sk = str_pad('SK-SENTINEL-objectstore', 32, 'x');
            $e = null;
            try {
                $this->store()->readEntry($this->alice, $this->store()->createEntry($this->alice, $this->aliceGroup(), ['title' => 'x']), $sk);
            } catch (\Throwable $e) {
            }
            $this->assertNotNull($e);
            $this->assertNoArg('SK-SENTINEL', $e);

            $e = null;
            try {
                $this->store()->createEntry($this->alice, $this->aliceGroup(), ['password' => 'PW-SENTINEL', 'bogus' => 1]);
            } catch (\Throwable $e) {
            }
            $this->assertNotNull($e);
            $this->assertSame('payload_invalid', $e->getMessage());
            $this->assertNoArg('PW-SENTINEL', $e);
        } finally {
            ini_set('zend.exception_ignore_args', (string) $old);
        }
    }

    private function assertNoArg(string $needle, \Throwable $e): void
    {
        $walk = function ($v) use (&$walk, $needle): bool {
            if (is_string($v)) {
                return str_contains($v, $needle);
            }
            if (is_array($v)) {
                foreach ($v as $k => $x) {
                    if ($walk($k) || $walk($x)) {
                        return true;
                    }
                }
            }
            return false;
        };
        $vaultFrames = 0;
        for ($t = $e; $t !== null; $t = $t->getPrevious()) {
            foreach ($t->getTrace() as $frame) {
                if (! str_starts_with($frame['class'] ?? '', 'Kanboard\\Plugin\\Vault\\')) {
                    continue;
                }
                $vaultFrames++;
                $this->assertFalse($walk($frame['args'] ?? []), 'secret in the args of '.($frame['class'] ?? '').'::'.($frame['function'] ?? '?'));
            }
        }
        $this->assertGreaterThan(0, $vaultFrames);
    }
}
