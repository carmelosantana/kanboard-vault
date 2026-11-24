<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Model\DekContext;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\ServerGrant;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;
use PHPUnit\Framework\Attributes\DataProvider;

// Spec amendment: Server grants (validation part). Consumers and fields are canonical lists: unique, sorted, 1..16
// consumers and 1..32 fields. R1: a field is a top-level name (stored plain) or a custom name stored only as
// c: + base32(BLAKE2b-128(field_mac_key, name)); a plain custom name is payload_invalid.
//
// Task 7, Server grants (GrantModel::grantServer): entry only, read, no expiry, owner only and unlocked, Server on.
// Custom field names arrive plain from the owner and are stored only as their MAC (R1); a requested field the entry
// doesn't have is payload_invalid. Every grant, revoke and refusal is audited, a refusal in its own transaction after
// the rollback.
class ServerGrantTest extends Base
{
    use ServerFixture;

    private bool $booted = false;
    private int $g;
    private int $e;

    protected function tearDown(): void
    {
        if ($this->booted) {
            $this->tearDownServer();
            $this->tearDownVault();
        }
        parent::tearDown();
    }

    // Alice, carol and an enrolled bob; Server on; alice's group and entry (the fixture entry has the custom field
    // 'api key').
    private function boot(): void
    {
        $this->setUpAgents();
        $this->principals()->enrolHuman($this->bob, Fixtures::NEW_PASSPHRASE);
        $this->setUpServer();
        $this->enableServer();
        $this->booted = true;
        $this->g = $this->store()->createGroup($this->alice, null, ['name' => 'servers']);
        $this->e = $this->store()->createEntry($this->alice, $this->g, Fixtures::entry('server shared'));
        $this->pdo()->exec('DELETE FROM vault_audit');
    }

    private function epoch(): int
    {
        return (int) $this->row('SELECT key_epoch FROM vault_entries WHERE id = ?', [$this->e])['key_epoch'];
    }

    private function grantRow(): ?array
    {
        return $this->row('SELECT * FROM vault_grants WHERE subject_type = ? AND subject_id = ? AND grantee_id = -1', ['entry', $this->e]);
    }

    private function serverKeyRow(): ?array
    {
        return $this->row("SELECT key_epoch, sealed_dek FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND principal_id = -1", [$this->e]);
    }

    private function serverDek(): string
    {
        $key = $this->serverKeyRow();
        $this->assertNotNull($key, 'a Server key row');
        return $this->freshProvider()->openSealedDek(base64_decode($key['sealed_dek']), new DekContext('entry', $this->e, (int) $key['key_epoch'], ServerPrincipal::ID));
    }

    private function grantServer(array $consumers = ['CveHunter'], array $fields = ['password'], ?int $rate = null, ?int $burst = null): void
    {
        $this->grants()->grantServer($this->alice, $this->e, $consumers, $fields, $rate, $burst, $this->aliceSk());
    }

    private function mac(string $name): string
    {
        $key = $this->freshProvider()->openFieldMacKey();
        return ServerGrant::macField($key, $name);
    }

    // Mutation: no sealTo (no -1 key row, or one that doesn't open to the entry's DEK).
    public function testGrantServerSealsAndRecords(): void
    {
        $this->boot();
        $this->grantServer();
        $g = $this->grantRow();
        $this->assertNotNull($g);
        $this->assertSame(['["CveHunter"]', '["password"]', 60, 10, 'read', null, $this->alice],
            [$g['consumers'], $g['fields'], (int) $g['rate_per_hour'], (int) $g['rate_burst'], $g['permission'], $g['expires_at'], (int) $g['granted_by']]);

        $key = $this->serverKeyRow();
        $this->assertNotNull($key, 'the -1 key row');
        $epoch = $this->epoch();
        $this->assertSame($epoch, (int) $key['key_epoch']);
        $dek = $this->serverDek();
        $row = $this->row('SELECT nonce, ciphertext FROM vault_entries WHERE id = ?', [$this->e]);
        $json = Aead::open(base64_decode($row['nonce']), base64_decode($row['ciphertext']), $dek, ObjectStore::ad('entry', $this->e, $this->alice, $epoch));
        $this->assertSame('server shared', json_decode($json, true)['title']);

        $rows = $this->auditRows('server_grant');
        $this->assertCount(1, $rows);
        $this->assertSame([(string) $this->alice, 'entry', (string) $this->e, '["CveHunter"]', '["password"]'],
            [(string) $rows[0]['actor_user_id'], $rows[0]['object_type'], (string) $rows[0]['object_id'], $rows[0]['consumers'], $rows[0]['fields']]);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', (string) $rows[0]['correlation_id']);
        $this->assertSame(['server_grant'], $this->auditActions());
    }

    // R1: a custom field arrives plain and is stored, and audited, only as its MAC; the sharing view maps it back for
    // the unlocked owner. Kills: the plain custom name stored; an unkeyed or second MAC helper; a field the entry
    // doesn't have accepted.
    public function testCustomFieldsAreStoredAsTheirMac(): void
    {
        $this->boot();
        $this->grantServer(['CveHunter'], ['password', 'api key', 'password']);
        $mac = $this->mac('api key');
        $want = ServerGrant::encodeList([$mac, 'password']);
        $this->assertSame($want, $this->grantRow()['fields']);
        $this->assertSame($want, $this->auditRows('server_grant')[0]['fields']);
        $this->assertStringNotContainsString('api key', json_encode($this->auditRows()));
        $this->assertStringNotContainsString('api key', json_encode($this->grantRow()));

        $sharing = $this->grants()->sharing($this->alice, 'entry', $this->e, $this->aliceSk());
        $this->assertSame(['api key', 'password'], $sharing['grants'][0]['fields']);
        $this->assertSame([$mac, 'password'], $this->grants()->sharing($this->alice, 'entry', $this->e)['grants'][0]['fields'], 'without the sk: the stored form');

        $this->assertVaultError('payload_invalid', fn () => $this->grantServer(['CveHunter'], ['password', 'no such field']));
        $this->assertSame($want, $this->grantRow()['fields'], 'the refused re-grant changed nothing');
        $this->assertSame('payload_invalid', $this->auditRows('server_grant_denied')[0]['reason']);
    }

    public static function refusals(): array
    {
        return [
            'no consumers' => ['payload_invalid', 'no_consumers'],
            'a bad consumer name' => ['payload_invalid', 'bad_consumer'],
            'no fields' => ['payload_invalid', 'no_fields'],
            'a grantee, not the owner' => ['not_found', 'bob'],
            "someone else's sk" => ['not_found', 'carol_sk'],
            'Server off' => ['server_off', 'server_off'],
            'a group id' => ['not_found', 'group'],
            // Requirement 18: a reason outside the old allowlist was dropped unrecorded.
            "the owner's key row can't be opened" => ['integrity_error', 'integrity'],
        ];
    }

    /**
     * Mutation: the denied row written inside the rolled-back transaction (it vanishes).
     *
     * @dataProvider refusals
     */
    #[DataProvider('refusals')]
    public function testRefusalsAreAuditedAndWriteNothing(string $reason, string $case): void
    {
        $this->boot();
        $sk = $this->aliceSk();
        $actor = $this->alice;
        $id = $this->e;
        $consumers = ['CveHunter'];
        $fields = ['password'];
        switch ($case) {
            case 'no_consumers': $consumers = [];
                break;
            case 'bad_consumer': $consumers = ['bad name'];
                break;
            case 'no_fields': $fields = [];
                break;
            case 'bob':
                $this->grants()->grant($this->alice, 'entry', $this->e, $this->bob, 'read', null, $sk);
                $actor = $this->bob;
                $sk = $this->skFor($this->bob, Fixtures::NEW_PASSPHRASE);
                break;
            case 'carol_sk': $sk = $this->carolSk();
                break;
            case 'server_off': $this->server()->disable(self::ADMIN);
                break;
            case 'integrity':
                $this->pdo()->prepare("UPDATE vault_keys SET sealed_dek = ? WHERE object_type = 'entry' AND object_id = ? AND principal_id = ?")
                    ->execute([base64_encode(random_bytes(80)), $this->e, $this->alice]);
                break;
            case 'group':
                do {
                    $id = $this->store()->createGroup($this->alice, null, ['name' => 'not an entry']);
                } while ($this->countRows('SELECT COUNT(*) FROM vault_entries WHERE id = ?', [$id]) > 0);
                break;
        }
        $this->pdo()->exec('DELETE FROM vault_audit');
        $this->assertVaultError($reason, fn () => $this->grants()->grantServer($actor, $id, $consumers, $fields, null, null, $sk));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = -1'));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE principal_id = -1'));
        $rows = $this->auditRows('server_grant_denied');
        $this->assertCount(1, $rows);
        $this->assertSame([$reason, (string) $actor, 'entry', (string) $id], [$rows[0]['reason'], (string) $rows[0]['actor_user_id'], $rows[0]['object_type'], (string) $rows[0]['object_id']]);
        $this->assertSame(['server_grant_denied'], $this->auditActions());
    }

    // Mutation: the requested rate stored as is (no clamp to the admin maximum).
    public function testRatesNeverExceedTheAdminMaximum(): void
    {
        $this->boot();
        $settings = new VaultSettings($this->container, null, $this->clock());
        $settings->set('vault_server_rate_max', 30, self::ADMIN);
        $settings->set('vault_server_burst_max', 5, self::ADMIN);
        $this->grantServer(['CveHunter'], ['password'], 60, 10);
        $this->assertSame([30, 5], [(int) $this->grantRow()['rate_per_hour'], (int) $this->grantRow()['rate_burst']]);
        $this->grantServer(['CveHunter'], ['password'], 20, 2);
        $this->assertSame([20, 2], [(int) $this->grantRow()['rate_per_hour'], (int) $this->grantRow()['rate_burst']]);
        $this->grantServer();
        $this->assertSame([30, 5], [(int) $this->grantRow()['rate_per_hour'], (int) $this->grantRow()['rate_burst']], 'the default, clamped');
    }

    // Kills: min/max swapped; a zero or negative rate accepted.
    public function testRate(): void
    {
        $this->assertSame(60, ServerGrant::rate(null, 60, 100));
        $this->assertSame(30, ServerGrant::rate(null, 60, 30));
        $this->assertSame(20, ServerGrant::rate(20, 60, 30));
        $this->assertSame(30, ServerGrant::rate(31, 60, 30));
        $this->assertSame(1, ServerGrant::rate(1, 60, 30));
        $this->assertInvalid(fn () => ServerGrant::rate(0, 60, 30), 'a zero rate');
        $this->assertInvalid(fn () => ServerGrant::rate(-5, 60, 30), 'a negative rate');
    }

    // Mutation: a second row inserted instead of the update.
    public function testRegrantUpdatesTheRow(): void
    {
        $this->boot();
        $this->grantServer();
        $this->grantServer(['Lifeboat', 'CveHunter']);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = -1'));
        $this->assertSame('["CveHunter","Lifeboat"]', $this->grantRow()['consumers']);
        $this->assertSame(['["CveHunter"]', '["CveHunter","Lifeboat"]'], array_column($this->auditRows('server_grant'), 'consumers'));
    }

    // Security requirement 6 (without versions). Mutation: removeSource still auditing revoke for -1; the srvread
    // buckets left behind.
    public function testRevokeRekeysDropsServerAndAuditsServerRevoke(): void
    {
        $this->boot();
        $this->grantServer();
        $oldDek = $this->serverDek();
        $before = $this->epoch();
        foreach (["srvread:CveHunter:{$this->e}", "srvread:CveHunter:1{$this->e}", 'srvread:CveHunter:'.($this->e + 100), 'unlock:ip:keep'] as $bucket) {
            $this->pdo()->prepare('INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES (?, 3, ?)')->execute([$bucket, $this->now]);
        }

        $this->grants()->revoke($this->alice, 'entry', $this->e, ServerPrincipal::ID, $this->aliceSk());

        $this->assertNull($this->serverKeyRow());
        $this->assertNull($this->grantRow());
        $this->assertSame($before + 1, $this->epoch());
        $rows = $this->auditRows('server_revoke');
        $this->assertCount(1, $rows);
        $this->assertSame([(string) $this->alice, 'entry', (string) $this->e, '["CveHunter"]', '["password"]'],
            [(string) $rows[0]['actor_user_id'], $rows[0]['object_type'], (string) $rows[0]['object_id'], $rows[0]['consumers'], $rows[0]['fields']]);
        $this->assertSame([], $this->auditRows('revoke'));

        $row = $this->row('SELECT nonce, ciphertext FROM vault_entries WHERE id = ?', [$this->e]);
        try {
            Aead::open(base64_decode($row['nonce']), base64_decode($row['ciphertext']), $oldDek, ObjectStore::ad('entry', $this->e, $this->alice, $this->epoch()));
            $this->fail('the old Server DEK opened the re-keyed entry');
        } catch (\Throwable $t) {
            $this->assertNotInstanceOf(\PHPUnit\Framework\AssertionFailedError::class, $t);
        }
        $buckets = array_column($this->pdo()->query('SELECT bucket FROM vault_rate ORDER BY bucket')->fetchAll(\PDO::FETCH_ASSOC), 'bucket');
        sort($buckets);
        $keep = ["srvread:CveHunter:1{$this->e}", 'srvread:CveHunter:'.($this->e + 100), 'unlock:ip:keep'];
        sort($keep);
        $this->assertSame($keep, $buckets, "only this entry's srvread buckets go");
    }

    // A refused revoke of the Server grant is audited server_revoke_denied, after the rollback; the grant stays.
    // Mutation: the denied row written inside the rolled-back transaction.
    public function testRefusedServerRevokeIsAudited(): void
    {
        $this->boot();
        $this->grantServer();
        $this->pdo()->exec('DELETE FROM vault_audit');
        $this->assertVaultError('not_found', fn () => $this->grants()->revoke($this->alice, 'entry', $this->e, ServerPrincipal::ID, $this->carolSk()));
        $this->assertNotNull($this->grantRow());
        $this->assertNotNull($this->serverKeyRow());
        $rows = $this->auditRows('server_revoke_denied');
        $this->assertCount(1, $rows);
        $this->assertSame(['not_found', (string) $this->alice, 'entry', (string) $this->e], [$rows[0]['reason'], (string) $rows[0]['actor_user_id'], $rows[0]['object_type'], (string) $rows[0]['object_id']]);
        $this->assertSame(['server_revoke_denied'], $this->auditActions());

        // A refused revoke of anyone else is not a Server row.
        $this->pdo()->exec('DELETE FROM vault_audit');
        $this->assertVaultError('not_found', fn () => $this->grants()->revoke($this->alice, 'entry', $this->e, $this->bob, $this->aliceSk()));
        $this->assertSame([], $this->auditActions());
    }

    public function testDisableAuditsOneServerRevokePerGrant(): void
    {
        $this->boot();
        $this->grantServer();
        $first = $this->e;
        $this->e = $this->store()->createEntry($this->alice, $this->g, Fixtures::entry('second'));
        $this->grantServer(['Lifeboat'], ['username']);
        $this->pdo()->exec('DELETE FROM vault_audit');

        $this->server()->disable(self::ADMIN);

        $rows = $this->auditRows('server_revoke');
        $this->assertSame([[(string) self::ADMIN, (string) $first, '["CveHunter"]', '["password"]'], [(string) self::ADMIN, (string) $this->e, '["Lifeboat"]', '["username"]']],
            array_map(static fn (array $r): array => [(string) $r['actor_user_id'], (string) $r['object_id'], $r['consumers'], $r['fields']], $rows));
        $this->assertSame([], $this->auditRows('revoke'));
    }

    // Mutation: the Server row listed as a human grant (no consumers, fields or rates).
    public function testSharingListsTheServerGrant(): void
    {
        $this->boot();
        $sk = $this->aliceSk();
        $this->grants()->grant($this->alice, 'entry', $this->e, $this->bob, 'read', null, $sk);
        $this->grantServer();
        $grants = $this->grants()->sharing($this->alice, 'entry', $this->e)['grants'];
        $this->assertSame(['grantee_id' => $this->bob, 'kind' => 'human', 'permission' => 'read', 'expires_at' => null], $grants[0]);
        $this->assertSame(['grantee_id' => -1, 'kind' => 'server', 'permission' => 'read', 'consumers' => ['CveHunter'], 'fields' => ['password'], 'rate_per_hour' => 60, 'rate_burst' => 10], $grants[1]);
        $this->assertSame($grants, $this->grants()->sharing($this->alice, 'entry', $this->e, $sk)['grants'], 'top-level names read the same with the sk');
    }
    private function assertInvalid(callable $call, string $what): void
    {
        try {
            $call();
            $this->fail("accepted $what");
        } catch (VaultException $e) {
            $this->assertSame('payload_invalid', $e->errorCode(), $what);
        }
    }

    // Kills: names not trimmed-checked, an empty list accepted, the 16 cap off by one, no dedupe or sort.
    public function testConsumers(): void
    {
        $this->assertInvalid(fn () => ServerGrant::consumers([' CveHunter']), 'a leading space');
        $this->assertInvalid(fn () => ServerGrant::consumers([]), 'no consumers');
        $names = array_map(static fn (int $i): string => 'C'.$i, range(1, 17));
        $this->assertInvalid(fn () => ServerGrant::consumers($names), '17 consumers');
        $this->assertSame(16, count(ServerGrant::consumers(array_slice($names, 0, 16))));
        $this->assertSame(['a', 'b'], ServerGrant::consumers(['b', 'a', 'a']));
        $this->assertSame(['B', 'a'], ServerGrant::consumers(['a', 'B']), 'byte order');
        $this->assertInvalid(fn () => ServerGrant::consumers([7]), 'a non-string');
    }

    public function testValidConsumer(): void
    {
        foreach (['a', 'CveHunter', 'x_1', 'C'.str_repeat('x', 63)] as $ok) {
            $this->assertTrue(ServerGrant::validConsumer($ok), $ok);
        }
        foreach (['', '9bad', '_x', 'a b', 'a-b', 'C'.str_repeat('x', 64), "a\n", null, 1, ['a']] as $bad) {
            $this->assertFalse(ServerGrant::validConsumer($bad), var_export($bad, true));
        }
    }

    // Adapted to R1: the brief's fields(['title']) is a top-level name (EntryPayload::STRING_KEYS), stored plain; a
    // custom name is the c: MAC form only. Kills: a plain custom name accepted; the control-character, empty and
    // length checks on the MAC helper's input removed; the 32 cap off by one.
    public function testFields(): void
    {
        $this->assertSame(['title'], ServerGrant::fields(['title']));
        $this->assertSame(['password', 'title', 'username'], ServerGrant::fields(['username', 'title', 'password', 'title']));
        $mac = 'c:'.str_repeat('A', 25).'Q';
        $this->assertSame([$mac, 'password'], ServerGrant::fields(['password', $mac]));
        $this->assertInvalid(fn () => ServerGrant::fields(['api_token']), 'a plain custom name');
        $this->assertInvalid(fn () => ServerGrant::fields(["x\x01"]), 'a control character');
        $this->assertInvalid(fn () => ServerGrant::fields([]), 'no fields');
        $many = array_map(static fn (int $i): string => ServerGrant::macField(str_repeat('k', 32), 'f'.$i), range(1, 33));
        $this->assertInvalid(fn () => ServerGrant::fields($many), '33 fields');
        $this->assertCount(32, ServerGrant::fields(array_slice($many, 0, 32)));
    }

    public function testValidField(): void
    {
        foreach ([...ServerGrant::TOP_LEVEL, 'c:'.str_repeat('7', 25).'4', 'c:'.str_repeat('A', 26)] as $ok) {
            $this->assertTrue(ServerGrant::validField($ok), $ok);
        }
        foreach (['', 'api_token', str_repeat('é', 65), 'c:'.str_repeat('A', 25).'B', 'c:'.str_repeat('a', 26), 'C:'.str_repeat('A', 26),
            'c:'.str_repeat('A', 26).'=', 'c:'.str_repeat('A', 27), 'Password', 'password ', null, 3] as $bad) {
            $this->assertFalse(ServerGrant::validField($bad), var_export($bad, true));
        }
    }

    // R1's encoding: RFC 4648 base32 (upper case, no padding) of the 16-byte keyed BLAKE2b. The vector is computed
    // independently here. Kills: the wrong hash length, an unkeyed hash, lower case, padding, a top-level name MACed.
    public function testMacField(): void
    {
        $key = str_repeat("\x01", 32);
        $raw = sodium_crypto_generichash('api_token', $key, 16);
        $bits = '';
        foreach (str_split($raw) as $c) {
            $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        $want = 'c:';
        foreach (str_split(str_pad($bits, 130, '0'), 5) as $chunk) {
            $want .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[bindec($chunk)];
        }
        $got = ServerGrant::macField($key, 'api_token');
        $this->assertSame($want, $got);
        $this->assertSame(28, strlen($got));
        $this->assertTrue(ServerGrant::validField($got));
        $this->assertNotSame($got, ServerGrant::macField(str_repeat("\x02", 32), 'api_token'), 'keyed');
        $this->assertSame('password', ServerGrant::macField($key, 'password'), 'a top-level name stays plain');
        $this->assertSame('title', ServerGrant::macField($key, 'title'));
        $this->assertTrue(ServerGrant::validField(ServerGrant::macField($key, str_repeat('é', 64))), '128 bytes');
        foreach (['', "x\x01", "x\x7f", str_repeat('é', 65), "\xff"] as $bad) {
            $this->assertInvalid(fn () => ServerGrant::macField($key, $bad), bin2hex($bad));
        }
        $this->expectException(LogicException::class);
        ServerGrant::macField('short', 'api_token');
    }

    // Kills: a non-canonical list decoded (callers then trust an order or uniqueness that isn't there).
    public function testEncodeAndDecodeList(): void
    {
        $this->assertSame('["CveHunter","é/x"]', ServerGrant::encodeList([1 => 'CveHunter', 5 => 'é/x']));
        $this->assertSame([], ServerGrant::decodeList(null));
        $this->assertSame(['a', 'b'], ServerGrant::decodeList('["a","b"]'));
        foreach (['["b","a"]', '["a","a"]', '["a", "b"]', '{"0":"a"}', '[1]', 'nope', '"a"', '["'.chr(92).'u00e9"]', '[["a"]]'] as $bad) {
            try {
                ServerGrant::decodeList($bad);
                $this->fail("decoded $bad");
            } catch (LogicException) {
            }
        }
    }

    public function testDefaults(): void
    {
        $this->assertSame([16, 32, 128, 60, 10], [ServerGrant::MAX_CONSUMERS, ServerGrant::MAX_FIELDS, ServerGrant::MAX_FIELD_BYTES, ServerGrant::DEFAULT_RATE, ServerGrant::DEFAULT_BURST]);
        $this->assertSame('/^[A-Za-z][A-Za-z0-9_]{0,63}$/D', ServerGrant::CONSUMER_PATTERN);
    }

    // Kills: an unknown reason accepted; the message not the bare reason; a previous exception chained.
    public function testServiceSecretException(): void
    {
        $e = new ServiceSecretException('rate_limited');
        $this->assertSame('rate_limited', $e->getMessage());
        $this->assertSame('rate_limited', $e->reason());
        $this->assertNull($e->getPrevious());
        $this->assertInstanceOf(RuntimeException::class, $e);
        foreach (ServiceSecretException::REASONS as $r) {
            $this->assertSame($r, (new ServiceSecretException($r))->reason());
        }
        $this->assertSame(['server_off', 'server_key_unavailable', 'not_shared', 'consumer_not_allowed', 'field_not_allowed',
            'rate_limited', 'revoked', 'not_found', 'orphaned'], ServiceSecretException::REASONS);
        $this->expectException(LogicException::class);
        new ServiceSecretException('bogus');
    }
}
