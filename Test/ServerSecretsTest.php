<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';
require_once __DIR__.'/Support/VaultFailingAudit.php';

use Kanboard\Plugin\Vault\Model\Correlation;
use Kanboard\Plugin\Vault\Model\RateLimitAudit;
use Kanboard\Plugin\Vault\Model\ServerGrant;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Model\ServerSecrets;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;
use Kanboard\Plugin\Vault\Secrets\ServiceSecrets;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec amendment: Consumer API → The read path; security requirements 4, 5 and 13. ServerSecrets::read runs steps 1–11
// in order, steps 3–11 in one exclusive transaction that also holds the audit row and the spent token; every refusal
// is a typed ServiceSecretException whose message is the frozen reason and nothing else. R1: a custom field is matched,
// and audited, by its MAC. R3: rate_limited denials are aggregated per bucket and window.
class ServerSecretsTest extends Base
{
    use ServerFixture;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpAgents();
        $this->principals()->enrolHuman($this->bob, Fixtures::NEW_PASSPHRASE);
        $this->setUpServer();
    }

    protected function tearDown(): void
    {
        $this->tearDownServer();
        $this->tearDownVault();
        parent::tearDown();
    }

    private function mac(string $name): string
    {
        return ServerGrant::macField($this->freshProvider()->openFieldMacKey(), $name);
    }

    private function refused(string $reason, callable $fn): ServiceSecretException
    {
        try {
            $fn();
        } catch (ServiceSecretException $e) {
            $this->assertSame($reason, $e->reason());
            return $e;
        }
        $this->fail("expected $reason");
    }

    private function bucketRow(int $e): ?array
    {
        return $this->row('SELECT tokens, updated_at FROM vault_rate WHERE bucket = ?', [ServerSecrets::bucket('CveHunter', $e)]);
    }

    // Kills: a value from the wrong field; an unaudited read; the audit row missing a column or with the wrong actor.
    public function testReadReturnsOneFieldAndAuditsIt(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $v = $this->serverSecrets()->read('CveHunter', "vault://$e/password", 'scan:nightly');
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $v->reveal());
        $rows = $this->auditRows('server_read');
        $this->assertCount(1, $rows);
        $row = $rows[0];
        $this->assertSame(['server', null, 'entry', (string) $e, 'password', '1', 'CveHunter', 'scan:nightly', Correlation::id()],
            [$row['actor_kind'], $row['actor_user_id'], $row['object_type'], (string) $row['object_id'], $row['field_name'],
             (string) $row['entry_version'], $row['consumer'], $row['job_ref'], $row['correlation_id']]);
        $this->assertSame([], $this->auditRows('server_read_denied'));
    }

    /** @return array<string, array{0: string, 1: callable}> reason => arrange(test, entryId): [consumer, ref] */
    public static function refusals(): array
    {
        return [
            'server_off' => ['server_off', static function (self $t, int $e): array {
                ServerPrincipal::of($t->container)->disable(1);
                return ['CveHunter', "vault://$e/password"];
            }],
            'server_key_unavailable' => ['server_key_unavailable', static function (self $t, int $e): array {
                file_put_contents($t->keyPath, random_bytes(32));
                chmod($t->keyPath, 0600);
                return ['CveHunter', "vault://$e/password"];
            }],
            'not_shared' => ['not_shared', static function (self $t, int $e): array {
                $g = (int) $t->row('SELECT group_id FROM vault_entries WHERE id = ?', [$e])['group_id'];
                $other = $t->store()->createEntry($t->alice, $g, Fixtures::fullEntry());
                return ['CveHunter', "vault://$other/password"];
            }],
            'revoked' => ['revoked', static function (self $t, int $e): array {
                $t->grants()->revoke($t->alice, 'entry', $e, ServerPrincipal::ID, $t->aliceSk());
                return ['CveHunter', "vault://$e/password"];
            }],
            'consumer_not_allowed' => ['consumer_not_allowed', static fn (self $t, int $e): array => ['Lifeboat', "vault://$e/password"]],
            'consumer_not_allowed (invalid name)' => ['consumer_not_allowed', static fn (self $t, int $e): array => ['not a consumer!', "vault://$e/password"]],
            'field_not_allowed' => ['field_not_allowed', static fn (self $t, int $e): array => ['CveHunter', "vault://$e/username"]],
            'field_not_allowed (custom)' => ['field_not_allowed', static fn (self $t, int $e): array => ['CveHunter', 'vault://'.$e.'/'.rawurlencode(Fixtures::FIELD_NAME)]],
            'rate_limited' => ['rate_limited', static function (self $t, int $e): array {
                for ($i = 0; $i < 10; $i++) {
                    $t->serverSecrets()->read('CveHunter', "vault://$e/password");
                }
                return ['CveHunter', "vault://$e/password"];
            }],
            'not_found (unknown entry)' => ['not_found', static fn (self $t, int $e): array => ['CveHunter', 'vault://'.($e + 1000).'/password']],
            'not_found (version)' => ['not_found', static fn (self $t, int $e): array => ['CveHunter', "vault://$e/password@2"]],
            'not_found (malformed)' => ['not_found', static fn (self $t, int $e): array => ['CveHunter', 'vault:/x']],
            'not_found (allowed but absent)' => ['not_found', static function (self $t, int $e): array {
                $payload = Fixtures::fullEntry();
                $payload['fields'][] = ['name' => 'API_TOKEN', 'value' => 'VaultFixtureSecret-apitoken', 'protected' => true];
                $other = $t->serverShare(['CveHunter'], ['password', 'API_TOKEN'], $payload);
                $t->store()->updateEntry($t->alice, $other, 1, Fixtures::fullEntry(), $t->aliceSk());
                return ['CveHunter', "vault://$other/API_TOKEN"];
            }],
            'orphaned' => ['orphaned', static function (self $t, int $e): array {
                $t->container['userModel']->remove($t->alice);
                return ['CveHunter', "vault://$e/password"];
            }],
        ];
    }

    // Kills: any of steps 1–11 skipped or reordered so a refusal leaks a later stage; a refusal not audited; a value or
    // title in the exception.
    /** @dataProvider refusals */
    public function testEveryRefusalIsTypedAuditedAndCarriesNothing(string $reason, callable $arrange): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        [$consumer, $ref] = $arrange($this, $e);
        try {
            $this->serverSecrets()->read($consumer, $ref);
            $this->fail("$reason: read succeeded");
        } catch (ServiceSecretException $x) {
            $this->assertSame($reason, $x->reason());
            $this->assertSame($reason, $x->getMessage());
            $this->assertNull($x->getPrevious());
            foreach ([Fixtures::ENTRY_PASSWORD, Fixtures::ENTRY_TITLE] as $s) {
                $this->assertStringNotContainsString($s, (string) $x);
            }
        }
        $denied = $this->auditRows('server_read_denied');
        $this->assertCount(1, $denied);
        $this->assertSame($reason, $denied[0]['reason']);
        $this->assertSame('server', $denied[0]['actor_kind']);
        if ($reason === 'rate_limited') {
            $this->assertCount(10, $this->auditRows('server_read'));
            $this->assertSame('1', (string) $denied[0]['count']);
        } else {
            $this->assertSame([], $this->auditRows('server_read'));
            $this->assertNull($denied[0]['count']);
        }
    }

    // Requirement 5: a key row alone grants nothing, and a stale one opens nothing.
    public function testStaleKeyRowWithoutAGrantReadsNothing(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->pdo()->prepare('DELETE FROM vault_grants WHERE grantee_id = -1 AND subject_id = ?')->execute([$e]);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE principal_id = -1 AND object_id = ?', [$e]), 'the key row is still there');
        $this->refused('not_shared', fn () => $this->serverSecrets()->read('CveHunter', "vault://$e/password"));

        $e2 = $this->serverShare(['CveHunter'], ['password']);
        $this->pdo()->prepare('UPDATE vault_entries SET key_epoch = key_epoch + 1 WHERE id = ?')->execute([$e2]);
        $this->refused('not_shared', fn () => $this->serverSecrets()->read('CveHunter', "vault://$e2/password"));
    }

    // Requirement 13. Mutation: grant rates not clamped to the admin maximum at read time.
    public function testRateRefillsAtTheConfiguredRate(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $read = fn () => $this->serverSecrets()->read('CveHunter', "vault://$e/password");
        for ($i = 0; $i < 10; $i++) {
            $read();
        }
        $this->refused('rate_limited', $read);
        $this->now += 60;
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $read()->reveal(), '60/h is one token a minute');
        $this->refused('rate_limited', $read);

        $e2 = $this->serverShare(['CveHunter'], ['password']);
        $this->settings()->set('vault_server_rate_max', 30, self::ADMIN);
        $read2 = fn () => $this->serverSecrets()->read('CveHunter', "vault://$e2/password");
        for ($i = 0; $i < 10; $i++) {
            $read2();
        }
        $this->now += 60;
        $this->refused('rate_limited', $read2);
        $this->now += 60;
        $read2();
    }

    // R3: rate_limited refusals in one window are aggregated like R39: the window's first refusal is recorded at once
    // (count 1), the rest are tallied and written as one row with their count once the window has closed (the next
    // refusal on the bucket after it, or the purge's flush). Every other refusal is one row each.
    public function testRateLimitedRefusalsAggregatePerWindow(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        for ($i = 0; $i < 10; $i++) {
            $this->serverSecrets()->read('CveHunter', "vault://$e/password");
        }
        for ($i = 0; $i < 25; $i++) {
            $this->refused('rate_limited', fn () => $this->serverSecrets()->read('CveHunter', "vault://$e/password", 'job:'.$i));
            $this->now += 1;
        }
        $this->refused('field_not_allowed', fn () => $this->serverSecrets()->read('CveHunter', "vault://$e/username"));
        $this->refused('field_not_allowed', fn () => $this->serverSecrets()->read('CveHunter', "vault://$e/username"));
        $denied = $this->auditRows('server_read_denied');
        $this->assertSame([['rate_limited', '1'], ['field_not_allowed', null], ['field_not_allowed', null]],
            array_map(fn (array $r): array => [$r['reason'], $r['count'] === null ? null : (string) $r['count']], $denied));

        $this->assertSame(0, (new RateLimitAudit($this->container, $this->clock()))->flush(), 'the window is still open');
        $this->now += RateLimitAudit::WINDOW;
        $this->assertSame(1, (new RateLimitAudit($this->container, $this->clock()))->flush());
        $denied = $this->auditRows('server_read_denied');
        $this->assertCount(4, $denied);
        $tally = $denied[3];
        $this->assertSame(['rate_limited', '24', 'server', 'entry', (string) $e, 'CveHunter', null, null],
            [$tally['reason'], (string) $tally['count'], $tally['actor_kind'], $tally['object_type'], (string) $tally['object_id'], $tally['consumer'], $tally['field_name'], $tally['job_ref']]);
        $this->assertSame(0, (new RateLimitAudit($this->container, $this->clock()))->flush(), 'written once');

        // The next window: its first refusal writes the closed window's tally (none left) and its own row.
        for ($i = 0; $i < 10; $i++) {
            $this->serverSecrets()->read('CveHunter', "vault://$e/password");
        }
        $this->refused('rate_limited', fn () => $this->serverSecrets()->read('CveHunter', "vault://$e/password"));
        $this->assertCount(5, $this->auditRows('server_read_denied'));
    }

    // R1: a custom field arrives percent-encoded, is matched by its MAC, and the audit row holds the MAC, never the name.
    // Kills: the plain custom name compared against the stored MACs; the plain name audited.
    public function testCustomFieldByEncodedName(): void
    {
        $payload = Fixtures::fullEntry();
        $payload['fields'][] = ['name' => 'My Token', 'value' => 'VaultFixtureSecret-mytoken', 'protected' => true];
        $e = $this->serverShare(['CveHunter'], ['My Token'], $payload);
        $this->assertSame('VaultFixtureSecret-mytoken', $this->serverSecrets()->read('CveHunter', "vault://$e/My%20Token")->reveal());
        $row = $this->auditRows('server_read')[0];
        $this->assertSame($this->mac('My Token'), $row['field_name']);
        $this->assertStringNotContainsString('My Token', json_encode($this->auditRows(), JSON_THROW_ON_ERROR));
        $this->refused('field_not_allowed', fn () => $this->serverSecrets()->read('CveHunter', "vault://$e/My%20token"));
        $this->assertSame($this->mac('My token'), $this->auditRows('server_read_denied')[0]['field_name']);
    }

    // R5: title is a top-level ref field, and a top-level key wins over a custom field with the same name.
    public function testTopLevelKeyWinsOverACustomFieldOfTheSameName(): void
    {
        $payload = Fixtures::fullEntry();
        $payload['fields'][] = ['name' => 'password', 'value' => 'VaultFixtureSecret-shadowpw', 'protected' => true];
        $payload['fields'][] = ['name' => 'title', 'value' => 'VaultFixtureSecret-shadowtitle', 'protected' => true];
        $e = $this->serverShare(['CveHunter'], ['password', 'title'], $payload);
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->serverSecrets()->read('CveHunter', "vault://$e/password")->reveal());
        $this->assertSame(Fixtures::ENTRY_TITLE, $this->serverSecrets()->read('CveHunter', "vault://$e/title")->reveal());
        $this->assertSame(['password', 'title'], array_column($this->auditRows('server_read'), 'field_name'));
    }

    // One transaction: an audit write that fails after the token was taken rolls the token back with it.
    public function testAuditFailureRollsBackTheToken(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->serverSecrets()->read('CveHunter', "vault://$e/password");
        $before = $this->bucketRow($e);
        $this->assertNotNull($before);
        unset($this->container['vaultAudit']);
        $this->container['vaultAudit'] = fn ($c) => new VaultFailingAudit($c, 'server_read', $this->clock());
        $this->now += 1;
        try {
            $this->serverSecrets()->read('CveHunter', "vault://$e/password");
            $this->fail('the audit failure must surface');
        } catch (RuntimeException $x) {
            $this->assertNotInstanceOf(ServiceSecretException::class, $x);
            $this->assertSame('injected audit failure', $x->getMessage());
        }
        $this->assertSame($before, $this->bucketRow($e));
        $this->assertCount(1, $this->auditRows('server_read'));
    }

    private function initializePlugin(): void
    {
        foreach (['vaultServerKeyFile', 'vaultKeyProvider', 'vaultServerPrincipal', 'vaultSecrets', 'vaultAudit'] as $service) {
            unset($this->container[$service]);
        }
        (new Plugin($this->container))->initialize();
    }

    public function testContainerHasVaultSecretsOnlyWhenServerIsOn(): void
    {
        $this->initializePlugin();
        $this->assertFalse(isset($this->container['vaultSecrets']));

        $this->registerServerServices();
        $this->enableServer();
        $this->initializePlugin();
        $this->assertTrue(isset($this->container['vaultSecrets']));
        $this->assertInstanceOf(ServiceSecrets::class, $this->container['vaultSecrets']);
    }

    // Kills: describe spending a token, writing an audit row or carrying the title.
    public function testDescribeIsTitleFree(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $g = (int) $this->row('SELECT group_id FROM vault_entries WHERE id = ?', [$e])['group_id'];
        $other = $this->store()->createEntry($this->alice, $g, Fixtures::fullEntry());
        $audit = count($this->auditRows());
        $ok = $this->serverSecrets()->describe("vault://$e/password");
        $this->assertSame([true, null, $e, 'password'], [$ok->ok, $ok->reason, $ok->entryId, $ok->field]);
        $no = $this->serverSecrets()->describe("vault://$other/password");
        $this->assertSame([false, 'not_shared', $other, 'password'], [$no->ok, $no->reason, $no->entryId, $no->field]);
        $this->assertSame([false, 'field_not_allowed'], [($f = $this->serverSecrets()->describe("vault://$e/username"))->ok, $f->reason]);
        $this->assertSame([false, 'not_found', null, null], [($m = $this->serverSecrets()->describe('vault:/x'))->ok, $m->reason, $m->entryId, $m->field]);
        foreach ([$ok, $no] as $status) {
            $this->assertStringNotContainsString(Fixtures::ENTRY_TITLE, var_export($status, true));
            $this->assertStringNotContainsString(Fixtures::ENTRY_PASSWORD, var_export($status, true));
        }
        $this->assertCount($audit, $this->auditRows(), 'no audit row');
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_rate WHERE bucket LIKE 'srvread:%'"), 'no token spent');
        ServerPrincipal::of($this->container)->disable(1);
        $this->assertSame('server_off', $this->serverSecrets()->describe("vault://$e/password")->reason);
    }

    public function testAvailable(): void
    {
        $this->assertFalse($this->serverSecrets()->available(), 'off');
        $this->enableServer();
        $this->assertTrue($this->serverSecrets()->available(), 'on, with a healthy key');
        unlink($this->keyPath);
        $this->assertFalse($this->serverSecrets()->available(), 'the key file gone');
        ServerPrincipal::of($this->container)->disable(1);
        $this->assertFalse($this->serverSecrets()->available(), 'off again');
    }

    // A job ref the audit can't hold is a caller error, refused before anything runs.
    public function testMalformedJobRefIsRefused(): void
    {
        $e = $this->serverShare(['CveHunter'], ['password']);
        $this->expectException(InvalidArgumentException::class);
        try {
            $this->serverSecrets()->read('CveHunter', "vault://$e/password", 'bad job ref with spaces');
        } finally {
            $this->assertSame([], $this->auditRows('server_read'));
            $this->assertNull($this->bucketRow($e));
        }
    }
}
