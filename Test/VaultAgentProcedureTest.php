<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/AgentFixture.php';

use Kanboard\Plugin\Vault\Api\VaultAgentProcedure;
use Kanboard\Plugin\Vault\Model\AgentRoster;
use Kanboard\Plugin\Vault\Model\AgentVault;
use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\RateLimitAudit;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec: Agents → Auth and Methods, over the JSON-RPC procedure as Kanboard's server calls it. Every refusal is
// {ok: false, reason} with one of not_agent, bad_vault_key, rate_limited, not_found, conflict, agents_unavailable.
class VaultAgentProcedureTest extends Base
{
    use AgentFixture;

    private const OTHER_IP = '198.51.100.9';
    /** @var list<array> */
    private array $sent = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        $this->setUpAgents();
        $this->pdo()->prepare('UPDATE users SET email = ? WHERE id = ?')->execute(['alice@example.test', $this->alice]);
        $this->container['emailClient']->method('send')->willReturnCallback(function (...$args) {
            $this->sent[] = array_slice($args, 0, 4);
            return $this->container['emailClient'];
        });
    }

    protected function tearDown(): void
    {
        session_flush();
        $this->tearDownVault();
        parent::tearDown();
    }

    // Spec, Auth (a): Vault itself requires the Basic-auth password to be the user's API token (hash_equals against
    // users.api_access_token); Kanboard alone also accepts a login password, which an adopted agent may have. A user
    // without a token never matches, not even an empty password. Kills: the token check dropped (the login password
    // passes); an empty token matching an empty password.
    public function testLoginPasswordRefusedTokenAccepted(): void
    {
        $key = $this->enrolDave();
        [, $e] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Prod DB');

        $this->assertSame(['ok' => false, 'reason' => 'not_agent'], $this->asApi('dave.bot', $this->davePassword, $key)->getVaultSecret($e));
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($key)->getVaultSecret($e));

        $this->pdo()->prepare('UPDATE users SET api_access_token = NULL WHERE id = ?')->execute([$this->dave]);
        $this->assertSame(['ok' => false, 'reason' => 'not_agent'], $this->asApi('dave.bot', '', $key)->getVaultSecret($e));
        $this->pdo()->prepare("UPDATE users SET api_access_token = '' WHERE id = ?")->execute([$this->dave]);
        $this->assertSame(['ok' => false, 'reason' => 'not_agent'], $this->asApi('dave.bot', '', $key)->getVaultSecret($e));
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_audit WHERE action = 'read'"), 'only the token call was served');
    }

    // Spec, Auth: the application (jsonrpc) user is refused, whatever session is lying around. Kills: identity taken
    // from the logged-in session without matching the Basic-auth user (the call would act as dave).
    public function testAppTokenRefused(): void
    {
        $key = $this->enrolDave();
        [, $e] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Prod DB');
        $this->assertSame(['ok' => false, 'reason' => 'not_agent'], $this->asApi('jsonrpc', 'app-token', $key)->getVaultSecret($e));
        // A stale login of dave in the same PHP session must not turn the application user, or anyone else's
        // Basic-auth name, into dave, not even with dave's token as the password.
        foreach (['jsonrpc', 'bob'] as $name) {
            $this->asApi($name, $this->daveToken, $key);
            $this->loginAs($this->dave);
            $this->assertSame(['ok' => false, 'reason' => 'not_agent'], (new VaultAgentProcedure($this->container))->getVaultSecret($e), $name);
        }
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_audit WHERE action IN ('read', 'bad_vault_key')"));
    }

    // Spec, Auth: a non-agent user gets not_agent (the v1 API is for agents only), before the vault key is even looked
    // at. A roster agent whose principal is still human (a legacy enrolment, T14) is no agent principal either, and an
    // agent principal off the roster is no agent. Kills: the roster check dropped (dave off the roster still served); the
    // principal-kind check dropped (bob, on the roster with a human principal, would get bad_vault_key).
    public function testNonAgentNotAgent(): void
    {
        $key = $this->enrolDave();
        $bobToken = bin2hex(random_bytes(30));
        $this->pdo()->prepare('UPDATE users SET api_access_token = ? WHERE id = ?')->execute([$bobToken, $this->bob]);
        $this->principals()->enrolHuman($this->bob, Fixtures::NEW_PASSPHRASE);
        $fake = AgentVault::encodeKey(random_bytes(32));
        foreach (['getVaultEntries' => [], 'getVaultSecret' => [1], 'createVaultEntry' => [['title' => 'x']], 'updateVaultEntry' => [1, 1, ['title' => 'x']]] as $m => $args) {
            $this->assertSame(['ok' => false, 'reason' => 'not_agent'], $this->asApi('bob', $bobToken, $fake)->$m(...$args), $m);
        }
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_rate WHERE bucket LIKE 'agentkey:%'"), 'no key guess counted');

        // bob on the roster, but his principal is human: still no agent.
        $this->roster([$this->dave => $this->alice, $this->bob => $this->alice]);
        $this->assertSame(['ok' => false, 'reason' => 'not_agent'], $this->asApi('bob', $bobToken, $fake)->getVaultEntries());
        // dave's agent principal, once he is off the roster: no agent either.
        $this->roster([]);
        $this->assertSame(['ok' => false, 'reason' => 'not_agent'], $this->asDave($key)->getVaultEntries());
    }

    // Spec, Auth (b): the vault key comes only from the X-Kanboard-Vault-Key header, as base64url. Missing, malformed,
    // wrong or sent anywhere else, it is bad_vault_key, audited (actor, ip_trunc only) and counted. Kills: a key taken
    // from the query string or a JSON-RPC param; a wrong key accepted; a malformed key throwing instead of refusing;
    // the audit row missing or carrying more than its allowlist.
    public function testMissingOrWrongVaultKey(): void
    {
        $key = $this->enrolDave();
        [, $e] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Prod DB');
        $bad = ['ok' => false, 'reason' => 'bad_vault_key'];

        $this->assertSame($bad, $this->asDave(null)->getVaultSecret($e), 'missing');
        $this->assertSame($bad, $this->asDave(null, self::IP, ['QUERY_STRING' => 'vault_key='.$key])->getVaultSecret($e), 'not from the URL');
        $_GET['vault_key'] = $key;
        $this->assertSame($bad, $this->asDave(null)->getVaultSecret($e), 'not from GET');
        unset($_GET['vault_key']);
        $this->assertSame($bad, $this->asDave(AgentVault::encodeKey(random_bytes(32)))->getVaultSecret($e), 'wrong');
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($key)->getVaultSecret($e), 'right (resets the four)');
        $this->assertSame($bad, $this->asDave('not*base64url')->getVaultSecret($e), 'malformed');
        $this->assertSame($bad, $this->asDave(substr($key, 0, 20))->getVaultSecret($e), 'short');
        $this->assertSame($bad, $this->asDave($key.'=')->getVaultSecret($e), 'padded');
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($key)->getVaultSecret($e), 'right');

        $rows = $this->auditRows('bad_vault_key');
        $this->assertCount(7, $rows);
        foreach ($rows as $r) {
            $this->assertSame([$this->dave, '203.0.113.0/24', 'agent', null, null, null, null, null], [
                (int) $r['actor_user_id'], $r['ip_trunc'], $r['actor_kind'], $r['object_type'], $r['object_id'], $r['target_user_id'], $r['share_hash'], $r['count'],
            ]);
        }
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_rate WHERE bucket LIKE 'agentkey:%'"), 'a success resets the pair');
    }

    // Spec, Throttling: the agent key bucket is per agent and IP, so someone holding a leaked token on another IP can't
    // lock out the real agent, not even by forging X-Forwarded-For with the agent's address (R21: no trusted proxy, so
    // forwarding headers are ignored). The guesser is backed off, even with the right key. Kills: a per-agent bucket;
    // the IP taken from X-Forwarded-For; the back-off checked after the key (a right key would get through).
    public function testLeakedTokenOtherIpDoesNotLockRealAgent(): void
    {
        $key = $this->enrolDave();
        [, $e] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Prod DB');
        $forged = ['HTTP_X_FORWARDED_FOR' => self::IP, 'HTTP_X_REAL_IP' => self::IP, 'HTTP_CF_CONNECTING_IP' => self::IP];
        $reasons = [];
        for ($i = 0; $i < 8; $i++) {
            $reasons[] = $this->asDave(AgentVault::encodeKey(random_bytes(32)), self::OTHER_IP, $forged)->getVaultSecret($e)['reason'];
        }
        $this->assertSame(array_merge(array_fill(0, 5, 'bad_vault_key'), array_fill(0, 3, 'rate_limited')), $reasons);
        $this->assertSame(['ok' => false, 'reason' => 'rate_limited'], $this->asDave($key, self::OTHER_IP, $forged)->getVaultSecret($e), 'backed off before the key is tried');

        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($key)->getVaultSecret($e), 'the real agent is untouched');
        $this->assertCount(5, $this->auditRows('bad_vault_key'));
        $this->assertSame(['198.51.100.0/24'], array_values(array_unique(array_column($this->auditRows('bad_vault_key'), 'ip_trunc'))));
    }

    // Spec, Methods: "an entry the agent can't see always gives not_found", the same as a missing one: one not shared,
    // one whose grant expired, one that doesn't exist, and a group it can't see. Kills: forbidden / a distinct reason
    // for an existing entry; the live-grant check skipped (an expired grant still read).
    public function testUnseenEntryIsNotFound(): void
    {
        $key = $this->enrolDave();
        [$cg, $carols] = $this->sharedEntry($this->carol, $this->carolSk(), 'Carol private', false);
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'Expiring']);
        $expiring = $this->store()->createEntry($this->alice, $g, Fixtures::entry('Expiring'));
        $this->grants()->grant($this->alice, 'group', $g, $this->dave, 'read', $this->now + 60, $this->aliceSk());
        $this->assertTrue($this->asDave($key)->getVaultSecret($expiring)['ok'], 'readable while live');
        $this->now += 61;
        $notFound = ['ok' => false, 'reason' => 'not_found'];
        foreach ([$carols, $expiring, 999999, 0, -1, 'abc', [1]] as $id) {
            $this->assertSame($notFound, $this->asDave($key)->getVaultSecret($id), 'secret '.json_encode($id));
            $this->assertSame($notFound, $this->asDave($key)->updateVaultEntry($id, 1, ['password' => 'x']), 'update '.json_encode($id));
        }
        $this->assertSame($notFound, $this->asDave($key)->getVaultSecret($carols, 'notes'));
        $this->assertSame($notFound, $this->asDave($key)->getVaultSecret($expiring, ['password']), 'a non-string field');
        $this->assertSame($notFound, $this->asDave($key)->getVaultEntries($cg));
        $this->assertSame($notFound, $this->asDave($key)->getVaultEntries($g));
        $this->assertSame($notFound, $this->asDave($key)->getVaultEntries(424242));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_audit WHERE action = 'read' AND object_id = ?", [$carols]));
    }

    // Decision 5: agents never overwrite entries a human shared with them; updateVaultEntry works only for entries in the
    // agent's "Agent-created" group that the agent created. An entry the owner added to that group (Edit) is not the
    // agent's to change either. Kills: the created_by check dropped; the group check dropped; a write that lands anyway.
    public function testCannotUpdateSharedEntry(): void
    {
        $key = $this->enrolDave();
        [, $shared] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Shared read');
        $aliceInAgentGroup = $this->store()->createEntry($this->alice, $this->agentGroup($this->dave), Fixtures::entry('Alice put this here'));
        $own = $this->asDave($key)->createVaultEntry(['title' => 'Mine', 'password' => 'first']);
        $this->assertTrue($own['ok']);

        foreach ([$shared, $aliceInAgentGroup] as $id) {
            $before = $this->row('SELECT version, ciphertext FROM vault_entries WHERE id = ?', [$id]);
            $this->assertSame(['ok' => false, 'reason' => 'not_found'], $this->asDave($key)->updateVaultEntry($id, 1, ['password' => 'pwned']));
            $this->assertSame($before, $this->row('SELECT version, ciphertext FROM vault_entries WHERE id = ?', [$id]));
        }
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->store()->readField($this->alice, $aliceInAgentGroup, 'password', $this->aliceSk()));

        $this->assertSame(['ok' => true, 'version' => 2], $this->asDave($key)->updateVaultEntry($own['entry_id'], 1, ['password' => 'second']));
        $this->assertSame(['ok' => false, 'reason' => 'conflict'], $this->asDave($key)->updateVaultEntry($own['entry_id'], 1, ['password' => 'stale']));
        $payload = $this->store()->readEntry($this->alice, $own['entry_id'], $this->aliceSk())['payload'];
        $this->assertSame(['Mine', 'second'], [$payload['title'], $payload['password']], 'the update merges the given fields');
    }

    // Spec: createVaultEntry always creates in the agent's "Agent-created" group, which the owner (Edit grant) sees and
    // nobody else does. Kills: the entry created elsewhere (a group the agent was shared); the owner left out of the
    // recipients; a third person able to read it.
    public function testCreateGoesToAgentCreatedOwnerSees(): void
    {
        $key = $this->enrolDave();
        [$aliceGroup] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Read only');
        $r = $this->asDave($key)->createVaultEntry(['title' => 'Made by dave', 'password' => Fixtures::UPDATED_PASSWORD, 'group_id' => $aliceGroup]);
        $this->assertSame(['ok' => false, 'reason' => 'payload_invalid'], $r, 'no group_id: the payload is an entry');
        $r = $this->asDave($key)->createVaultEntry(['title' => 'Made by dave', 'password' => Fixtures::UPDATED_PASSWORD]);
        $this->assertTrue($r['ok']);
        $row = $this->row('SELECT group_id, owner_id, created_by FROM vault_entries WHERE id = ?', [$r['entry_id']]);
        $this->assertSame([$this->agentGroup($this->dave), $this->dave, $this->dave], [(int) $row['group_id'], (int) $row['owner_id'], (int) $row['created_by']]);
        $this->assertSame(Fixtures::UPDATED_PASSWORD, $this->store()->readField($this->alice, $r['entry_id'], 'password', $this->aliceSk()), 'the owner sees it');
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->carol, $r['entry_id'], $this->carolSk()));
        $this->assertSame(['ok' => false, 'reason' => 'payload_invalid'], $this->asDave($key)->createVaultEntry('just a string'));
        $this->assertSame(['ok' => false, 'reason' => 'payload_invalid'], $this->asDave($key)->createVaultEntry(['title' => ['nested']]));

        $list = $this->asDave($key)->getVaultEntries();
        $this->assertTrue($list['ok']);
        $byTitle = array_column($list['entries'], null, 'title');
        ksort($byTitle);
        $this->assertSame(['Made by dave', 'Read only'], array_keys($byTitle));
        $this->assertTrue($byTitle['Made by dave']['can_write']);
        $this->assertFalse($byTitle['Read only']['can_write']);
        $this->assertSame(['entry_id', 'group_id', 'title', 'username', 'url', 'fields', 'expires_at', 'can_write'], array_keys($byTitle['Read only']));
        $this->assertSame(['api key'], $byTitle['Read only']['fields']);
        $this->assertStringNotContainsString(Fixtures::ENTRY_PASSWORD, json_encode($list), 'no secret values in a listing');
        $this->assertStringNotContainsString(Fixtures::FIELD_VALUE, json_encode($list));
        $this->assertSame([$r['entry_id']], array_column($this->asDave($key)->getVaultEntries($this->agentGroup($this->dave))['entries'], 'entry_id'));
    }

    // Spec, Agents: without the Agents plugin every method refuses with agents_unavailable, before anything else. The
    // real roster decides that by its class_exists guard. Kills: the availability check dropped (not_agent instead);
    // the roster assumed present.
    public function testAgentsPluginAbsentGivesAgentsUnavailable(): void
    {
        $key = $this->enrolDave();
        $unavailable = ['ok' => false, 'reason' => 'agents_unavailable'];
        $this->roster([$this->dave => $this->alice], false);
        foreach (['getVaultEntries' => [], 'getVaultSecret' => [1], 'createVaultEntry' => [['title' => 'x']], 'updateVaultEntry' => [1, 1, ['title' => 'x']]] as $m => $args) {
            $this->assertSame($unavailable, $this->asDave($key)->$m(...$args), $m);
        }
        unset($this->container['vaultAgentRoster']);
        $missing = new AgentRoster($this->container, '\Kanboard\Plugin\NoSuchPlugin\Model\Roster');
        $this->container['vaultAgentRoster'] = fn () => $missing;
        $this->assertFalse($missing->available());
        $this->assertSame($unavailable, $this->asDave($key)->getVaultEntries());
        $this->assertSame($unavailable, $this->asDave($key, self::IP)->getVaultSecret(1));
    }

    // R17 / spec, Unlocked sessions: API requests never touch vault_sessions. An agent's calls create no vault session
    // and set no cookie, and Vault's auth.success listener (Kanboard fires it on every JSON-RPC call) locks nothing.
    // Kills: a vault session created for the API; the listener locking the owner's UI session on an API call.
    public function testApiCallsCreateNoVaultSession(): void
    {
        $key = $this->enrolDave();
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'alice-ui-session');
        $before = $this->countRows('SELECT COUNT(*) FROM vault_sessions');
        $cookies = count($this->jar->sets);
        [, $e] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Prod DB');
        $this->assertTrue($this->asDave($key)->getVaultSecret($e)['ok']);
        $this->assertTrue($this->asDave($key)->createVaultEntry(['title' => 't'])['ok']);
        (new \Kanboard\Plugin\Vault\Subscriber\AuthSubscriber($this->container))->onAuthSuccess();
        $this->assertSame($before, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->dave]));
        $this->assertSame($cookies, count($this->jar->sets), 'no cookie');
    }

    // Spec: every read is audited, and reads are capped per hour (token bucket agentread:<id>, burst 10). A refused read
    // is audited as rate_limited once per window (R39, RateLimitAudit), and the owner is emailed once (R19), with no
    // secret in the mail. Kills: the cap not applied; a read row missing; one rate_limited row per refusal; the owner
    // emailed per refusal or not at all; the secret in the email.
    public function testReadsAreAuditedCappedAndTheOwnerTold(): void
    {
        $this->configureEmail();
        $key = $this->enrolDave();
        [, $e] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Prod DB');
        $results = [];
        for ($i = 0; $i < 14; $i++) {
            $results[] = $this->asDave($key)->getVaultSecret($e)['ok'] ? 'ok' : 'limited';
        }
        $this->assertSame(array_merge(array_fill(0, 10, 'ok'), array_fill(0, 4, 'limited')), $results);
        $reads = $this->auditRows('read');
        $this->assertCount(10, $reads);
        $this->assertSame([$this->dave, 'entry', $e, '203.0.113.0/24', 'agent'], [(int) $reads[0]['actor_user_id'], $reads[0]['object_type'], (int) $reads[0]['object_id'], $reads[0]['ip_trunc'], $reads[0]['actor_kind']]);
        $this->assertSame([], $this->auditRows('rate_limited'), 'counted, not yet written');
        $this->now += RateLimitAudit::WINDOW + 1;
        (new RateLimitAudit($this->container, $this->clock()))->flush();
        $limited = $this->auditRows('rate_limited');
        $this->assertCount(1, $limited);
        $this->assertSame([$this->dave, 4], [(int) $limited[0]['target_user_id'], (int) $limited[0]['count']]);
        $this->assertCount(1, $this->sent, 'the owner is told once');
        $this->assertSame('alice@example.test', $this->sent[0][0]);
        $this->assertStringNotContainsString(Fixtures::ENTRY_PASSWORD, json_encode($this->sent));
        // Tokens come back over time (60 an hour).
        $this->assertSame('ok', $this->asDave($key)->getVaultSecret($e)['ok'] ? 'ok' : 'limited');
    }

    // Spec, Throttling: "the owner is notified after 5 failures" of the agent's vault key, and the notice holds no key.
    // Kills: no notice; a notice per failure; the key in the email.
    public function testOwnerToldAfterFiveBadKeys(): void
    {
        $this->configureEmail();
        $key = $this->enrolDave();
        for ($i = 0; $i < 4; $i++) {
            $this->asDave(AgentVault::encodeKey(random_bytes(32)))->getVaultEntries();
        }
        $this->assertSame([], $this->sent);
        $wrong = AgentVault::encodeKey(random_bytes(32));
        $this->asDave($wrong)->getVaultEntries();
        $this->assertCount(1, $this->sent);
        $this->assertSame('alice@example.test', $this->sent[0][0]);
        $this->assertStringNotContainsString($wrong, json_encode($this->sent));
        $this->assertStringNotContainsString($key, json_encode($this->sent));
    }

    // Kanboard's procedure handler (withObject) lets core win a name clash and makes every method of the object
    // callable, private ones included; the ACL keys on the short class name. So the class declares exactly the four
    // methods, without type hints (a TypeError would be a fatal with no JSON-RPC body), with a name no core procedure
    // uses. Kills: a helper method on the procedure; a typed parameter; a clashing name.
    public function testProcedureSurface(): void
    {
        $declared = array_map(fn ($m) => $m->getName(), array_filter(
            (new ReflectionClass(VaultAgentProcedure::class))->getMethods(),
            fn ($m) => $m->getDeclaringClass()->getName() === VaultAgentProcedure::class
        ));
        sort($declared);
        $this->assertSame(['createVaultEntry', 'getVaultEntries', 'getVaultSecret', 'updateVaultEntry'], $declared);
        foreach ($declared as $m) {
            foreach ((new ReflectionMethod(VaultAgentProcedure::class, $m))->getParameters() as $p) {
                $this->assertNull($p->getType(), "$m \$".$p->getName());
            }
            foreach (glob('app/Api/Procedure/*Procedure.php') as $file) {
                $this->assertFalse(method_exists('Kanboard\\Api\\Procedure\\'.basename($file, '.php'), $m), "$m clashes with core");
            }
        }
        $this->assertFileDoesNotExist('app/Api/Procedure/VaultAgentProcedure.php');
    }

    // Plugin.php registers the procedure on Kanboard's JSON-RPC server (Agents' withObject pattern).
    public function testPluginRegistersTheProcedure(): void
    {
        unset($this->container['api']);
        $server = new \JsonRPC\Server('{}', []);
        $this->container['api'] = $server;
        (new Plugin($this->container))->initialize();
        $instances = (fn () => $this->instances)->call($server->getProcedureHandler());
        $this->assertCount(1, array_filter($instances, fn ($i) => $i instanceof VaultAgentProcedure));
    }
}
