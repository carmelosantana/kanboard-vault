<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';

use Kanboard\Plugin\Vault\Model\AgentRoster;
use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\GranteeDirectory;
use Kanboard\Plugin\Vault\Model\Notifier;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultFailure;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// A roster set by the test: agent user id → owner user id. Every Vault model must ask AgentRoster, so this one decides.
class VaultFakeRoster extends AgentRoster
{
    public function __construct($container, private array $agents)
    {
        parent::__construct($container);
    }

    public function isAgent(int $userId): bool
    {
        return isset($this->agents[$userId]);
    }

    public function agentsOf(int $ownerId): array
    {
        return array_keys(array_filter($this->agents, fn (int $o): bool => $o === $ownerId));
    }

    public function ownerOf(int $agentId): ?int
    {
        return $this->agents[$agentId] ?? null;
    }
}

// Review T14 I1 and R47: one definition of "agent", the Agents roster (spec: Agents, "Vault decides who is an agent with
// AgentTable roster membership"), through AgentRoster, used by GrantModel, PrincipalModel, GranteeDirectory, AuditModel
// and Notifier. A roster agent can't enrol as a human, and even one that holds a human principal gets Read only.
class AgentRosterTest extends Base
{
    use ServiceFixture;

    private int $dave;
    /** @var list<array> */
    private array $sent = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->dave = (int) $this->container['userModel']->create(['username' => 'dave.bot', 'password' => 'dave usable password 1']);
        $this->pdo()->prepare('UPDATE users SET email = ? WHERE id = ?')->execute(['alice@example.test', $this->alice]);
        $this->container['emailClient']->method('send')->willReturnCallback(function (...$args) {
            $this->sent[] = array_slice($args, 0, 4);
            return $this->container['emailClient'];
        });
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function roster(array $agents): void
    {
        // Pimple freezes a service once read, so it is set again from scratch each time.
        unset($this->container['vaultAgentRoster']);
        $fake = new VaultFakeRoster($this->container, $agents);
        $this->container['vaultAgentRoster'] = fn () => $fake;
    }

    // A human principal inserted by hand, as an enrolment before this fix (or before adoption) would have left it.
    private function humanPrincipal(int $userId): void
    {
        $kp = sodium_crypto_box_keypair();
        $this->pdo()->prepare("INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at, live_user_id) VALUES (?, 'human', ?, 1, 'active', ?, ?)")
            ->execute([$userId, base64_encode(sodium_crypto_box_publickey($kp)), $this->now, $userId]);
    }

    // An adopted agent may have a usable password and log in to the web UI; it still can't make itself a human
    // principal. The refusal is generic (VaultFailure 'failed'), and nothing is written. Kills: enrolHuman without the
    // roster check.
    public function testRosterAgentCannotEnrolAsHuman(): void
    {
        $this->roster([$this->dave => $this->alice]);
        $e = $this->assertVaultError('enrol_refused', fn () => $this->principals()->enrolHuman($this->dave, 'VaultFixtureSecret-davephrase-Mn7oP8'));
        $this->assertSame([400, 'failed'], VaultFailure::map($e), 'generic to the client');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_principals WHERE user_id = ?', [$this->dave]));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_audit WHERE action = 'enroll' AND actor_user_id = ?", [$this->dave]));
        $this->assertSame(0, $this->argonCalls - 1, 'refused before any Argon2 work (alice\'s enrolment was the one call)');
        // Not on the roster: a normal enrolment.
        $this->roster([]);
        $this->principals()->enrolHuman($this->dave, 'VaultFixtureSecret-davephrase-Mn7oP8');
        $this->assertSame('human', $this->row('SELECT kind FROM vault_principals WHERE user_id = ?', [$this->dave])['kind']);
    }

    // R47 against a roster agent that holds a human principal (inserted directly): Edit is still refused, Read works.
    // Kills: checkAgentGrant trusting the principal's kind alone.
    public function testRosterAgentWithHumanPrincipalCannotGetEdit(): void
    {
        $this->humanPrincipal($this->dave);
        $this->roster([$this->dave => $this->bob]);
        $sk = $this->skFor($this->alice, Fixtures::PASSPHRASE);
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'Infra']);
        $this->assertVaultError('agent_read_only', fn () => $this->grants()->grant($this->alice, 'group', $g, $this->dave, 'edit', null, $sk));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants'));
        $this->grants()->grant($this->alice, 'group', $g, $this->dave, 'read', null, $sk);
        $this->assertSame('read', $this->row('SELECT permission FROM vault_grants')['permission']);
    }

    // Every agent lookup goes through AgentRoster: with no agents table at all, the fake roster alone makes dave alice's
    // agent, and each call site follows it. No Vault source outside AgentRoster queries the roster itself.
    // Kills: GranteeDirectory, AuditModel or Notifier keeping its own roster query; a new copy anywhere.
    public function testEveryAgentLookupGoesThroughTheRoster(): void
    {
        $this->humanPrincipal($this->dave);
        $this->roster([$this->dave => $this->alice]);

        // GranteeDirectory: alice's own agent is offered without sharing a project.
        $this->assertSame([$this->dave], array_column((new GranteeDirectory($this->container))->candidates($this->alice), 'id'));

        // AuditModel: alice sees her agent's own rows.
        AuditModel::of($this->container)->record('lock', ['actor_user_id' => $this->dave]);
        $mine = array_filter(AuditModel::of($this->container)->visibleTo($this->alice, 0, 50), fn (array $r): bool => $r['actor_user_id'] === $this->dave);
        $this->assertCount(1, $mine);
        $this->assertSame([], AuditModel::of($this->container)->visibleTo($this->bob, 0, 50));

        // Notifier: the agent's owner gets its notice.
        $this->configureEmail();
        $this->assertTrue((new Notifier($this->container))->agentBadKey($this->dave));
        $this->assertSame('alice@example.test', $this->sent[0][0]);

        // The source: only AgentRoster names the roster.
        $root = dirname(__DIR__);
        $offenders = [];
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)) as $f) {
            $path = $f->getPathname();
            if ($f->getExtension() !== 'php' || str_contains($path, '/Test/') || str_ends_with($path, '/Model/AgentRoster.php')) {
                continue;
            }
            $src = (string) file_get_contents($path);
            if (preg_match('/AgentTable|\bFROM\s+agents\b|\bJOIN\s+agents\b/i', $src)) {
                $offenders[] = substr($path, strlen($root) + 1);
            }
        }
        $this->assertSame([], $offenders);
    }

    // The real roster, read from Agents' table behind the class_exists guard; without the table every answer is empty.
    // Kills: isAgent, agentsOf or ownerOf answering wrongly; an unreadable table throwing.
    public function testRealRosterReadsAgentsTable(): void
    {
        $roster = new AgentRoster($this->container);
        $this->assertFalse($roster->isAgent($this->dave), 'no table yet: nobody');
        $this->assertSame([], $roster->agentsOf($this->alice));
        if (! class_exists('\Kanboard\Plugin\Agents\Model\AgentTable')) {
            $this->markTestSkipped('Agents is not installed');
        }
        $this->agentsTable();
        $this->adoptAgent($this->alice, $this->dave);
        $this->assertTrue($roster->isAgent($this->dave));
        $this->assertFalse($roster->isAgent($this->bob));
        $this->assertSame([$this->dave], $roster->agentsOf($this->alice));
        $this->assertSame($this->alice, $roster->ownerOf($this->dave));
        $this->assertNull($roster->ownerOf($this->bob));
        $this->assertVaultError('enrol_refused', fn () => $this->principals()->enrolHuman($this->dave, 'VaultFixtureSecret-davephrase-Mn7oP8'));
    }
}
