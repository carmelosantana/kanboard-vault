<?php

use Kanboard\Plugin\Vault\Api\VaultAgentProcedure;
use Kanboard\Plugin\Vault\Model\AgentVault;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;

require_once __DIR__.'/ServiceFixture.php';
require_once __DIR__.'/TestRoster.php';

// Agents for the agent tests (spec: Agents): alice owns the agent dave, an adopted user with a real login password and
// an API token; carol is a third person with her own vault. Calls reach Vault as Kanboard's JSON-RPC server hands them
// over: the API middleware has logged the user in from Basic auth and set the session scope 'API'.
trait AgentFixture
{
    use ServiceFixture;

    protected int $dave;
    protected int $carol;
    protected string $daveToken;
    protected string $davePassword = 'dave usable password 1';

    protected function setUpAgents(): void
    {
        $this->setUpVault();
        $this->dave = (int) $this->container['userModel']->create(['username' => 'dave.bot', 'password' => $this->davePassword]);
        $this->carol = (int) $this->container['userModel']->create(['username' => 'carol', 'password' => 'carol login password 1']);
        $this->daveToken = bin2hex(random_bytes(30));
        $this->pdo()->prepare('UPDATE users SET api_access_token = ? WHERE id = ?')->execute([$this->daveToken, $this->dave]);
        $this->roster([$this->dave => $this->alice]);
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->principals()->enrolHuman($this->carol, Fixtures::BOB_PASSPHRASE);
        $this->container['vaultAgentVault'] = fn ($c) => new AgentVault($c, $this->clock());
    }

    protected function roster(array $agents, bool $present = true): void
    {
        // Pimple freezes a service once read, so it is set again from scratch each time.
        unset($this->container['vaultAgentRoster']);
        $fake = new VaultTestRoster($this->container, $agents, $present);
        $this->container['vaultAgentRoster'] = fn () => $fake;
    }

    protected function agentVault(): AgentVault
    {
        return new AgentVault($this->container, $this->clock());
    }

    protected function aliceSk(): string
    {
        return $this->skFor($this->alice, Fixtures::PASSPHRASE);
    }

    protected function carolSk(): string
    {
        return $this->skFor($this->carol, Fixtures::BOB_PASSPHRASE);
    }

    protected function enrolDave(): string
    {
        return $this->agentVault()->enrol($this->alice, $this->dave, $this->aliceSk());
    }

    // The request as Kanboard's JSON-RPC server leaves it: Basic-auth credentials on the server object, the user the
    // middleware authenticated logged in (none for the application user), the session scope 'API', the vault key header.
    protected function asApi(string $username, string $password, ?string $vaultKey, string $remoteAddr = self::IP, array $server = []): VaultAgentProcedure
    {
        unset($this->container['api']);
        $this->container['api'] = new \JsonRPC\Server('{}', ['PHP_AUTH_USER' => $username, 'PHP_AUTH_PW' => $password]);
        session_flush();
        $user = $this->container['userModel']->getByUsername($username);
        if ($username !== 'jsonrpc' && $user) {
            $this->container['userSession']->initialize($user);
        }
        session_set('scope', 'API');
        $server += ['REMOTE_ADDR' => $remoteAddr, 'SCRIPT_NAME' => '/jsonrpc.php', 'REQUEST_METHOD' => 'POST'];
        if ($vaultKey !== null) {
            $server['HTTP_X_KANBOARD_VAULT_KEY'] = $vaultKey;
        }
        $this->container['request'] = new \Kanboard\Core\Http\Request($this->container, $server, [], [], [], []);
        return new VaultAgentProcedure($this->container);
    }

    // dave with his token and the given key.
    protected function asDave(?string $vaultKey, string $remoteAddr = self::IP, array $server = []): VaultAgentProcedure
    {
        return $this->asApi('dave.bot', $this->daveToken, $vaultKey, $remoteAddr, $server);
    }

    // An entry owned by $ownerId in a new group of theirs, the group read-shared with dave when $share.
    protected function sharedEntry(int $ownerId, string $sk, string $title, bool $share = true): array
    {
        $g = $this->store()->createGroup($ownerId, null, ['name' => $title.' group']);
        $e = $this->store()->createEntry($ownerId, $g, Fixtures::entry($title));
        if ($share) {
            $this->grants()->grant($ownerId, 'group', $g, $this->dave, 'read', null, $sk);
        }
        return [$g, $e];
    }

    protected function agentGroup(int $agentId): ?int
    {
        $r = $this->row("SELECT id FROM vault_groups WHERE owner_id = ? AND kind = 'agent_created'", [$agentId]);
        return $r === null ? null : (int) $r['id'];
    }
}
