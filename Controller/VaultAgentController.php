<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\AgentRoster;
use Kanboard\Plugin\Vault\Model\AgentVault;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultSettings;

// The owner's agents and their vault access (spec: Agents → Enrolment, Re-enrolment; Throttling, agent secret reads).
//
//   GET  vault/agents          the page: the logged-in user's own agents (the Agents roster), each with its vault
//                              state, Enable vault access / Re-enrol, and the read cap. Without a vault of their own the
//                              buttons are disabled with the reason; locked, they say to unlock first.
//   POST vault/agents/enrol    {agent_id}: AgentVault::enrol. The vault key comes back once: JSON to vault-agents.js
//   POST vault/agents/reenrol  {agent_id}: AgentVault::reenrol.      ({ok, vault_key, env}), or for a native form POST
//                              this page rendered with the key (no-store, never in a URL or a redirect).
//   POST vault/agents/cap      {agent_id, cap}: AgentVault::setReadCap; the admin maximum still applies.
//
// Only the owner's agents, for everyone (an app admin too): AgentVault refuses any other agent with not_found. Every
// POST carries the CSRF token, runs in the hardened handler with the unlocked owner's key (withKey: fetched before any
// vault lock, wiped after) and answers failures with VaultFailure's fixed reasons. A vault key is a secret, so the key
// endpoints need a secure transport, as unlock does.
class VaultAgentController extends BaseVaultController
{
    public function index(): void
    {
        $this->handle(fn () => $this->page());
    }

    public function enrol(): void
    {
        $this->keyAction(false);
    }

    public function reenrol(): void
    {
        $this->keyAction(true);
    }

    public function cap(): void
    {
        $this->withKey(function (int $userId): void {
            $cap = $this->intParam('cap');
            $this->agentVault()->setReadCap($userId, (int) $this->intParam('agent_id'), $cap ?? 0);
            $this->succeed([], 'saved');
        });
    }

    protected function returnRoute(): array
    {
        return ['VaultAgentController', 'index'];
    }

    private function keyAction(bool $reenrol): void
    {
        $this->withKey(function (int $userId, #[\SensitiveParameter] string $sk) use ($reenrol): void {
            $this->requireTransport();
            $agentId = (int) $this->intParam('agent_id');
            $vault = $this->agentVault();
            $key = $reenrol ? $vault->reenrol($userId, $agentId, $sk) : $vault->enrol($userId, $agentId, $sk);
            if ($this->request->isAjax()) {
                $this->answer(['agent_id' => $agentId, 'vault_key' => $key, 'env' => 'KANBOARD_VAULT_KEY='.$key]);
            } else {
                $this->page(['agent_id' => $agentId, 'key' => $key]);
            }
        });
    }

    // $shown: the key a native form POST just made, shown once.
    private function page(array $shown = []): void
    {
        $userId = $this->userId();
        $client = $this->clientConfig();
        $state = 'none';
        if ($this->principals()->get($userId) !== null) {
            // R18: fetched before any vault lock, and wiped: the page carries no secret but $shown.
            $sk = $this->vaultSession()->secretKey();
            $state = $sk === null ? 'locked' : 'unlocked';
            if ($sk !== null) {
                sodium_memzero($sk);
            }
        }
        $this->respond()->html($this->helper->layout->app('Vault:vault/agents', [
            'title' => t('Vault access for my agents'),
            'client' => $client,
            'https_ok' => $this->vaultSession()->transportAllowed(),
            'available' => AgentRoster::of($this->container)->available(),
            'agents' => $this->agentVault()->agentsOf($userId),
            'owner_state' => $state,
            'cap_max' => (int) (new VaultSettings($this->container))->get('vault_agent_cap_max'),
            'error' => $this->codeMessage('vault_error', $client['messages']),
            'notice' => $this->request->getStringParam('vault_notice') === 'saved' ? $client['messages']['saved'] : '',
            'shown_agent' => (int) ($shown['agent_id'] ?? 0),
            'shown_key' => (string) ($shown['key'] ?? ''),
        ]));
    }

    private function agentVault(): AgentVault
    {
        return AgentVault::of($this->container);
    }
}
