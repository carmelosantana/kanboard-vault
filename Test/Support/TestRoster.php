<?php

use Kanboard\Plugin\Vault\Model\AgentRoster;

// A roster set by the test (agent user id → owner user id), with the Agents plugin present or not. Vault's own CI has
// no Agents checkout, so tests that need agents set this one as 'vaultAgentRoster'.
class VaultTestRoster extends AgentRoster
{
    public function __construct($container, private array $agents, private bool $present = true)
    {
        parent::__construct($container);
    }

    public function available(): bool
    {
        return $this->present;
    }

    public function isAgent(int $userId): bool
    {
        return $this->present && isset($this->agents[$userId]);
    }

    public function agentsOf(int $ownerId): array
    {
        return $this->present ? array_keys(array_filter($this->agents, fn (int $o): bool => $o === $ownerId)) : [];
    }

    public function ownerOf(int $agentId): ?int
    {
        return $this->present ? ($this->agents[$agentId] ?? null) : null;
    }
}
