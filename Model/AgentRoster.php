<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Core\Base;
use Throwable;

// The single source for "is this Kanboard user an agent" (spec: Agents, "Vault decides who is an agent with
// AgentTable roster membership, behind a class_exists guard"). Every Vault model asks here: GrantModel (the Read-only
// cap, R47), PrincipalModel (no human enrolment for an agent), GranteeDirectory (the actor's own agents), AuditModel
// (an owner sees their agents' rows) and Notifier (the agent's owner gets its notices).
//
// Without Agents, or when its roster can't be read, nobody is on the roster: every answer is the empty one (fewer
// rows shown, fewer notices). Callers that refuse something to agents also check the principal's own kind, so an
// unreadable roster never widens what an enrolled agent principal may get.
class AgentRoster extends Base
{
    private const AGENT_TABLE = '\Kanboard\Plugin\Agents\Model\AgentTable';

    private string $rosterClass;

    // $rosterClass: the class whose presence means Agents is installed (tests name a missing one).
    public function __construct($container, string $rosterClass = self::AGENT_TABLE)
    {
        parent::__construct($container);
        $this->rosterClass = $rosterClass;
    }

    // The container's roster ('vaultAgentRoster', which tests may set) or a new one.
    public static function of($container): self
    {
        return isset($container['vaultAgentRoster']) ? $container['vaultAgentRoster'] : new self($container);
    }

    // Is the Agents plugin installed (the spec's class_exists guard)? Without it the agent API refuses with
    // agents_unavailable and nobody is an agent.
    public function available(): bool
    {
        return class_exists($this->rosterClass);
    }

    public function isAgent(int $userId): bool
    {
        return $this->query('SELECT 1 AS x FROM agents WHERE agent_user_id = ?', [$userId]) !== [];
    }

    /** @return list<int> the owner's agents */
    public function agentsOf(int $ownerId): array
    {
        return array_map('intval', array_column($this->query('SELECT agent_user_id FROM agents WHERE owner_user_id = ?', [$ownerId]), 'agent_user_id'));
    }

    public function ownerOf(int $agentId): ?int
    {
        $rows = $this->query('SELECT owner_user_id FROM agents WHERE agent_user_id = ?', [$agentId]);
        return $rows === [] ? null : (int) $rows[0]['owner_user_id'];
    }

    /** @return list<array<string,mixed>> */
    private function query(string $sql, array $params): array
    {
        if (! $this->available()) {
            return [];
        }
        try {
            return (new VaultDb($this->container))->fetchAll($sql, $params);
        } catch (Throwable) {
            return [];
        }
    }
}
