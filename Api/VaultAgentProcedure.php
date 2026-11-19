<?php
namespace Kanboard\Plugin\Vault\Api;

use Kanboard\Api\Procedure\BaseProcedure;
use Kanboard\Plugin\Vault\Model\AgentVault;

// The agent JSON-RPC API (spec: Agents → Methods). Each method answers {ok: true, ...} or {ok: false, reason}; all the
// work, authentication included, is AgentVault's.
//
// Kanboard's procedure handler (withObject) makes EVERY method of this object remotely callable, private ones included,
// and lets a core procedure win a name clash; its API ACL keys on the short class name. So this class holds only these
// four RPC methods, under a Vault-prefixed name no core procedure uses, and its parameters carry no type hints (a
// TypeError would be a fatal with no JSON-RPC body).
class VaultAgentProcedure extends BaseProcedure
{
    public function getVaultEntries($group_id = 0)
    {
        return AgentVault::of($this->container)->call(fn (int $agentId, #[\SensitiveParameter] string $sk): array => [
            'entries' => AgentVault::of($this->container)->entries($agentId, $sk, AgentVault::id($group_id)),
        ]);
    }

    public function getVaultSecret($entry_id, $field = 'password')
    {
        return AgentVault::of($this->container)->call(fn (int $agentId, #[\SensitiveParameter] string $sk, string $ip): array => [
            'value' => AgentVault::of($this->container)->readSecret($agentId, $sk, AgentVault::id($entry_id), $field, $ip),
        ]);
    }

    public function createVaultEntry(#[\SensitiveParameter] $fields)
    {
        return AgentVault::of($this->container)->call(function (int $agentId, #[\SensitiveParameter] string $sk) use ($fields): array {
            $vault = AgentVault::of($this->container);
            $id = $vault->createEntry($agentId, $fields);
            $vault->afterWrite($agentId, $sk);
            return ['entry_id' => $id];
        });
    }

    public function updateVaultEntry($entry_id, $expected_version, #[\SensitiveParameter] $fields)
    {
        return AgentVault::of($this->container)->call(function (int $agentId, #[\SensitiveParameter] string $sk) use ($entry_id, $expected_version, $fields): array {
            $vault = AgentVault::of($this->container);
            $version = $vault->updateEntry($agentId, $sk, AgentVault::id($entry_id), AgentVault::id($expected_version), $fields);
            $vault->afterWrite($agentId, $sk);
            return ['version' => $version];
        });
    }
}
