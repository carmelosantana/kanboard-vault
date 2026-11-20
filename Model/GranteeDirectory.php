<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Core\Base;
use Kanboard\Core\Security\Role;

// Who the sharing dialog may offer (spec: UI → The sharing dialog: "a user or an enrolled agent"). The picker never
// shows more of the user directory than Kanboard already shows the actor:
//
//   - Kanboard's own member pickers (the @mention list, the assignee list) offer the members of a project the actor
//     is in. So does this: every user who shares a project with the actor, directly or through a Kanboard group.
//   - The actor's own agents (Agents' roster, behind a class_exists guard), which Agents already shows their owner.
//   - An app admin sees Kanboard's whole user list (UserListController is admin only), so an admin is offered every
//     user.
//
// Of those, only active Kanboard users with a live vault principal are offered (a grantee must be enrolled). The same
// scope gates a grant: visible() is checked before the grant, so a user id outside it is the generic not_found, and an
// id that is visible but not enrolled is GrantModel's not_enrolled. Revoking needs no picker and isn't gated here.
class GranteeDirectory extends Base
{
    /** @return list<array{id:int, name:string, kind:string}> sorted by name, then id; never the actor */
    public function candidates(int $actorId): array
    {
        $ids = $this->scope($actorId);
        if ($ids === []) {
            return [];
        }
        $out = [];
        foreach (array_chunk($ids, 500) as $chunk) {
            $rows = (new VaultDb($this->container))->fetchAll(
                'SELECT u.id, u.username, u.name, p.kind FROM users u JOIN vault_principals p ON p.user_id = u.id
                 WHERE u.is_active = ? AND p.live_user_id IS NOT NULL AND u.id IN ('.RecipientResolver::marks($chunk).')',
                array_merge([1], $chunk)
            );
            foreach ($rows as $r) {
                $out[] = [
                    'id' => (int) $r['id'],
                    'name' => (string) ($r['name'] !== null && $r['name'] !== '' ? $r['name'] : $r['username']),
                    'kind' => $r['kind'] === 'agent' ? 'agent' : 'human',
                ];
            }
        }
        usort($out, static fn (array $a, array $b): int => [strtolower($a['name']), $a['id']] <=> [strtolower($b['name']), $b['id']]);
        return $out;
    }

    // Whether $userId is an active user inside the actor's picker scope (enrolled or not: enrolment is GrantModel's).
    public function visible(int $actorId, int $userId): bool
    {
        if ($userId <= 0 || $userId === $actorId || ! in_array($userId, $this->scope($actorId), true)) {
            return false;
        }
        return (bool) $this->userModel->isActive($userId);
    }

    /** @return list<int> the user ids the actor may see, without the actor */
    private function scope(int $actorId): array
    {
        $actor = $this->userModel->getById($actorId);
        if (! $actor || (int) $actor['is_active'] !== 1) {
            return [];
        }
        if ($actor['role'] === Role::APP_ADMIN) {
            $ids = array_map('intval', array_column((new VaultDb($this->container))->fetchAll('SELECT id FROM users'), 'id'));
        } else {
            $ids = AgentRoster::of($this->container)->agentsOf($actorId);
            foreach ($this->projectPermissionModel->getProjectIds($actorId) as $projectId) {
                foreach ($this->projectPermissionModel->getMembers($projectId) as $member) {
                    $ids[] = (int) $member['id'];
                }
            }
        }
        return array_values(array_diff(array_unique($ids), [$actorId]));
    }
}
