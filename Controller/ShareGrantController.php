<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\GranteeDirectory;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\VaultException;

// The sharing dialog, revoke and the activity view (spec: UI → The sharing dialog; Entries, groups and grants; Audit →
// Who sees what). All are POSTs with the CSRF token, from an unlocked session, answered with JSON through respond()
// (no-store, XFO DENY, frame-ancestors), with the generic failures of handle().
//
//   vault/sharing   {type, id}                       → {grants: [{grantee_id, name, kind, permission, expires_at}],
//                                                        candidates: [{id, name, kind}], covered_entries (group)}
//   vault/grant     {type, id, grantee_id, perm: read|edit, expires_at?, confirm?}
//                     a group without confirm         → {confirm_required: true, covered_entries}; nothing granted
//                     otherwise                       → {covered_entries (group)}; then afterWrite
//   vault/revoke    {type, id, grantee_id}           → {suggest_rotate: true}; then afterWrite
//   vault/activity  {offset}                         → {rows, next_offset}; ACTIVITY_PAGE rows a page
//
// Only the owner may see the sharing view, grant or revoke: that is GrantModel's gate (not_found for anyone else, so an
// object that isn't yours looks like no object). A grantee must be inside the actor's picker scope (GranteeDirectory,
// the same scope Kanboard's own member pickers use; not_found otherwise) and enrolled (not_enrolled). Agents get read
// only (agent_read_only, GrantModel). An expiry is a Unix time in the future (payload_invalid otherwise).
//
// The activity view shows exactly AuditModel::visibleTo's rows for the logged-in user, newest first, with names for
// the actor and target and an object title only when this viewer can decrypt that object now.
class ShareGrantController extends BaseVaultController
{
    public const ACTIVITY_PAGE = 50;

    public function sharing(): void
    {
        $this->withKey(function (int $userId): void {
            $view = $this->grants()->sharing($userId, $this->type(), $this->intParam('id') ?? 0);
            $names = [];
            $grants = array_map(fn (array $g): array => [
                'grantee_id' => $g['grantee_id'],
                'name' => $names[$g['grantee_id']] ??= $this->userName($g['grantee_id']),
                'kind' => $g['kind'],
                'permission' => $g['permission'],
                'expires_at' => $g['expires_at'],
            ], $view['grants']);
            $this->answer(['grants' => $grants, 'candidates' => $this->directory()->candidates($userId)]
                + (isset($view['covered_entries']) ? ['covered_entries' => $view['covered_entries']] : []));
        });
    }

    public function grant(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $type = $this->type();
            $id = $this->intParam('id') ?? 0;
            $granteeId = $this->intParam('grantee_id') ?? 0;
            $perm = (string) $this->request->getRawValue('perm');
            $expiresAt = $this->expiresAt();
            if (! in_array($perm, GrantModel::PERMISSIONS, true)) {
                throw new VaultException('payload_invalid');
            }
            if (! $this->directory()->visible($userId, $granteeId)) {
                throw new VaultException('not_found');
            }
            // Spec: sharing a group warns how many entries it covers. The first request only counts (owner only).
            if ($type === 'group' && ! $this->request->getRawValue('confirm')) {
                $this->answer(['confirm_required' => true, 'covered_entries' => $this->grants()->coveredCount($userId, $id)]);
                return;
            }
            $this->grants()->grant($userId, $type, $id, $granteeId, $perm, $expiresAt, $sk);
            $this->housekeeping()->afterWrite($userId, $sk);
            $this->answer($type === 'group' ? ['covered_entries' => $this->grants()->coveredCount($userId, $id)] : []);
        });
    }

    // Spec, Revocation: "Afterwards the UI suggests rotating the secrets themselves."
    public function revoke(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $this->grants()->revoke($userId, $this->type(), $this->intParam('id') ?? 0, $this->intParam('grantee_id') ?? 0, $sk);
            $this->housekeeping()->afterWrite($userId, $sk);
            $this->answer(['suggest_rotate' => true]);
        });
    }

    public function activity(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $offset = $this->intParam('offset') ?? 0;
            $rows = AuditModel::of($this->container)->visibleTo($userId, $offset, self::ACTIVITY_PAGE + 1);
            $more = count($rows) > self::ACTIVITY_PAGE;
            $names = [];
            $titles = [];
            $out = [];
            foreach (array_slice($rows, 0, self::ACTIVITY_PAGE) as $r) {
                $object = $r['object_type'] === null ? null : $r['object_type'].':'.$r['object_id'];
                if ($object !== null && ! array_key_exists($object, $titles)) {
                    $titles[$object] = $this->title($userId, (string) $r['object_type'], (int) $r['object_id'], $sk);
                }
                $out[] = [
                    'id' => $r['id'],
                    'created_at' => $r['created_at'],
                    'action' => $r['action'],
                    'actor_kind' => $r['actor_kind'],
                    'via' => $r['via'],
                    'actor' => $r['actor_user_id'] === null ? null : ($names[$r['actor_user_id']] ??= $this->userName($r['actor_user_id'])),
                    'target' => $r['target_user_id'] === null ? null : ($names[$r['target_user_id']] ??= $this->userName($r['target_user_id'])),
                    'object_type' => $r['object_type'],
                    'object_id' => $r['object_id'],
                    'title' => $object === null ? null : $titles[$object],
                    'count' => $r['count'],
                    'ip_trunc' => $r['ip_trunc'],
                    'ua_family' => $r['ua_family'],
                ];
            }
            $this->answer(['rows' => $out, 'next_offset' => $more ? $offset + self::ACTIVITY_PAGE : null]);
        });
    }

    // Spec: "Object titles are decrypted for display only for a viewer who holds that object's DEK." The read path's own
    // checks decide (live grants, current key); anything it refuses, or an object since deleted, has no title.
    private function title(int $userId, string $type, int $id, #[\SensitiveParameter] string $sk): ?string
    {
        try {
            if ($type === 'entry') {
                $payload = $this->store()->readEntry($userId, $id, $sk)['payload'];
                $title = (string) ($payload['title'] ?? '');
            } else {
                $payload = $this->store()->readGroup($userId, $id, $sk)['payload'];
                $title = (string) ($payload['name'] ?? '');
            }
            unset($payload);
            return $title;
        } catch (VaultException) {
            return null;
        }
    }

    // An optional Unix time: absent or empty is no expiry; anything but decimal digits is payload_invalid. GrantModel
    // refuses one that isn't in the future.
    private function expiresAt(): ?int
    {
        $raw = $this->request->getRawValue('expires_at');
        if ($raw === null || $raw === '') {
            return null;
        }
        if (is_int($raw) && $raw > 0) {
            return $raw;
        }
        if (! is_string($raw) || ! ctype_digit($raw) || strlen($raw) > 12) {
            throw new VaultException('payload_invalid');
        }
        return (int) $raw;
    }

    private function directory(): GranteeDirectory
    {
        return new GranteeDirectory($this->container);
    }
}
