<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\GranteeDirectory;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ServerGrant;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Model\VaultException;

// The sharing dialog, revoke and the activity view (spec: UI → The sharing dialog; Entries, groups and grants; Audit →
// Who sees what). All are POSTs with the CSRF token, from an unlocked session, answered with JSON through respond()
// (no-store, XFO DENY, frame-ancestors), with the generic failures of handle().
//
//   vault/sharing   {type, id}                       → {grants: [{grantee_id, name, kind, permission, expires_at}],
//                                                        candidates: [{id, name, kind}], covered_entries (group),
//                                                        server: {available}}
//                     the Server grant (grantee -1)   → {grantee_id: -1, name, kind: server, permission, consumers,
//                                                        fields, rate_per_hour, rate_burst}
//   vault/grant-server {id, consumers, fields[], custom_fields, rate_per_hour?, rate_burst?}
//                                                    → {}; then afterWrite
//   vault/grant     {type, id, grantee_id, perm: read|edit, expires_at?, confirm?}
//                     a group without confirm         → {confirm_required: true, covered_entries}; nothing granted
//                     otherwise                       → {covered_entries (group)}; then afterWrite
//   vault/revoke    {type, id, grantee_id}           → {suggest_rotate: true}; then afterWrite. grantee_id -1 is the
//                                                        Server grant (no directory check: revoke never has one)
//   vault/activity  {offset}                         → {rows, next_offset}; ACTIVITY_PAGE rows a page
//
// Only the owner may see the sharing view, grant or revoke: that is GrantModel's gate (not_found for anyone else, so an
// object that isn't yours looks like no object). A grantee must be inside the actor's picker scope (GranteeDirectory,
// the same scope Kanboard's own member pickers use; not_found otherwise) and enrolled (not_enrolled). Agents get read
// only (agent_read_only, GrantModel). An expiry is a Unix time in the future (payload_invalid otherwise).
//
// The activity view shows exactly AuditModel::visibleTo's rows for the logged-in user, newest first, with names for
// the actor and target and an object title only when this viewer can decrypt that object now.
//
// Server (spec amendment): sharing offers Server only for an entry while Server is on. A Server grant shows its
// consumers, its fields and its rates. R1: custom field names are stored as MACs; the sharing and activity views map
// them back to the entry's plain names with the viewer's key, and a MAC that matches no field (renamed or removed, or
// Server off) is null. A MAC never reaches the browser.
class ShareGrantController extends BaseVaultController
{
    public const ACTIVITY_PAGE = 50;

    public function sharing(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $type = $this->type();
            $serverOn = ServerPrincipal::of($this->container)->isOn();
            // The sk maps a Server grant's MACs back to names; Server off means no Server grant, so no key file read.
            $view = $this->grants()->sharing($userId, $type, $this->intParam('id') ?? 0, $serverOn ? $sk : null);
            $names = [];
            $grants = array_map(fn (array $g): array => $g['kind'] === 'server' ? [
                'grantee_id' => ServerPrincipal::ID,
                'name' => t('Server'),
                'kind' => 'server',
                'permission' => $g['permission'],
                'consumers' => $g['consumers'],
                'fields' => array_map(self::shownField(...), $g['fields']),
                'rate_per_hour' => $g['rate_per_hour'],
                'rate_burst' => $g['rate_burst'],
            ] : [
                'grantee_id' => $g['grantee_id'],
                'name' => $names[$g['grantee_id']] ??= $this->userName($g['grantee_id']),
                'kind' => $g['kind'],
                'permission' => $g['permission'],
                'expires_at' => $g['expires_at'],
            ], $view['grants']);
            $this->answer(['grants' => $grants, 'candidates' => $this->directory()->candidates($userId)]
                + (isset($view['covered_entries']) ? ['covered_entries' => $view['covered_entries']] : [])
                + ['server' => ['available' => $serverOn && $type === 'entry']]);
        });
    }

    // Spec amendment, The sharing dialog: the owner (unlocked) shares one entry with Server. The endpoint takes an entry
    // id only (any other type is not_found). Consumers are split on commas and whitespace, the fields are the checked
    // top-level keys (fields[]) plus the comma-separated custom field names, and the rates are optional decimal ints.
    // GrantModel::grantServer validates all of it (payload_invalid), checks the owner (not_found) and Server (server_off).
    public function grantServer(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $type = $this->request->getRawValue('type');
            if ($type !== null && $type !== 'entry') {
                throw new VaultException('not_found');
            }
            $consumers = $this->request->getRawValue('consumers');
            $fields = $this->request->getRawValue('fields') ?? [];
            $custom = $this->request->getRawValue('custom_fields') ?? '';
            if (! is_string($consumers) || ! is_array($fields) || ! array_is_list($fields) || ! is_string($custom)) {
                throw new VaultException('payload_invalid');
            }
            $custom = array_values(array_filter(array_map('trim', explode(',', $custom)), static fn (string $f): bool => $f !== ''));
            $this->grants()->grantServer(
                $userId,
                $this->intParam('id') ?? 0,
                preg_split('/[\s,]+/', $consumers, -1, PREG_SPLIT_NO_EMPTY),
                [...$fields, ...$custom],
                $this->intParam('rate_per_hour'),
                $this->intParam('rate_burst'),
                $sk
            );
            $this->housekeeping()->afterWrite($userId, $sk);
            $this->answer([]);
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
            // intParam reads only non-negative ids; -1 is the Server grant.
            $raw = $this->request->getRawValue('grantee_id');
            $granteeId = $raw === (string) ServerPrincipal::ID || $raw === ServerPrincipal::ID ? ServerPrincipal::ID : ($this->intParam('grantee_id') ?? 0);
            $this->grants()->revoke($userId, $this->type(), $this->intParam('id') ?? 0, $granteeId, $sk);
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
            $fieldNames = [];
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
                    'consumer' => $r['consumer'],
                    'field_name' => $this->activityField($userId, $r, $sk, $fieldNames),
                    'entry_version' => $r['entry_version'],
                    'reason' => $r['reason'],
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

    // A Server read row's field as this viewer may see it: a top-level name as is; a MAC as the entry's plain name,
    // looked up once per entry, or null when it matches none.
    private function activityField(int $userId, array $r, #[\SensitiveParameter] string $sk, array &$cache): ?string
    {
        $f = $r['field_name'];
        if (! ServerGrant::isMac($f)) {
            return $f;
        }
        if ($r['object_type'] !== 'entry') {
            return null;
        }
        $id = (int) $r['object_id'];
        $cache[$id] ??= $this->grants()->fieldNamesByMac($userId, $id, $sk);
        return $cache[$id][$f] ?? null;
    }

    // R1: a field the sharing view could not map back is still a MAC; it is shown as unknown (null), never as the MAC.
    private static function shownField(string $f): ?string
    {
        return ServerGrant::isMac($f) ? null : $f;
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
