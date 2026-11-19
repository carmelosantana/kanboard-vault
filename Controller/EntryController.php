<?php
namespace Kanboard\Plugin\Vault\Controller;

use InvalidArgumentException;
use JsonException;
use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\ClientIp;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\VaultException;

// The three-pane browser's endpoints (spec: UI, Secrets never go into the HTML; Audit: read). All are POSTs with the
// CSRF token, from an unlocked session, answered with JSON through respond() (no-store, XFO DENY, frame-ancestors).
//
//   vault/tree    {}                                   → {groups: [{id, parent_id, permission, shared_by, name |
//                                                          integrity_error}], shared_entries}
//   vault/list    {group_id, offset} | {shared, offset} → {entries: [metadata | {id, group_id, integrity_error}],
//                                                          next_offset}; 200 a page
//   vault/entry   {id}                                 → {entry: metadata, which secrets are set, custom field names}
//   vault/field   {id, field}                          → {value}: the one place a secret leaves the server; audited
//                                                          as read once the value has been read
//   vault/save    {type: entry|group, id?, version?, group_id?, parent_id?, payload}  → {id, version}
//   vault/move    {type, id, parent_id}                → {}   (owner only, R29)
//   vault/delete  {type, id}                           → {}   (owner only, unlocked, R25)
//
// Metadata is title, username, URL, tags, expiry, field names and times. Password, notes, the OTP seed and every
// custom field value (protected or not) only come from vault/field, as 'password', 'notes', 'otp' or
// 'field:<name>' (T6's convention). Authorisation is ObjectStore's and GrantModel's own gate in every case; a write
// by a read grantee is their not_found. Every write is followed by Housekeeping::afterWrite (rotation step, queue
// drain; never Rekeyer::rekey). The session key is fetched before any vault lock (R18) and wiped afterwards (R12).
class EntryController extends BaseVaultController
{
    public function tree(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $tree = $this->store()->tree($userId, $sk);
            $names = [];
            $groups = [];
            foreach ($tree['groups'] as $g) {
                $owner = $g['owner_id'];
                $item = [
                    'id' => $g['id'],
                    'parent_id' => $g['parent_id'],
                    'permission' => $g['permission'],
                    'shared_by' => $owner === $userId ? null : ($names[$owner] ??= $this->userName($owner)),
                ];
                $groups[] = $item + (isset($g['integrity_error']) ? ['integrity_error' => true] : ['name' => $g['name']]);
            }
            $this->answer(['groups' => $groups, 'shared_entries' => $tree['shared_entries']]);
        });
    }

    public function list(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $offset = max(0, $this->intParam('offset') ?? 0);
            $groupId = $this->request->getRawValue('shared') ? null : ($this->intParam('group_id') ?? 0);
            $page = $this->store()->listPage($userId, $groupId, $sk, $offset, ObjectStore::LIST_LIMIT);
            $this->answer(['entries' => $page['entries'], 'next_offset' => $page['more'] ? $offset + ObjectStore::LIST_LIMIT : null]);
        });
    }

    public function entry(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $id = $this->intParam('id') ?? 0;
            $e = $this->store()->readEntry($userId, $id, $sk);
            $p = $e['payload'];
            $entry = [
                'id' => $e['id'],
                'group_id' => $e['group_id'],
                'version' => $e['version'],
                'permission' => $this->store()->permission($userId, 'entry', $id),
                'title' => (string) ($p['title'] ?? ''),
                'username' => (string) ($p['username'] ?? ''),
                'url' => (string) ($p['url'] ?? ''),
                'tags' => array_values(array_map('strval', (array) ($p['tags'] ?? []))),
                'expires_at' => $p['expires_at'] ?? null,
                'created_at' => $e['created_at'],
                'updated_at' => $e['updated_at'],
                // Whether each secret is set, never its value.
                'secrets' => [
                    'password' => ($p['password'] ?? '') !== '',
                    'notes' => ($p['notes'] ?? '') !== '',
                    'otp' => ($p['otp'] ?? '') !== '',
                ],
                'fields' => array_map(static fn (array $f): array => ['name' => (string) $f['name'], 'protected' => (bool) $f['protected']], $p['fields'] ?? []),
            ];
            unset($p, $e);
            $this->answer(['entry' => $entry]);
        });
    }

    // Reveal and copy (spec): one field per request, then a read row (actor, entry, ip_trunc). The row is written only
    // once the value was read, and the value is sent only once the row is written.
    public function field(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $id = $this->intParam('id') ?? 0;
            $value = $this->store()->readField($userId, $id, (string) $this->request->getRawValue('field'), $sk);
            try {
                $ip = (new ClientIp($this->container))->truncate($this->clientIp());
                AuditModel::of($this->container)->record('read', [
                    'actor_user_id' => $userId,
                    'object_type' => 'entry',
                    'object_id' => $id,
                    'ip_trunc' => $ip === '' ? null : $ip,
                ]);
                $this->answer(['value' => $value]);
            } finally {
                sodium_memzero($value);
            }
        });
    }

    public function save(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $type = $this->type();
            $payload = $this->payload();
            $id = $this->intParam('id');
            $store = $this->store();
            if ($type === 'group') {
                if ($id !== null) {
                    throw new InvalidArgumentException('Vault: groups are not edited here');
                }
                $out = ['id' => $store->createGroup($userId, $this->intParam('parent_id'), $payload)];
            } elseif ($id === null) {
                $out = ['id' => $store->createEntry($userId, $this->intParam('group_id') ?? 0, $payload), 'version' => 1];
            } else {
                $out = ['id' => $id, 'version' => $store->updateEntry($userId, $id, $this->intParam('version') ?? 0, $payload, $sk)];
            }
            unset($payload);
            $this->housekeeping()->afterWrite($userId, $sk);
            $this->answer($out);
        });
    }

    public function move(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $this->grants()->move($userId, $this->type(), $this->intParam('id') ?? 0, $this->intParam('parent_id'), $sk);
            $this->housekeeping()->afterWrite($userId, $sk);
            $this->answer([]);
        });
    }

    public function delete(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $this->store()->deleteObject($userId, $this->type(), $this->intParam('id') ?? 0, $sk);
            $this->housekeeping()->afterWrite($userId, $sk);
            $this->answer([]);
        });
    }

    // POST + CSRF, then the unlocked session's key (fetched before any vault lock, R18), wiped whatever happens.
    private function withKey(callable $action): void
    {
        $this->handle(function () use ($action): void {
            $this->requirePostCsrf();
            $sk = $this->requireUnlocked();
            try {
                $action($this->userId(), $sk);
            } finally {
                sodium_memzero($sk);
            }
        });
    }

    private function answer(array $data): void
    {
        $this->respond()->json(['ok' => true] + $data);
    }

    // entry or group; anything else is the generic failure (T6 minor).
    private function type(): string
    {
        $type = (string) $this->request->getRawValue('type');
        if (! in_array($type, ObjectStore::TYPES, true)) {
            throw new InvalidArgumentException('Vault: unknown object type');
        }
        return $type;
    }

    // A decimal id, or null when absent or empty (a top-level group). Anything else matches no object.
    private function intParam(string $name): ?int
    {
        $raw = $this->request->getRawValue($name);
        if ($raw === null || $raw === '') {
            return null;
        }
        if (is_int($raw)) {
            return max(0, $raw);
        }
        return is_string($raw) && ctype_digit($raw) && strlen($raw) < 16 ? (int) $raw : 0;
    }

    // The editor's JSON object; EntryPayload validates its shape inside the store.
    private function payload(): array
    {
        $raw = $this->request->getRawValue('payload');
        try {
            $p = is_string($raw) ? json_decode($raw, true, 8, JSON_THROW_ON_ERROR) : null;
        } catch (JsonException) {
            throw new VaultException('payload_invalid');
        }
        if (! is_array($p) || array_is_list($p) && $p !== []) {
            throw new VaultException('payload_invalid');
        }
        return $p;
    }

    private function userName(int $userId): string
    {
        $user = $this->userModel->getById($userId);
        if (! $user) {
            return '';
        }
        return (string) ($user['name'] !== '' && $user['name'] !== null ? $user['name'] : $user['username']);
    }

    private function store(): ObjectStore
    {
        return isset($this->container['vaultStore']) ? $this->container['vaultStore'] : new ObjectStore($this->container);
    }

    private function grants(): GrantModel
    {
        return isset($this->container['vaultGrants']) ? $this->container['vaultGrants'] : new GrantModel($this->container);
    }
}
