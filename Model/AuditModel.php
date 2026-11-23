<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use Kanboard\Core\Base;
use Kanboard\Core\Security\Role;
use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;
use LogicException;

// The audit log (spec: Audit). vault_audit is append-only: rows are inserted here and deleted only by purge()
// (retention). Each action may fill only the columns ALLOW lists for it; record() throws a LogicException on an
// unknown action, an unknown column, or a non-null value in a column the action may not use, and never drops a
// value. There is no free-form column.
//
// record() writes through VaultDb (R13), so called inside the vault lock it is part of the change's transaction:
// a rolled-back change leaves no audit row, and a failed audit write rolls the change back. Called outside a lock
// it is a single autocommitted insert. It is never called inside the shared lock (on SQLite that would upgrade a
// read transaction to a write).
//
// actor_kind and via: a column given by the caller wins, then this model's context (constructor), then the
// process: a CLI process is cli/cli; a web request is api for JSON-RPC, ui otherwise, and the actor is an agent
// when its principal is one, the system when there is no actor (R39), human otherwise.
class AuditModel extends Base
{
    private const SESSION = ['actor_user_id', 'ip_trunc', 'ua_family'];
    private const OBJECT = ['actor_user_id', 'object_type', 'object_id'];
    // Spec amendment (Server): a consumer's read, a grant or revoke to Server, and a refused admin action.
    private const SERVER_READ = ['object_type', 'object_id', 'field_name', 'entry_version', 'consumer', 'job_ref', 'correlation_id'];
    private const SERVER_GRANT = ['actor_user_id', 'object_type', 'object_id', 'consumers', 'fields', 'correlation_id'];
    private const DENIED = ['actor_user_id', 'object_type', 'object_id', 'reason', 'correlation_id'];

    // The spec's per-action table, verbatim.
    public const ALLOW = [
        'enroll' => ['actor_user_id'],
        'lock' => ['actor_user_id'],
        'hw_key_add' => ['actor_user_id'],
        'hw_key_remove' => ['actor_user_id'],
        'recovery_code_create' => ['actor_user_id'],
        'unlock' => self::SESSION,
        'unlock_failed' => self::SESSION,
        'recovery_used' => self::SESSION,
        'hw_signcount' => self::SESSION,
        'read' => ['actor_user_id', 'object_type', 'object_id', 'ip_trunc'],
        'create' => self::OBJECT,
        'update' => self::OBJECT,
        'delete' => self::OBJECT,
        'rekey' => self::OBJECT,
        'grant' => [...self::OBJECT, 'target_user_id'],
        'revoke' => [...self::OBJECT, 'target_user_id'],
        'rotate' => ['actor_user_id', 'count'],
        'import' => ['actor_user_id', 'count'],
        'export' => ['actor_user_id', 'count'],
        'share_create' => ['actor_user_id', 'share_hash'],
        'share_revoke' => ['actor_user_id', 'share_hash'],
        'share_reveal' => ['target_user_id', 'share_hash', 'ip_trunc', 'ua_family'],
        'share_expire' => ['target_user_id', 'share_hash'],
        'rate_limited' => ['target_user_id', 'ip_trunc', 'count'],
        'bad_vault_key' => ['actor_user_id', 'ip_trunc'],
        'org_recovery' => ['target_user_id'],
        'policy_change' => ['actor_user_id'],
        // R37 (spec addendum at T25): an object the rotation sweep keeps for an integrity fault, so it is
        // operator-visible (R31's safety relies on it).
        'integrity_error' => self::OBJECT,
        // R72 (spec addendum at T24b): an unlock or recovery-code use refused while a Steward switch-user session is
        // active (SwitchedSessionGuard). Not a failed guess: no streak, no back-off.
        'unlock_refused' => self::SESSION,
        // Codex security round 1: an agent enrolment refused because the principal still owns objects outside its
        // Agent-created group (actor the owner, target the agent, count the objects).
        'enroll_refused' => ['actor_user_id', 'target_user_id', 'count'],
        // Spec amendment: the Server and orphan actions, and (P1) their denied variants.
        'server_read' => self::SERVER_READ,
        // R3: a rate_limited read denial is one row per bucket and window with its count (like R39's rate_limited);
        // every other denial is one row per refusal, without a count.
        'server_read_denied' => [...self::SERVER_READ, 'reason', 'count'],
        'server_grant' => self::SERVER_GRANT,
        'server_grant_denied' => self::DENIED,
        'server_revoke' => self::SERVER_GRANT,
        'server_revoke_denied' => self::DENIED,
        'orphan_quarantine' => ['object_type', 'object_id', 'old_owner_id', 'correlation_id'],
        'orphan_claim' => ['actor_user_id', 'object_type', 'object_id', 'old_owner_id', 'new_owner_id', 'key_epoch', 'correlation_id'],
        'orphan_claim_denied' => self::DENIED,
        'orphan_destroy' => ['actor_user_id', 'object_type', 'object_id', 'old_owner_id', 'correlation_id'],
        'orphan_destroy_denied' => self::DENIED,
    ];
    // The columns an action may fill; id, created_at, action, actor_kind and via are on every row.
    public const COLUMNS = ['actor_user_id', 'object_type', 'object_id', 'share_hash', 'target_user_id', 'ip_trunc', 'ua_family', 'count',
        'consumer', 'field_name', 'entry_version', 'job_ref', 'correlation_id', 'reason', 'consumers', 'fields', 'old_owner_id', 'new_owner_id', 'key_epoch'];
    // A denied row's reason: a consumer read's refusal, or a grant, revoke, claim or destroy refused.
    public const REASONS = [...ServiceSecretException::REASONS, 'not_allowed', 'payload_invalid', 'not_enrolled'];
    // 'system' (R39, spec addendum at T25): an action with no actor in a web request, such as a share expiry or a
    // rate-limit summary written by the opportunistic purge.
    // 'server' (spec amendment): the Server principal reading for a consumer.
    public const ACTOR_KINDS = ['human', 'agent', 'public', 'cli', 'system', 'server'];
    public const VIAS = ['ui', 'api', 'cli'];
    // "App admins see policy_change, org_recovery and aggregate counts."
    // Spec amendment: admins decide orphans (claim or destroy), so they see every orphan row.
    public const ADMIN_ACTIONS = ['policy_change', 'org_recovery', 'orphan_quarantine', 'orphan_claim', 'orphan_claim_denied',
        'orphan_destroy', 'orphan_destroy_denied'];
    // Actions whose target_user_id is the viewer's own share or rate-limit bucket ("the share is theirs").
    private const TARGET_OWNS = ['share_reveal', 'share_expire', 'rate_limited'];
    public const PAGE_LIMIT = 200;

    // T10 carry, pinned to T17's formats: share_hash is ShareModel::idHash (64 lowercase hex), so a raw share id or
    // burn capability (32 hex) or a share key can never be recorded; ip_trunc is exactly ClientIp::truncate's output;
    // ua_family exactly UaFamily's.
    private const SHARE_HASH = ShareModel::ID_HASH_PATTERN;
    private const JOB_REF = '/^[A-Za-z0-9_.:-]{1,64}$/D';

    private ?string $actorKind;
    private ?string $via;
    private Closure $clock;

    public function __construct($container, ?string $actorKind = null, ?string $via = null, ?callable $clock = null)
    {
        parent::__construct($container);
        if ($actorKind !== null && ! in_array($actorKind, self::ACTOR_KINDS, true)) {
            throw new LogicException('Vault audit: unknown actor_kind');
        }
        if ($via !== null && ! in_array($via, self::VIAS, true)) {
            throw new LogicException('Vault audit: unknown via');
        }
        $this->actorKind = $actorKind;
        $this->via = $via;
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    // The container's audit log ('vaultAudit', registered by the plugin) or a new one with this clock.
    public static function of($container, ?callable $clock = null): self
    {
        return isset($container['vaultAudit']) ? $container['vaultAudit'] : new self($container, null, null, $clock);
    }

    public function record(string $action, array $cols): void
    {
        $this->vdb()->insert('vault_audit', $this->row($action, $cols));
    }

    // Who sees what (spec): rows where the viewer is the actor; rows on an object the viewer owns; share and
    // rate-limit rows whose target is the viewer; the rows of the viewer's agents (Agents' roster); and for app
    // admins, policy_change and org_recovery. Newest first, at most PAGE_LIMIT per page. Object titles are not
    // here: the UI decrypts them only for a viewer who holds the DEK.
    /** @return list<array<string,int|string|null>> */
    public function visibleTo(int $viewerId, int $offset, int $limit): array
    {
        if ($viewerId <= 0) {
            return [];
        }
        $offset = max(0, $offset);
        $limit = max(1, min(self::PAGE_LIMIT, $limit));
        $people = array_values(array_unique([$viewerId, ...AgentRoster::of($this->container)->agentsOf($viewerId)]));
        $in = RecipientResolver::marks($people);
        $targets = RecipientResolver::marks(self::TARGET_OWNS);
        $where = [
            'a.actor_user_id IN ('.$in.')',
            "(a.object_type = 'entry' AND a.object_id IN (SELECT e.id FROM vault_entries e WHERE e.owner_id = ?))",
            "(a.object_type = 'group' AND a.object_id IN (SELECT g.id FROM vault_groups g WHERE g.owner_id = ?))",
            '(a.action IN ('.$targets.') AND a.target_user_id IN ('.$in.'))',
        ];
        $params = [...$people, $viewerId, $viewerId, ...self::TARGET_OWNS, ...$people];
        if ($this->isAdmin($viewerId)) {
            $where[] = 'a.action IN ('.RecipientResolver::marks(self::ADMIN_ACTIONS).')';
            array_push($params, ...self::ADMIN_ACTIONS);
        }
        $rows = $this->vdb()->fetchAll(
            'SELECT a.* FROM vault_audit a WHERE '.implode(' OR ', $where).' ORDER BY a.id DESC LIMIT '.$limit.' OFFSET '.$offset,
            $params
        );
        return array_map(self::typed(...), $rows);
    }

    // Rows per action across the whole log, for app admins; empty for anyone else.
    /** @return array<string,int> */
    public function aggregateCounts(int $viewerId): array
    {
        if (! $this->isAdmin($viewerId)) {
            return [];
        }
        $out = [];
        foreach ($this->vdb()->fetchAll('SELECT action, COUNT(*) AS n FROM vault_audit GROUP BY action ORDER BY action') as $r) {
            $out[(string) $r['action']] = (int) $r['n'];
        }
        return $out;
    }

    // R8/R31/R37: the objects the rotation sweep kept for an integrity fault, for app admins (empty for anyone else):
    // how many distinct objects, and up to $limit of them as type and id with the last time seen. Nothing else
    // (no actor, no title): the admin learns that an object needs attention, not what it holds.
    /** @return array{count:int, objects:list<array{object_type:string,object_id:int,last_at:int}>} */
    public function integrityFaults(int $viewerId, int $limit = 50): array
    {
        if (! $this->isAdmin($viewerId)) {
            return ['count' => 0, 'objects' => []];
        }
        $db = $this->vdb();
        $count = $db->fetchOne("SELECT COUNT(*) AS n FROM (SELECT DISTINCT object_type, object_id FROM vault_audit WHERE action = 'integrity_error') t");
        $rows = $db->fetchAll(
            "SELECT object_type, object_id, MAX(created_at) AS last_at FROM vault_audit WHERE action = 'integrity_error'"
            .' GROUP BY object_type, object_id ORDER BY last_at DESC, object_type, object_id LIMIT '.max(1, min(self::PAGE_LIMIT, $limit))
        );
        return [
            'count' => (int) ($count['n'] ?? 0),
            'objects' => array_map(static fn (array $r): array => ['object_type' => (string) $r['object_type'], 'object_id' => (int) $r['object_id'], 'last_at' => (int) $r['last_at']], $rows),
        ];
    }

    // Retention: deletes rows older than $retentionDays. Returns how many went.
    public function purge(int $retentionDays): int
    {
        if ($retentionDays < 1) {
            throw new InvalidArgumentException('Vault audit: retention must be at least one day');
        }
        return $this->vdb()->execute('DELETE FROM vault_audit WHERE created_at < ?', [$this->now() - $retentionDays * 86400]);
    }

    // The validated row to insert. Error messages name the action and column, never a value.
    private function row(string $action, array $cols): array
    {
        if (! isset(self::ALLOW[$action])) {
            throw new LogicException('Vault audit: unknown action');
        }
        $context = ['actor_kind' => $cols['actor_kind'] ?? null, 'via' => $cols['via'] ?? null];
        unset($cols['actor_kind'], $cols['via']);
        $row = ['created_at' => $this->now(), 'action' => $action];
        foreach (array_keys($cols) as $column) {
            if (! in_array($column, self::COLUMNS, true)) {
                throw new LogicException('Vault audit: unknown column '.$column);
            }
        }
        if (in_array('correlation_id', self::ALLOW[$action], true)) {
            $cols['correlation_id'] ??= Correlation::id();
        }
        foreach (self::COLUMNS as $column) {
            $value = $cols[$column] ?? null;
            if ($value !== null && ! in_array($column, self::ALLOW[$action], true)) {
                throw new LogicException('Vault audit: '.$action.' may not fill '.$column);
            }
            $this->check($column, $value);
            $row[$column] = $value;
        }
        if ($row['count'] !== null && $action === 'server_read_denied' && $row['reason'] !== 'rate_limited') {
            throw new LogicException('Vault audit: server_read_denied count needs reason rate_limited');
        }
        $row['via'] = $context['via'] ?? $this->via ?? $this->processVia();
        $row['actor_kind'] = $context['actor_kind'] ?? $this->actorKind ?? $this->deriveActorKind($row['via'], $row['actor_user_id']);
        if (! in_array($row['via'], self::VIAS, true)) {
            throw new LogicException('Vault audit: unknown via');
        }
        if (! in_array($row['actor_kind'], self::ACTOR_KINDS, true)) {
            throw new LogicException('Vault audit: unknown actor_kind');
        }
        return $row;
    }

    private function check(string $column, mixed $value): void
    {
        if ($value === null) {
            return;
        }
        $ok = match ($column) {
            'actor_user_id', 'object_id', 'target_user_id', 'old_owner_id', 'new_owner_id' => is_int($value) && $value > 0,
            'count' => is_int($value) && $value >= 0,
            'entry_version', 'key_epoch' => is_int($value) && $value >= 1,
            'consumer' => ServerGrant::validConsumer($value),
            'field_name' => ServerGrant::validField($value),
            'job_ref' => is_string($value) && preg_match(self::JOB_REF, $value) === 1,
            'correlation_id' => is_string($value) && preg_match(Correlation::PATTERN, $value) === 1,
            'reason' => in_array($value, self::REASONS, true),
            'consumers' => self::canonicalList($value, ServerGrant::consumers(...)),
            'fields' => self::canonicalList($value, ServerGrant::fields(...)),
            'object_type' => in_array($value, ObjectStore::TYPES, true),
            'ip_trunc' => is_string($value) && $value !== '' && (new ClientIp($this->container))->truncate(explode('/', $value)[0]) === $value,
            'share_hash' => is_string($value) && preg_match(self::SHARE_HASH, $value) === 1,
            'ua_family' => is_string($value) && UaFamily::isFamily($value),
        };
        if (! $ok) {
            throw new LogicException('Vault audit: invalid value for '.$column);
        }
    }

    // A stored consumers or fields value: the non-empty canonical list that $canon returns unchanged.
    private static function canonicalList(mixed $value, callable $canon): bool
    {
        try {
            $list = is_string($value) ? ServerGrant::decodeList($value) : [];
            return $list !== [] && $canon($list) === $list;
        } catch (LogicException|VaultException) {
            return false;
        }
    }

    private function processVia(): string
    {
        if (PHP_SAPI === 'cli') {
            return 'cli';
        }
        return (new VaultSession($this->container))->isApiRequest() ? 'api' : 'ui';
    }

    private function deriveActorKind(string $via, ?int $actorId): string
    {
        if ($via === 'cli') {
            return 'cli';
        }
        if ($actorId === null) {
            return 'system';
        }
        $p = $this->vdb()->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ?', [$actorId]);
        return $p !== null && $p['kind'] === 'agent' ? 'agent' : 'human';
    }

    private function isAdmin(int $userId): bool
    {
        $u = $this->vdb()->fetchOne('SELECT role, is_active FROM users WHERE id = ?', [$userId]);
        return $u !== null && $u['role'] === Role::APP_ADMIN && (int) $u['is_active'] === 1;
    }

    private static function typed(array $row): array
    {
        foreach (['id', 'created_at', 'actor_user_id', 'object_id', 'target_user_id', 'count', 'entry_version', 'old_owner_id', 'new_owner_id', 'key_epoch'] as $c) {
            if ($row[$c] !== null) {
                $row[$c] = (int) $row[$c];
            }
        }
        return $row;
    }

    private function vdb(): VaultDb
    {
        return new VaultDb($this->container);
    }

    private function now(): int
    {
        return (int) ($this->clock)();
    }
}
