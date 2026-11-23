<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use SodiumException;
use Throwable;
use ValueError;

// Agents in the vault (spec: Agents; decision 5). Agents are API-only Kanboard users from the Agents plugin; who is an
// agent is AgentRoster's answer alone (R47).
//
// Enrolment (the agent's owner, unlocked): a keypair, a random 256-bit vault key and the agent wrap
// (KEK = BLAKE2b-256(key = vault_key, msg = enc("kek", "agent", agent_user_id)); no Argon2, the key is random), plus the
// agent's "Agent-created" group (kind agent_created), owned by the agent and granted Edit to the owner. The vault key
// is returned once, base64url, and stored nowhere. The wrap row is inserted first and sealed with its id in the AD,
// inside the same exclusive transaction (R10).
//
// Re-enrolment (a lost or leaked key; the owner unlocked) runs the spec's five steps in ONE exclusive transaction:
//   1. a new keypair and wrap (key_gen + 1);
//   4. (done next, so the re-keys below see the final grants) every grant source to the agent on an object whose owner
//      isn't the agent's owner is removed with GrantModel::removeSource: the agent's key rows go, the objects are
//      queued, each removal is audited as revoke. A later re-key, by anyone, can't seal to the agent's new key;
//   2, 3. every object the agent can still open (its own Agent-created objects, through the owner's Edit grant, and
//      what the owner shared with it) is re-keyed by the owner: a new DEK, key_epoch + 1, sealed to the agent's new
//      key and every other recipient. One the owner can't re-key is queued instead (the write barrier holds);
//   5. the old wraps, and the agent's rate state, are deleted.
// After it commits, each owner whose share was removed gets a notice asking them to re-share.
// A roster agent that still holds a human principal (T14) is converted by enrolment through the same procedure, which
// also deletes its passphrase, recovery and org wraps, hardware keys and sessions. Enrolment and re-enrolment are
// refused (agent_owns_objects, audited as enroll_refused) while the principal owns anything outside its Agent-created
// group, so a converted human never keeps its former vault (Codex security round 1).
//
// The JSON-RPC API (Api\VaultAgentProcedure → call()): authenticate() requires the user's API token as the Basic-auth
// password (hash_equals; Kanboard alone also accepts a login password), refuses the application user, requires roster
// membership and an agent principal, then reads the vault key from the X-Kanboard-Vault-Key header only. Wrong keys
// back off per agent and client IP (ClientIp, R21), so a leaked token used elsewhere can't lock out the real agent; the
// owner is told after every 5 failures. Nothing here creates or reads a vault session (R17). Secret reads are audited
// and capped per agent (token bucket agentread:<id>, min(owner setting, admin max) an hour, burst 10); a refusal is
// audited once per window (R39) and the owner is told once an hour (R19).
//
// All SQL inside the vault lock goes through VaultDb (R13). Callers fetch an owner's sk before calling (R18) and wipe
// their own copies (R12).
class AgentVault extends Base
{
    public const HEADER = 'X-Kanboard-Vault-Key';
    public const KEY_BYTES = 32;
    public const READ_PER_HOUR = 60;
    public const READ_BURST = 10;
    public const CAP_RANGE = [1, 10000];
    public const KIND = 'agent_created';
    // What an API refusal may say (spec: Methods), plus the payload checks of a write.
    public const REASONS = ['not_agent', 'bad_vault_key', 'rate_limited', 'not_found', 'conflict', 'agents_unavailable', 'payload_invalid', 'payload_too_large'];
    private const APP_USER = 'jsonrpc';
    // The agent API's own audit rows: the actor is the agent, over the API, whatever process runs it.
    private const API = ['actor_kind' => 'agent', 'via' => 'api'];

    private Closure $clock;

    public function __construct($container, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    // The container's instance ('vaultAgentVault', which tests set) or a new one.
    public static function of($container): self
    {
        return isset($container['vaultAgentVault']) ? $container['vaultAgentVault'] : new self($container);
    }

    // base64url, no padding: 43 characters for the 32-byte key.
    public static function encodeKey(#[\SensitiveParameter] string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    // The 32-byte key, or null for anything that isn't exactly 43 base64url characters.
    public static function decodeKey(#[\SensitiveParameter] mixed $encoded): ?string
    {
        if (! is_string($encoded) || preg_match('/^[A-Za-z0-9_-]{43}$/D', $encoded) !== 1) {
            return null;
        }
        $raw = base64_decode(strtr($encoded, '-_', '+/').'=', true);
        return $raw !== false && strlen($raw) === self::KEY_BYTES ? $raw : null;
    }

    // A JSON-RPC id: a positive int, or a string of digits; anything else is -1, which matches nothing. 0 stays 0.
    public static function id(mixed $value): int
    {
        if (is_int($value)) {
            return $value >= 0 ? $value : -1;
        }
        return is_string($value) && ctype_digit($value) && strlen($value) < 16 ? (int) $value : -1;
    }

    // ---- Enrolment -------------------------------------------------------------------------------------------------

    public function enrol(int $ownerId, int $agentId, #[\SensitiveParameter] string $ownerSk): string
    {
        $this->requireOwnedAgent($ownerId, $agentId);
        $vaultKey = random_bytes(self::KEY_BYTES);
        try {
            $notify = $this->lock()->exclusive(function () use ($ownerId, $agentId, $ownerSk, $vaultKey): ?array {
                $db = $this->vdb();
                (new Purger($this->container))->sweepOrphans($this->now());
                $this->requireUnlockedOwner($db, $ownerId, $ownerSk);
                $existing = $db->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ?', [$agentId]);
                if ($existing !== null && $existing['kind'] === 'agent') {
                    throw new VaultException('already_enrolled');
                }
                if ($this->refusedForLegacyObjects($db, $ownerId, $agentId)) {
                    return null;
                }
                if ($existing !== null) {
                    // T14: a roster agent holding a human principal becomes an agent through re-enrolment.
                    $notify = $this->replaceKeys($db, $ownerId, $agentId, $ownerSk, $vaultKey);
                } else {
                    $notify = [];
                    $this->createPrincipal($db, $ownerId, $agentId, $vaultKey);
                }
                $this->audit()->record('enroll', ['actor_user_id' => $agentId]);
                return $notify;
            });
            if ($notify === null) {
                throw new VaultException('agent_owns_objects');
            }
            $this->askToReshare($notify, $agentId);
            return self::encodeKey($vaultKey);
        } finally {
            sodium_memzero($vaultKey);
        }
    }

    public function reenrol(int $ownerId, int $agentId, #[\SensitiveParameter] string $ownerSk): string
    {
        $this->requireOwnedAgent($ownerId, $agentId);
        $vaultKey = random_bytes(self::KEY_BYTES);
        try {
            $notify = $this->lock()->exclusive(function () use ($ownerId, $agentId, $ownerSk, $vaultKey): ?array {
                $db = $this->vdb();
                (new Purger($this->container))->sweepOrphans($this->now());
                $this->requireUnlockedOwner($db, $ownerId, $ownerSk);
                if ($db->fetchOne('SELECT 1 AS x FROM vault_principals WHERE user_id = ? AND live_user_id IS NOT NULL', [$agentId]) === null) {
                    throw new VaultException('not_found');
                }
                if ($this->refusedForLegacyObjects($db, $ownerId, $agentId)) {
                    return null;
                }
                return $this->replaceKeys($db, $ownerId, $agentId, $ownerSk, $vaultKey);
            });
            if ($notify === null) {
                throw new VaultException('agent_owns_objects');
            }
            $this->askToReshare($notify, $agentId);
            return self::encodeKey($vaultKey);
        } finally {
            sodium_memzero($vaultKey);
        }
    }

    // The owner's agents for the agents page: id, username, state (none | enrolled | human, a legacy human principal),
    // and the owner's read cap setting. Empty without Agents.
    /** @return list<array{id:int, username:string, state:string, read_cap:int}> */
    public function agentsOf(int $ownerId): array
    {
        $roster = AgentRoster::of($this->container);
        if (! $roster->available()) {
            return [];
        }
        $out = [];
        $db = $this->vdb();
        foreach ($roster->agentsOf($ownerId) as $agentId) {
            $u = $db->fetchOne('SELECT username, is_active FROM users WHERE id = ?', [$agentId]);
            if ($u === null || (int) $u['is_active'] !== 1) {
                continue;
            }
            $p = $db->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ? AND live_user_id IS NOT NULL', [$agentId]);
            $out[] = [
                'id' => $agentId,
                'username' => (string) $u['username'],
                'state' => $p === null ? 'none' : ($p['kind'] === 'agent' ? 'enrolled' : 'human'),
                'read_cap' => $this->ownerCap($db, $agentId),
            ];
        }
        return $out;
    }

    // Spec, Throttling: the owner can lower the agent's reads per hour; the admin maximum still applies on top.
    public function setReadCap(int $ownerId, int $agentId, int $cap): void
    {
        $this->requireOwnedAgent($ownerId, $agentId);
        if ($cap < self::CAP_RANGE[0] || $cap > self::CAP_RANGE[1]) {
            throw new VaultException('payload_invalid');
        }
        $this->lock()->exclusive(function () use ($agentId, $cap): void {
            $db = $this->vdb();
            if ($db->execute('UPDATE vault_agent_settings SET read_cap_per_hour = ? WHERE agent_user_id = ?', [$cap, $agentId]) === 0) {
                $db->insert('vault_agent_settings', ['agent_user_id' => $agentId, 'read_cap_per_hour' => $cap], null);
            }
        });
    }

    // Reads an hour: min(the owner's setting, default 60; the admin's hard maximum).
    public function readCap(int $agentId): int
    {
        $max = (int) (new VaultSettings($this->container))->get('vault_agent_cap_max');
        return max(1, min($this->ownerCap($this->vdb(), $agentId), $max));
    }

    // ---- The JSON-RPC API ------------------------------------------------------------------------------------------

    // Runs one API method: authenticate, then $op($agentId, $sk, $ip), whose array joins {ok: true}. Every refusal is
    // {ok: false, reason}; an unexpected failure is logged by class only and answered 'error'. sk is wiped after.
    /** @param callable(int, string, string): array $op */
    public function call(callable $op): array
    {
        try {
            $auth = $this->authenticate();
            try {
                (new Housekeeping($this->container, $this->clock))->purge();
                return ['ok' => true] + $op($auth['agent_id'], $auth['sk'], $this->clientIp());
            } finally {
                sodium_memzero($auth['sk']);
            }
        } catch (VaultException $e) {
            return ['ok' => false, 'reason' => in_array($e->errorCode(), self::REASONS, true) ? $e->errorCode() : 'not_found'];
        } catch (Throwable $e) {
            $this->logger->warning('Vault: an agent API call failed ('.get_class($e).')');
            return ['ok' => false, 'reason' => 'error'];
        }
    }

    // Spec, Agents → Auth. Returns the agent and its sk (the caller wipes it).
    /** @return array{agent_id:int, sk:string} */
    public function authenticate(): array
    {
        if (! AgentRoster::of($this->container)->available()) {
            throw new VaultException('agents_unavailable');
        }
        $agentId = $this->tokenAgent();
        $ip = $this->clientIp();
        $bucket = self::keyBucket($agentId, $ip);
        $limiter = $this->limiter();
        // Throttling first: a backed-off pair is refused before its key is tried.
        if ($limiter->backoffSeconds($bucket) > 0) {
            $this->noteRateLimited($agentId, $ip);
            throw new VaultException('rate_limited');
        }
        $sk = $this->openWrap($agentId, self::decodeKey($this->request->getHeader(self::HEADER)));
        if ($sk === null) {
            $failures = $this->recordBadKey($agentId, $bucket, $ip);
            if ($failures > 0 && $failures % RateLimiter::FREE_FAILURES === 0) {
                $this->notify(fn (Notifier $n) => $n->agentBadKey($agentId));
            }
            throw new VaultException('bad_vault_key');
        }
        $limiter->recordSuccess($bucket);
        return ['agent_id' => $agentId, 'sk' => $sk];
    }

    // getVaultEntries: the entries the agent can read by live grants (and its own), metadata only. $groupId 0 lists
    // them all; another id lists that group's entries, if the agent can read the group (not_found otherwise).
    /** @return list<array<string,mixed>> */
    public function entries(int $agentId, #[\SensitiveParameter] string $sk, int $groupId): array
    {
        if ($groupId < 0) {
            throw new VaultException('not_found');
        }
        $store = $this->store();
        $tree = $store->tree($agentId, $sk);
        $groups = [];
        foreach ($tree['groups'] as $g) {
            $groups[(int) $g['id']] = true;
        }
        if ($groupId > 0 && ! isset($groups[$groupId])) {
            throw new VaultException('not_found');
        }
        $targets = $groupId > 0 ? [$groupId] : array_keys($groups);
        if ($groupId === 0 && $tree['shared_entries']) {
            $targets[] = null;
        }
        $rows = [];
        foreach ($targets as $target) {
            $offset = 0;
            do {
                $page = $store->listPage($agentId, $target, $sk, $offset);
                array_push($rows, ...$page['entries']);
                $offset += ObjectStore::LIST_LIMIT;
            } while ($page['more']);
        }
        $writable = $this->writableEntries($agentId);
        $out = [];
        foreach ($rows as $r) {
            if (! empty($r['integrity_error'])) {
                continue;
            }
            $out[] = [
                'entry_id' => (int) $r['id'],
                // An entry shared on its own doesn't reveal a group the agent can't see.
                'group_id' => isset($groups[(int) $r['group_id']]) ? (int) $r['group_id'] : 0,
                'title' => (string) $r['title'],
                'username' => (string) $r['username'],
                'url' => (string) $r['url'],
                'fields' => $r['field_names'],
                'expires_at' => $r['expires_at'],
                'can_write' => isset($writable[(int) $r['id']]),
            ];
        }
        return $out;
    }

    // getVaultSecret: one field, counted against the read cap first, then audited. not_found for anything unseen.
    public function readSecret(int $agentId, #[\SensitiveParameter] string $sk, int $entryId, mixed $field, string $ip): string
    {
        if ($entryId <= 0 || ! is_string($field)) {
            throw new VaultException('not_found');
        }
        $cap = $this->readCap($agentId);
        if (! $this->limiter()->consume(self::readBucket($agentId), (float) min(self::READ_BURST, $cap), $cap / 3600)) {
            $this->noteRateLimited($agentId, $ip);
            // The owner hears about it at most once an hour.
            if ($this->limiter()->consume(self::readBucket($agentId).':notice', 1.0, 1 / 3600)) {
                $this->notify(fn (Notifier $n) => $n->agentRateLimited($agentId));
            }
            throw new VaultException('rate_limited');
        }
        $value = $this->store()->readField($agentId, $entryId, $field, $sk);
        $ipTrunc = (new ClientIp($this->container))->truncate($ip);
        $this->audit()->record('read', ['actor_user_id' => $agentId, 'object_type' => 'entry', 'object_id' => $entryId, 'ip_trunc' => $ipTrunc === '' ? null : $ipTrunc] + self::API);
        return $value;
    }

    // createVaultEntry: always in the agent's Agent-created group.
    public function createEntry(int $agentId, #[\SensitiveParameter] mixed $fields): int
    {
        if (! is_array($fields)) {
            throw new VaultException('payload_invalid');
        }
        $groupId = $this->agentGroupId($this->vdb(), $agentId) ?? throw new VaultException('not_found');
        return $this->store()->createEntry($agentId, $groupId, $fields);
    }

    // updateVaultEntry: only an entry the agent created in its Agent-created group (not_found for anything else). The
    // given keys replace those of the current payload; optimistic concurrency on version (conflict).
    public function updateEntry(int $agentId, #[\SensitiveParameter] string $sk, int $entryId, int $expectedVersion, #[\SensitiveParameter] mixed $fields): int
    {
        if (! is_array($fields)) {
            throw new VaultException('payload_invalid');
        }
        return $this->lock()->exclusive(function () use ($agentId, $sk, $entryId, $expectedVersion, $fields): int {
            $db = $this->vdb();
            $groupId = $this->agentGroupId($db, $agentId);
            $row = $db->fetchOne('SELECT group_id, created_by FROM vault_entries WHERE id = ?', [$entryId]);
            if ($groupId === null || $row === null || (int) $row['group_id'] !== $groupId || (int) ($row['created_by'] ?? 0) !== $agentId) {
                throw new VaultException('not_found');
            }
            $store = $this->store();
            $current = $store->readEntry($agentId, $entryId, $sk)['payload'];
            return $store->updateEntry($agentId, $entryId, $expectedVersion, array_merge($current, $fields), $sk);
        });
    }

    // After a write: the agent's share of the opportunistic work (its re-key queue).
    public function afterWrite(int $agentId, #[\SensitiveParameter] string $sk): void
    {
        (new Housekeeping($this->container, $this->clock))->afterWrite($agentId, $sk);
    }

    // ---- Internals -------------------------------------------------------------------------------------------------

    public static function keyBucket(int $agentId, string $ip): string
    {
        return 'agentkey:'.$agentId.':'.bin2hex(sodium_crypto_generichash($ip === '' ? 'unknown' : $ip, '', 16));
    }

    public static function readBucket(int $agentId): string
    {
        return 'agentread:'.$agentId;
    }

    // The Basic-auth user, if it is an agent that authenticated with its API token. not_agent otherwise.
    private function tokenAgent(): int
    {
        [$username, $password] = $this->credentials();
        $userId = (int) $this->userSession->getId();
        if ($username === '' || $username === self::APP_USER || $userId <= 0) {
            throw new VaultException('not_agent');
        }
        $user = $this->vdb()->fetchOne('SELECT username, is_active, api_access_token FROM users WHERE id = ?', [$userId]);
        $token = (string) ($user['api_access_token'] ?? '');
        if ($user === null || (int) $user['is_active'] !== 1 || ! hash_equals((string) $user['username'], $username)
            || $token === '' || ! hash_equals($token, $password)) {
            throw new VaultException('not_agent');
        }
        if (! AgentRoster::of($this->container)->isAgent($userId)) {
            throw new VaultException('not_agent');
        }
        $p = $this->vdb()->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ? AND live_user_id IS NOT NULL', [$userId]);
        if ($p === null || $p['kind'] !== 'agent') {
            throw new VaultException('not_agent');
        }
        return $userId;
    }

    // What the JSON-RPC server read from Basic auth (or Kanboard's API_AUTHENTICATION_HEADER): the same pair the API
    // middleware authenticated.
    /** @return array{0:string, 1:string} */
    private function credentials(): array
    {
        if (! isset($this->container['api'])) {
            return ['', ''];
        }
        $api = $this->container['api'];
        return [(string) $api->getUsername(), (string) $api->getPassword()];
    }

    // The agent's sk from its active agent wrap, or null for any failure (no oracle).
    private function openWrap(int $agentId, #[\SensitiveParameter] ?string $vaultKey): ?string
    {
        if ($vaultKey === null) {
            return null;
        }
        $kek = '';
        try {
            $db = $this->vdb();
            $p = $db->fetchOne('SELECT public_key, key_gen FROM vault_principals WHERE user_id = ? AND live_user_id IS NOT NULL', [$agentId]);
            $pk = $p === null ? false : base64_decode((string) $p['public_key'], true);
            if ($pk === false) {
                return null;
            }
            $w = $db->fetchOne("SELECT * FROM vault_wraps WHERE user_id = ? AND method = 'agent' AND status = 'active' AND key_gen = ? ORDER BY id LIMIT 1", [$agentId, (int) $p['key_gen']]);
            if ($w === null) {
                return null;
            }
            $kek = Kdf::kek($vaultKey, 'agent', $agentId);
            return Wraps::unwrap([
                'id' => (int) $w['id'],
                'user_id' => (int) $w['user_id'],
                'method' => (string) $w['method'],
                'credential_id' => $w['credential_id'],
                'nonce' => (string) $w['nonce'],
                'wrapped_sk' => (string) $w['wrapped_sk'],
                'crypto_v' => (int) $w['crypto_v'],
            ], $kek, $pk);
        } catch (CryptoException|SodiumException|ValueError) {
            return null;
        } finally {
            sodium_memzero($kek);
            sodium_memzero($vaultKey);
        }
    }

    // One wrong key: counted in the agent+IP bucket and audited as bad_vault_key, in one transaction. Returns the
    // failure count of the pair.
    private function recordBadKey(int $agentId, string $bucket, string $ip): int
    {
        return $this->lock()->exclusive(function () use ($agentId, $bucket, $ip): int {
            $this->limiter()->recordFailure($bucket);
            $ipTrunc = (new ClientIp($this->container))->truncate($ip);
            $this->audit()->record('bad_vault_key', ['actor_user_id' => $agentId, 'ip_trunc' => $ipTrunc === '' ? null : $ipTrunc] + self::API);
            $row = $this->vdb()->fetchOne('SELECT tokens FROM vault_rate WHERE bucket = ?', [$bucket]);
            return $row === null ? 0 : (int) round((float) $row['tokens']);
        });
    }

    // Spec, Enrolment, inside the caller's exclusive transaction.
    private function createPrincipal(VaultDb $db, int $ownerId, int $agentId, #[\SensitiveParameter] string $vaultKey): void
    {
        $keypair = sodium_crypto_box_keypair();
        $sk = sodium_crypto_box_secretkey($keypair);
        try {
            PrincipalModel::assertIdentity('agent', $agentId, $agentId);
            $db->insert('vault_principals', [
                'user_id' => $agentId,
                'kind' => 'agent',
                'public_key' => base64_encode(sodium_crypto_box_publickey($keypair)),
                'key_gen' => 1,
                'state' => 'active',
                'created_at' => $this->now(),
                // R26: without it the orphan sweep would take the principal for a deleted user's.
                'live_user_id' => $agentId,
            ], null);
            $this->insertWrap($db, $agentId, 1, $sk, $vaultKey);
            $this->ensureAgentGroup($db, $ownerId, $agentId, $sk);
        } finally {
            sodium_memzero($keypair);
            sodium_memzero($sk);
        }
    }

    // Spec, Re-enrolment, inside the caller's exclusive transaction (see the class comment for the order). Returns the
    // users whose shares were removed.
    /** @return list<int> */
    private function replaceKeys(VaultDb $db, int $ownerId, int $agentId, #[\SensitiveParameter] string $ownerSk, #[\SensitiveParameter] string $vaultKey): array
    {
        $gen = (int) $db->fetchOne('SELECT key_gen FROM vault_principals WHERE user_id = ?', [$agentId])['key_gen'] + 1;
        $keypair = sodium_crypto_box_keypair();
        $sk = sodium_crypto_box_secretkey($keypair);
        try {
            // 1. The new keypair and wrap. From here the principal is an agent (a human principal is converted, T14).
            PrincipalModel::assertIdentity('agent', $agentId, $agentId);
            $db->execute(
                "UPDATE vault_principals SET kind = 'agent', public_key = ?, key_gen = ?, state = 'active', live_user_id = ?, rotate_requested = 0 WHERE user_id = ?",
                [base64_encode(sodium_crypto_box_publickey($keypair)), $gen, $agentId, $agentId]
            );
            $db->execute('DELETE FROM vault_rotations WHERE user_id = ?', [$agentId]);
            $wrapId = $this->insertWrap($db, $agentId, $gen, $sk, $vaultKey);

            // 4. Shares other users control: removed through the one removal procedure, audited as revoke by the owner.
            $grants = new GrantModel($this->container, $this->clock);
            $resolver = new RecipientResolver($this->container);
            $notify = [];
            foreach ($db->fetchAll('SELECT id, subject_type, subject_id, permission FROM vault_grants WHERE grantee_id = ? ORDER BY id', [$agentId]) as $g) {
                $type = (string) $g['subject_type'];
                $subject = isset(RecipientResolver::TABLES[$type]) ? $resolver->object($type, (int) $g['subject_id']) : null;
                $subjectOwner = $subject === null ? null : (int) $subject['owner_id'];
                if ($subjectOwner === $ownerId) {
                    // R47/A8: grants to an agent are Read only. A converted human keeps the owner's grants, Edit cut to Read.
                    if ($g['permission'] === ObjectStore::EDIT) {
                        $db->execute('UPDATE vault_grants SET permission = ? WHERE id = ?', [ObjectStore::READ, (int) $g['id']]);
                        $this->audit()->record('grant', ['actor_user_id' => $ownerId, 'object_type' => $type, 'object_id' => (int) $g['subject_id'], 'target_user_id' => $agentId]);
                    }
                    continue;
                }
                $grants->removeSource((int) $g['id'], $ownerId);
                if ($subjectOwner !== null && $subjectOwner !== $agentId) {
                    $notify[$subjectOwner] = true;
                }
            }

            // 2 and 3. Everything the agent can still open is re-keyed by the owner and sealed to the agent's new key.
            $rekeyer = new Rekeyer($this->container, $this->clock);
            $objects = $db->fetchAll(
                'SELECT DISTINCT object_type, object_id FROM vault_keys WHERE principal_id = ?
                 UNION SELECT \'group\', id FROM vault_groups WHERE owner_id = ?
                 UNION SELECT \'entry\', id FROM vault_entries WHERE owner_id = ?',
                [$agentId, $agentId, $agentId]
            );
            $rekeyed = 0;
            foreach ($objects as $o) {
                $type = (string) $o['object_type'];
                $row = isset(RecipientResolver::TABLES[$type]) ? $resolver->object($type, (int) $o['object_id']) : null;
                if ($row === null) {
                    continue;
                }
                $recipients = $resolver->effective($type, (int) $row['id'], $this->now(), $row);
                if (isset($recipients[$agentId], $recipients[$ownerId]) && $rekeyer->rekeyRow($db, $type, $row, $ownerId, $ownerSk)) {
                    $rekeyed++;
                    continue;
                }
                // Not the owner's to re-key: the agent's dead rows go and the write barrier holds until a holder re-keys.
                $db->execute('DELETE FROM vault_keys WHERE object_type = ? AND object_id = ? AND principal_id = ?', [$type, (int) $row['id'], $agentId]);
                $rekeyer->enqueue($db, $type, (int) $row['id'], (int) $row['key_epoch']);
            }
            $db->execute('DELETE FROM vault_keys WHERE principal_id = ? AND principal_key_gen < ?', [$agentId, $gen]);
            $this->ensureAgentGroup($db, $ownerId, $agentId, $sk);

            // 5. The old wraps and everything else the old identity had: hardware keys, sessions, rate state.
            $db->execute('DELETE FROM vault_wraps WHERE user_id = ? AND id <> ?', [$agentId, $wrapId]);
            $db->execute('DELETE FROM vault_webauthn WHERE user_id = ?', [$agentId]);
            $db->execute('DELETE FROM vault_challenges WHERE user_id = ?', [$agentId]);
            $db->execute('DELETE FROM vault_sessions WHERE user_id = ?', [$agentId]);
            $db->execute('DELETE FROM vault_rate WHERE bucket LIKE ? OR bucket IN (?, ?, ?, ?, ?, ?)', [
                'agentkey:'.$agentId.':%',
                self::readBucket($agentId),
                self::readBucket($agentId).':notice',
                UnlockService::userBucket($agentId),
                RecoveryService::userBucket($agentId),
                FailedGuess::streakBucket($agentId),
                PrincipalModel::noticeBucket($agentId),
            ]);
            $this->audit()->record('rotate', ['actor_user_id' => $agentId, 'count' => $rekeyed]);
            return array_keys($notify);
        } finally {
            sodium_memzero($keypair);
            sodium_memzero($sk);
        }
    }

    // Codex security round 1: an agent may own only its Agent-created group and what is inside it. A principal that owns
    // anything else (a human's vault from before it was adopted) is not converted or re-keyed: the refusal is audited
    // as enroll_refused (actor the owner, target the agent, count the objects) in the caller's transaction, which then
    // commits with nothing else written, and the caller answers agent_owns_objects. The objects must be deleted first:
    // nobody but their owner holds every DEK, and the owner's own key is the one the conversion destroys.
    private function refusedForLegacyObjects(VaultDb $db, int $ownerId, int $agentId): bool
    {
        $groupId = $this->agentGroupId($db, $agentId);
        $inside = $groupId === null ? [] : array_flip(array_merge(...(new RecipientResolver($this->container))->subtreeLevels($groupId)));
        $count = 0;
        foreach ($db->fetchAll('SELECT id FROM vault_groups WHERE owner_id = ?', [$agentId]) as $g) {
            $count += isset($inside[(int) $g['id']]) ? 0 : 1;
        }
        foreach ($db->fetchAll('SELECT group_id FROM vault_entries WHERE owner_id = ?', [$agentId]) as $e) {
            $count += isset($inside[(int) $e['group_id']]) ? 0 : 1;
        }
        if ($count === 0) {
            return false;
        }
        $this->audit()->record('enroll_refused', ['actor_user_id' => $ownerId, 'target_user_id' => $agentId, 'count' => $count]);
        return true;
    }

    // R10: the row first (a placeholder), then the wrap sealed with its id in the AD, in the caller's transaction.
    private function insertWrap(VaultDb $db, int $agentId, int $keyGen, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] string $vaultKey): int
    {
        $wrapId = $db->insert('vault_wraps', [
            'user_id' => $agentId,
            'method' => 'agent',
            'credential_id' => null,
            'kdf_salt' => null,
            'kdf_ops' => null,
            'kdf_mem' => null,
            'status' => 'active',
            'key_gen' => $keyGen,
            'nonce' => '',
            'wrapped_sk' => '',
            'crypto_v' => Wraps::CRYPTO_V,
            'created_at' => $this->now(),
        ]);
        $kek = Kdf::kek($vaultKey, 'agent', $agentId);
        try {
            $wrap = Wraps::wrap($sk, $kek, $agentId, 'agent', '', $wrapId);
        } finally {
            sodium_memzero($kek);
        }
        $db->execute('UPDATE vault_wraps SET nonce = ?, wrapped_sk = ? WHERE id = ?', [$wrap['nonce'], $wrap['wrapped_sk'], $wrapId]);
        return $wrapId;
    }

    // The agent's Agent-created group: owned by the agent, granted Edit to the owner. Created when missing.
    private function ensureAgentGroup(VaultDb $db, int $ownerId, int $agentId, #[\SensitiveParameter] string $agentSk): void
    {
        if ($this->agentGroupId($db, $agentId) !== null) {
            return;
        }
        $u = $db->fetchOne('SELECT username FROM users WHERE id = ?', [$agentId]);
        $groupId = $this->store()->createGroup($agentId, null, ['name' => t('Agent-created').': '.(string) ($u['username'] ?? $agentId)], self::KIND);
        (new GrantModel($this->container, $this->clock))->grant($agentId, 'group', $groupId, $ownerId, ObjectStore::EDIT, null, $agentSk);
    }

    private function agentGroupId(VaultDb $db, int $agentId): ?int
    {
        $r = $db->fetchOne('SELECT id FROM vault_groups WHERE owner_id = ? AND kind = ? ORDER BY id LIMIT 1', [$agentId, self::KIND]);
        return $r === null ? null : (int) $r['id'];
    }

    // Entries updateVaultEntry accepts: the agent's own, in its Agent-created group.
    /** @return array<int,true> */
    private function writableEntries(int $agentId): array
    {
        $db = $this->vdb();
        $groupId = $this->agentGroupId($db, $agentId);
        if ($groupId === null) {
            return [];
        }
        $out = [];
        foreach ($db->fetchAll('SELECT id FROM vault_entries WHERE group_id = ? AND created_by = ?', [$groupId, $agentId]) as $r) {
            $out[(int) $r['id']] = true;
        }
        return $out;
    }

    // The agent must be on the roster, owned by $ownerId and active. not_found otherwise; agents_unavailable without
    // the Agents plugin.
    private function requireOwnedAgent(int $ownerId, int $agentId): void
    {
        $roster = AgentRoster::of($this->container);
        if (! $roster->available()) {
            throw new VaultException('agents_unavailable');
        }
        if ($agentId <= 0 || $roster->ownerOf($agentId) !== $ownerId) {
            throw new VaultException('not_found');
        }
        $u = $this->vdb()->fetchOne('SELECT is_active FROM users WHERE id = ?', [$agentId]);
        if ($u === null || (int) $u['is_active'] !== 1) {
            throw new VaultException('not_found');
        }
    }

    // The owner has a human vault (owner_not_enrolled otherwise) and $sk is their current key (not_found otherwise).
    private function requireUnlockedOwner(VaultDb $db, int $ownerId, #[\SensitiveParameter] string $sk): void
    {
        $p = $db->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ? AND live_user_id IS NOT NULL', [$ownerId]);
        if ($p === null || $p['kind'] !== 'human') {
            throw new VaultException('owner_not_enrolled');
        }
        if ((new Rekeyer($this->container, $this->clock))->currentPrincipal($db, $ownerId, $sk) === null) {
            throw new VaultException('not_found');
        }
    }

    private function ownerCap(VaultDb $db, int $agentId): int
    {
        $row = $db->fetchOne('SELECT read_cap_per_hour FROM vault_agent_settings WHERE agent_user_id = ?', [$agentId]);
        return $row === null ? self::READ_PER_HOUR : (int) $row['read_cap_per_hour'];
    }

    // R19: after a re-enrolment, each owner whose share was removed is asked to re-share. Best effort, after commit.
    /** @param list<int> $owners */
    private function askToReshare(array $owners, int $agentId): void
    {
        foreach ($owners as $owner) {
            $this->notify(fn (Notifier $n) => $n->agentRekeyed($owner, $agentId));
        }
    }

    private function notify(callable $send): void
    {
        try {
            $send(Notifier::of($this->container));
        } catch (Throwable $e) {
            $this->logger->warning('Vault: an agent notice could not be sent ('.get_class($e).')');
        }
    }

    // R39: once per bucket and window.
    private function noteRateLimited(int $agentId, string $ip): void
    {
        try {
            (new RateLimitAudit($this->container, $this->clock))->note($agentId, $ip);
        } catch (Throwable $e) {
            $this->logger->warning('Vault: a rate-limit refusal could not be audited ('.get_class($e).')');
        }
    }

    private function clientIp(): string
    {
        return (new ClientIp($this->container))->resolve($this->request, (new VaultSettings($this->container))->trustedProxies());
    }

    private function audit(): AuditModel
    {
        return AuditModel::of($this->container, $this->clock);
    }

    private function limiter(): RateLimiter
    {
        return new RateLimiter($this->container, null, $this->clock);
    }

    private function store(): ObjectStore
    {
        return new ObjectStore($this->container, $this->clock);
    }

    private function vdb(): VaultDb
    {
        return new VaultDb($this->container);
    }

    private function lock(): VaultLock
    {
        return new VaultLock($this->container);
    }

    private function now(): int
    {
        return (int) ($this->clock)();
    }
}
