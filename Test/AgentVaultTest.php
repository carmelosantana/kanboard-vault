<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/AgentFixture.php';
require_once __DIR__.'/Support/FileDb.php';

use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\AgentVault;
use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\Purger;
use Kanboard\Plugin\Vault\Model\Rekeyer;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// An audit log that fails one action, to prove a multi-step change commits or rolls back as one.
class VaultFailingAudit extends AuditModel
{
    public function __construct($container, private string $failOn, ?callable $clock = null)
    {
        parent::__construct($container, null, null, $clock);
    }

    public function record(string $action, array $cols): void
    {
        if ($action === $this->failOn) {
            throw new RuntimeException('injected audit failure');
        }
        parent::record($action, $cols);
    }
}

// Spec: Agents → Enrolment and Re-enrolment; Throttling (agent secret reads); Entries, groups and grants (removing a
// grant source, the re-key queue). Carries: R10, R12, R13, R26 (live_user_id), T7 (agent disable through
// removeSource), T10 (an owner sees the agent's rows), T14 (a roster agent holding a human principal).
class AgentVaultTest extends Base
{
    use AgentFixture;

    /** @var list<array> */
    private array $sent = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        $this->setUpAgents();
        $this->pdo()->prepare('UPDATE users SET email = ? WHERE id = ?')->execute(['carol@example.test', $this->carol]);
        $this->container['emailClient']->method('send')->willReturnCallback(function (...$args) {
            $this->sent[] = array_slice($args, 0, 4);
            return $this->container['emailClient'];
        });
    }

    protected function tearDown(): void
    {
        session_flush();
        $this->tearDownVault();
        parent::tearDown();
    }

    // The agent's sk, opened from its agent wrap with the vault key: KEK = BLAKE2b(key = vault_key, enc("kek", "agent", id)).
    private function agentSk(int $agentId, string $vaultKey): string
    {
        $p = $this->row('SELECT public_key, key_gen FROM vault_principals WHERE user_id = ?', [$agentId]);
        $w = $this->row("SELECT * FROM vault_wraps WHERE user_id = ? AND method = 'agent' AND status = 'active' AND key_gen = ?", [$agentId, $p['key_gen']]);
        $this->assertNotNull($w, 'an active agent wrap');
        return Wraps::unwrap($w, Kdf::kek(AgentVault::decodeKey($vaultKey), 'agent', $agentId), base64_decode($p['public_key']));
    }

    private function epoch(string $type, int $id): int
    {
        return (int) $this->row('SELECT key_epoch FROM '.($type === 'entry' ? 'vault_entries' : 'vault_groups').' WHERE id = ?', [$id])['key_epoch'];
    }

    // Spec, Enrolment: a keypair and a random 256-bit vault key, the agent wrap (no passphrase, no KDF parameters), the
    // "Agent-created" group owned by the agent and granted Edit to the owner. The key is returned once, base64url, and
    // stored nowhere. R26: the principal has live_user_id, so the orphan sweep keeps it. R10: the wrap's AD binds its
    // own row id. Kills: live_user_id left NULL (swept); the group missing, of the wrong kind or without the owner's Edit
    // grant; the key or its KEK stored; a wrap whose AD has another id.
    public function testEnrolCreatesTheAgentPrincipalAndGroup(): void
    {
        $key = $this->enrolDave();
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $key);
        $this->assertSame(32, strlen(AgentVault::decodeKey($key)));

        $p = $this->row('SELECT kind, live_user_id, state FROM vault_principals WHERE user_id = ?', [$this->dave]);
        $this->assertSame(['agent', $this->dave, 'active'], [$p['kind'], (int) $p['live_user_id'], $p['state']]);
        (new Purger($this->container))->sweepOrphans($this->now);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_principals WHERE user_id = ?', [$this->dave]), 'R26: not an orphan');

        $wraps = $this->pdo()->query('SELECT * FROM vault_wraps WHERE user_id = '.$this->dave)->fetchAll(PDO::FETCH_ASSOC);
        $this->assertCount(1, $wraps);
        $this->assertSame(['agent', null, null, null, null], [$wraps[0]['method'], $wraps[0]['credential_id'], $wraps[0]['kdf_salt'], $wraps[0]['kdf_ops'], $wraps[0]['kdf_mem']]);
        $sk = $this->agentSk($this->dave, $key);
        $this->assertSame(32, strlen($sk));
        $moved = $wraps[0];
        $moved['id'] = (int) $moved['id'] + 1;
        try {
            Wraps::unwrap($moved, Kdf::kek(AgentVault::decodeKey($key), 'agent', $this->dave), base64_decode($this->row('SELECT public_key FROM vault_principals WHERE user_id = ?', [$this->dave])['public_key']));
            $this->fail('the wrap AD binds its row id');
        } catch (CryptoException) {
        }

        $g = $this->row("SELECT id, owner_id, parent_id FROM vault_groups WHERE kind = 'agent_created'");
        $this->assertSame([$this->dave, null], [(int) $g['owner_id'], $g['parent_id']]);
        $grant = $this->row('SELECT grantee_id, permission, expires_at FROM vault_grants WHERE subject_type = ? AND subject_id = ?', ['group', (int) $g['id']]);
        $this->assertSame([$this->alice, 'edit', null], [(int) $grant['grantee_id'], $grant['permission'], $grant['expires_at']]);
        $this->assertSame('Agent-created: dave.bot', $this->store()->readGroup($this->alice, (int) $g['id'], $this->aliceSk())['payload']['name']);

        $dump = vault_test_dump($this->pdo());
        $raw = AgentVault::decodeKey($key);
        foreach ([$key, base64_encode($raw), bin2hex($raw), Kdf::kek($raw, 'agent', $this->dave), base64_encode(Kdf::kek($raw, 'agent', $this->dave))] as $form) {
            $this->assertStringNotContainsString($form, $dump);
        }
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_audit WHERE action = 'enroll' AND actor_user_id = ?", [$this->dave]), 'enrolment audited');
        $this->assertVaultError('already_enrolled', fn () => $this->enrolDave());
    }

    // Spec, Enrolment: only the agent's owner, with a vault, and unlocked (their current sk). Without Agents nothing is
    // enrolled. Kills: owner_not_enrolled lost; someone else's agent enrolled; a stale or wrong sk accepted; a user not
    // on the roster enrolled as an agent.
    public function testEnrolRefusals(): void
    {
        $eve = (int) $this->container['userModel']->create(['username' => 'eve.bot', 'password' => 'eve usable password 1']);
        $this->roster([$this->dave => $this->alice, $eve => $this->bob]);
        $this->assertVaultError('owner_not_enrolled', fn () => $this->agentVault()->enrol($this->bob, $eve, random_bytes(32)));
        $this->assertVaultError('not_found', fn () => $this->agentVault()->enrol($this->alice, $eve, $this->aliceSk()));
        $this->assertVaultError('not_found', fn () => $this->agentVault()->enrol($this->alice, $this->dave, $this->carolSk()));
        $this->assertVaultError('not_found', fn () => $this->agentVault()->enrol($this->alice, $this->carol, $this->aliceSk()));
        $this->assertVaultError('not_found', fn () => $this->agentVault()->reenrol($this->alice, $this->dave, $this->aliceSk()));
        $this->roster([$this->dave => $this->alice], false);
        $this->assertVaultError('agents_unavailable', fn () => $this->enrolDave());
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_principals WHERE user_id IN (?, ?)', [$this->dave, $eve]));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_groups'));
    }

    // Spec, Re-enrolment step 4, and its test: grant sources other users control are deleted (each audited as revoke),
    // the agent's key rows go and the objects are queued, so a re-key run later by anyone (drainQueue as carol) seals
    // nothing to the agent's new key; the agent's owner can't restore a grant carol controls; carol is asked to re-share
    // and re-sharing is an ordinary new grant. Kills: third-party grants kept (direct or ancestor); a bare DELETE without
    // removeSource (no queue, no re-key); the owner's own shares deleted too; no notice to carol.
    public function testReenrolDeletesThirdPartyGrantsAndQueueDoesNotRestore(): void
    {
        $this->configureEmail();
        $key = $this->enrolDave();
        [$cg, $ce] = $this->sharedEntry($this->carol, $this->carolSk(), 'Carol group');
        $cg2 = $this->store()->createGroup($this->carol, null, ['name' => 'Carol direct']);
        $ce2 = $this->store()->createEntry($this->carol, $cg2, Fixtures::entry('Carol direct'));
        $this->grants()->grant($this->carol, 'entry', $ce2, $this->dave, 'read', null, $this->carolSk());
        [, $ae] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Alice shared');
        foreach ([$ce, $ce2, $ae] as $e) {
            $this->assertTrue($this->asDave($key)->getVaultSecret($e)['ok']);
        }
        $epochs = ['group' => $this->epoch('group', $cg), 'entry' => $this->epoch('entry', $ce), 'entry2' => $this->epoch('entry', $ce2)];

        $new = $this->agentVault()->reenrol($this->alice, $this->dave, $this->aliceSk());
        $this->assertNotSame($key, $new);

        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants g JOIN vault_groups o ON g.subject_type = \'group\' AND o.id = g.subject_id WHERE g.grantee_id = ? AND o.owner_id = ?', [$this->dave, $this->carol]));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ? AND subject_type = ? AND subject_id = ?', [$this->dave, 'entry', $ce2]));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ? AND granted_by = ?', [$this->dave, $this->alice]), "alice's own share stays");
        $revokes = array_map(fn ($r) => [(int) $r['actor_user_id'], (int) $r['target_user_id'], $r['object_type']], $this->auditRows('revoke'));
        sort($revokes);
        $this->assertSame([[$this->alice, $this->dave, 'entry'], [$this->alice, $this->dave, 'group']], $revokes);
        $queued = $this->queuedRefs();
        $this->assertEqualsCanonicalizing(['entry:'.$ce, 'entry:'.$ce2, 'group:'.$cg], $queued);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND ((object_type = ? AND object_id IN (?, ?)) OR (object_type = ? AND object_id IN (?, ?)))', [$this->dave, 'entry', $ce, $ce2, 'group', $cg, $cg2]));

        $notFound = ['ok' => false, 'reason' => 'not_found'];
        $this->assertSame($notFound, $this->asDave($new)->getVaultSecret($ce));
        $this->assertSame($notFound, $this->asDave($new)->getVaultSecret($ce2));
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($new)->getVaultSecret($ae));

        // The owner can't restore it; the queue, run by carol, re-keys without the agent.
        $this->assertVaultError('not_found', fn () => $this->grants()->grant($this->alice, 'group', $cg, $this->dave, 'read', null, $this->aliceSk()));
        $this->assertVaultError('not_found', fn () => $this->grants()->grant($this->alice, 'entry', $ce2, $this->dave, 'read', null, $this->aliceSk()));
        $this->assertSame(3, (new Rekeyer($this->container, $this->clock()))->drainQueue($this->carol, $this->carolSk()));
        $this->assertSame([$epochs['group'] + 1, $epochs['entry'] + 1, $epochs['entry2'] + 1], [$this->epoch('group', $cg), $this->epoch('entry', $ce), $this->epoch('entry', $ce2)]);
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND ((object_type = 'group' AND object_id = ?) OR (object_type = 'entry' AND object_id IN (?, ?)))", [$this->dave, $cg, $ce, $ce2]));
        $this->assertSame($notFound, $this->asDave($new)->getVaultSecret($ce));
        $this->assertSame($notFound, $this->asDave($new)->getVaultSecret($ce2));

        $this->assertCount(1, $this->sent, 'carol is asked to re-share, once');
        $this->assertSame('carol@example.test', $this->sent[0][0]);
        $this->assertStringNotContainsString($new, json_encode($this->sent));
        // Re-sharing is an ordinary new grant that only carol can make.
        $this->grants()->grant($this->carol, 'group', $cg, $this->dave, 'read', null, $this->carolSk());
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($new)->getVaultSecret($ce));
    }

    // Spec, Re-enrolment steps 1, 2, 3 and 5: a new keypair and wrap; every agent-created object and every object the
    // owner shared with the agent is re-keyed (new DEK, key_epoch + 1) and sealed to the agent's new key and the owner;
    // the old wrap and the agent's rate state are deleted. Nothing the agent can still open is sealed to the old key.
    // Kills: agent-created objects only re-sealed (old DEK kept); the owner's shares only re-sealed; the old wrap kept
    // (the old key still works); rate state kept; a key row left on the old key.
    public function testReenrolRekeysAgentCreatedObjects(): void
    {
        $key = $this->enrolDave();
        $own = $this->asDave($key)->createVaultEntry(['title' => 'Made by dave', 'password' => Fixtures::UPDATED_PASSWORD])['entry_id'];
        $agentGroup = $this->agentGroup($this->dave);
        [$ag, $ae] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Alice shared');
        $oldSk = $this->agentSk($this->dave, $key);
        $oldKeypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($oldSk, sodium_crypto_box_publickey_from_secretkey($oldSk));
        $before = ['own' => $this->epoch('entry', $own), 'agentGroup' => $this->epoch('group', $agentGroup), 'ag' => $this->epoch('group', $ag), 'ae' => $this->epoch('entry', $ae)];
        $this->pdo()->exec("INSERT INTO vault_rate (bucket, tokens, updated_at) VALUES ('agentkey:{$this->dave}:abc', 3, 1), ('agentread:{$this->dave}', 0, 1), ('agentkey:{$this->carol}:abc', 3, 1)");
        $genBefore = (int) $this->row('SELECT key_gen FROM vault_principals WHERE user_id = ?', [$this->dave])['key_gen'];

        $new = $this->agentVault()->reenrol($this->alice, $this->dave, $this->aliceSk());
        $this->assertSame(['agentkey:'.$this->carol.':abc'], $this->pdo()->query("SELECT bucket FROM vault_rate WHERE bucket LIKE 'agent%'")->fetchAll(PDO::FETCH_COLUMN), "the agent's rate state is gone");

        $this->assertSame([$before['own'] + 1, $before['agentGroup'] + 1, $before['ag'] + 1, $before['ae'] + 1],
            [$this->epoch('entry', $own), $this->epoch('group', $agentGroup), $this->epoch('group', $ag), $this->epoch('entry', $ae)]);
        $this->assertSame(['ok' => false, 'reason' => 'bad_vault_key'], $this->asDave($key)->getVaultSecret($own), 'the old key is dead');
        $this->assertSame(['ok' => true, 'value' => Fixtures::UPDATED_PASSWORD], $this->asDave($new)->getVaultSecret($own));
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($new)->getVaultSecret($ae));
        $this->assertSame(Fixtures::UPDATED_PASSWORD, $this->store()->readField($this->alice, $own, 'password', $this->aliceSk()), 'the owner still reads it');

        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_wraps WHERE user_id = ?', [$this->dave]));
        $gen = (int) $this->row('SELECT key_gen FROM vault_principals WHERE user_id = ?', [$this->dave])['key_gen'];
        $this->assertSame($genBefore + 1, $gen);
        $rows = $this->pdo()->query('SELECT * FROM vault_keys WHERE principal_id = '.$this->dave)->fetchAll(PDO::FETCH_ASSOC);
        $this->assertCount(4, $rows, 'own entry, agent group, alice group, alice entry');
        foreach ($rows as $r) {
            $this->assertSame($gen, (int) $r['principal_key_gen']);
            try {
                Sealer::openDek(base64_decode($r['sealed_dek']), $oldKeypair, $r['object_type'], (int) $r['object_id'], (int) $r['key_epoch'], $this->dave);
                $this->fail('a DEK still opens with the old key');
            } catch (CryptoException) {
            }
        }
        $rotate = $this->auditRows('rotate');
        $this->assertCount(1, $rotate);
        $this->assertSame([$this->dave, 4], [(int) $rotate[0]['actor_user_id'], (int) $rotate[0]['count']]);
    }

    // Spec, Re-enrolment "runs as one exclusive transaction": a failure at its last step leaves everything as it was:
    // the old key works, carol's grant and every key row stay, nothing is queued. Kills: a step committed on its own.
    public function testReenrolIsOneTransaction(): void
    {
        $key = $this->enrolDave();
        [, $ce] = $this->sharedEntry($this->carol, $this->carolSk(), 'Carol group');
        $snapshot = fn () => [
            $this->pdo()->query('SELECT * FROM vault_principals ORDER BY user_id')->fetchAll(PDO::FETCH_ASSOC),
            $this->pdo()->query('SELECT * FROM vault_wraps ORDER BY id')->fetchAll(PDO::FETCH_ASSOC),
            $this->pdo()->query('SELECT * FROM vault_grants ORDER BY id')->fetchAll(PDO::FETCH_ASSOC),
            $this->pdo()->query('SELECT * FROM vault_keys ORDER BY object_type, object_id, principal_id, principal_key_gen')->fetchAll(PDO::FETCH_ASSOC),
            $this->pdo()->query('SELECT * FROM vault_rekey_queue')->fetchAll(PDO::FETCH_ASSOC),
            $this->pdo()->query('SELECT id, key_epoch, ciphertext FROM vault_entries ORDER BY id')->fetchAll(PDO::FETCH_ASSOC),
            $this->pdo()->query('SELECT * FROM vault_audit ORDER BY id')->fetchAll(PDO::FETCH_ASSOC),
        ];
        $before = $snapshot();
        unset($this->container['vaultAudit']);
        $failing = new VaultFailingAudit($this->container, 'rotate', $this->clock());
        $this->container['vaultAudit'] = fn () => $failing;
        try {
            $this->agentVault()->reenrol($this->alice, $this->dave, $this->aliceSk());
            $this->fail('the injected failure');
        } catch (RuntimeException) {
        }
        $this->assertSame($before, $snapshot());
        unset($this->container['vaultAudit']);
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($key)->getVaultSecret($ce));
    }

    // T14 carry: a roster agent that holds a human principal (enrolled before it was adopted) can't unlock as a human
    // (passphrase or recovery code), loses any UI vault session, isn't an agent to the API, and enrolment converts it:
    // the human wraps and sessions go, the principal becomes an agent with the agent wrap, through the re-enrolment
    // procedure (the owner's shares re-keyed to the new key). Kills: the unlock, recovery or session roster check
    // dropped; the conversion keeping a passphrase wrap or the kind human; already_enrolled for a human principal.
    public function testRosterAgentWithHumanPrincipalIsReconciled(): void
    {
        $phrase = 'VaultFixtureSecret-davephrase-Mn7oP8';
        $this->roster([]);
        $this->principals()->enrolHuman($this->dave, $phrase);
        $this->settings()->set(VaultSettings::POLICY, VaultSettings::POLICY_CODE, self::ADMIN);
        $daveSk = $this->unlockAs($this->dave, $phrase, 'dave-ui-session');
        $code = $this->recovery()->createCode($this->dave, $daveSk);
        [, $ae] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Alice shared');

        $this->roster([$this->dave => $this->alice]);
        $this->loginAs($this->dave);
        $this->sid = 'dave-ui-session';
        $this->sendCookieBack();
        $this->assertNull($this->session()->secretKey(), 'the UI session no longer serves a key');
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->dave, $phrase, self::IP));
        $this->assertVaultError('unlock_failed', fn () => $this->recovery()->useCode($this->dave, $code, Fixtures::NEW_PASSPHRASE, self::IP));
        $this->assertSame(['ok' => false, 'reason' => 'not_agent'], $this->asDave(AgentVault::encodeKey(random_bytes(32)))->getVaultEntries());

        // A session row the check above would kill on use; the conversion deletes it outright.
        $this->pdo()->prepare("INSERT INTO vault_sessions (sid_hash, user_id, nonce, enc_sk, created_at, last_used_at, idle_expires_at, abs_expires_at) VALUES ('stale', ?, 'n', 'c', ?, ?, ?, ?)")
            ->execute([$this->dave, $this->now, $this->now, $this->now + 900, $this->now + 3600]);

        $key = $this->enrolDave();
        $this->assertSame('agent', $this->row('SELECT kind FROM vault_principals WHERE user_id = ?', [$this->dave])['kind']);
        $this->assertSame(['agent'], $this->pdo()->query('SELECT method FROM vault_wraps WHERE user_id = '.$this->dave)->fetchAll(PDO::FETCH_COLUMN));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->dave]));
        $this->assertNotNull($this->agentGroup($this->dave));
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($key)->getVaultSecret($ae));
        $this->https();
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->dave, $phrase, self::IP));
        $this->assertVaultError('already_enrolled', fn () => $this->enrolDave());
    }

    // Final review I3 (R47, A8: grants to agents are Read only). A human holding Edit grants who is then adopted onto the
    // Agents roster and enrolled keeps the owner's grants through the conversion, but each Edit is downgraded to Read and
    // audited as grant (actor: the owner, target: the agent). Defence in depth: RecipientResolver caps an agent principal
    // at read even if an Edit row is written behind its back. Kills: the conversion keeping Edit; the downgrade not
    // audited; the resolver reporting edit for an agent.
    public function testConvertedHumanLosesEditAndResolverCapsAgentsAtRead(): void
    {
        $this->roster([]);
        $this->principals()->enrolHuman($this->dave, 'VaultFixtureSecret-davephrase-Mn7oP8');
        [$g, $e] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Alice edit share', false);
        $this->grants()->grant($this->alice, 'group', $g, $this->dave, 'edit', null, $this->aliceSk());
        $grantsBefore = count($this->auditRows('grant'));

        $this->roster([$this->dave => $this->alice]);
        $this->enrolDave();
        $this->assertSame('read', $this->row('SELECT permission FROM vault_grants WHERE grantee_id = ? AND subject_id = ?', [$this->dave, $g])['permission']);
        $added = array_slice($this->auditRows('grant'), $grantsBefore);
        $this->assertSame(
            [[$this->alice, 'group', $g, $this->dave]],
            array_map(fn ($r) => [(int) $r['actor_user_id'], $r['object_type'], (int) $r['object_id'], (int) $r['target_user_id']], array_values(array_filter($added, fn ($r) => (int) $r['target_user_id'] === $this->dave)))
        );

        $this->pdo()->prepare("UPDATE vault_grants SET permission = 'edit' WHERE grantee_id = ?")->execute([$this->dave]);
        $resolver = new \Kanboard\Plugin\Vault\Model\RecipientResolver($this->container);
        $this->assertSame('read', $resolver->effective('entry', $e, $this->now)[$this->dave] ?? null, 'an agent is capped at read');
        $this->assertSame('owner', $resolver->effective('group', $this->agentGroup($this->dave), $this->now)[$this->dave] ?? null, 'its own group stays its own');
    }

    // T7 carry / spec "Removals while nobody is unlocked": disabling an agent removes every grant source to it through
    // removeSource (its key rows go, the objects are queued and later re-keyed, each removal audited as revoke), on the
    // purge and before any write. Its "Agent-created" group stays readable by the owner. Kills: a bare DELETE of the
    // grants (key rows kept, nothing queued); the sweep missing from the purge or from beforeWrite; the owner's grant on
    // the agent's group removed too.
    public function testDisabledAgentLosesGrantsThroughRemoveSource(): void
    {
        $key = $this->enrolDave();
        $own = $this->asDave($key)->createVaultEntry(['title' => 'Made by dave'])['entry_id'];
        [$ag, $ae] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Alice shared');
        $epoch = $this->epoch('entry', $ae);

        $this->container['userModel']->disable($this->dave);
        (new Purger($this->container))->run($this->now, true);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$this->dave]));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND ((object_type = 'group' AND object_id = ?) OR (object_type = 'entry' AND object_id = ?))", [$this->dave, $ag, $ae]));
        $this->assertEqualsCanonicalizing(['entry:'.$ae, 'group:'.$ag], $this->queuedRefs());
        $this->assertSame([[null, $this->dave]], array_map(fn ($r) => [$r['actor_user_id'], (int) $r['target_user_id']], $this->auditRows('revoke')));
        $this->assertSame('Made by dave', $this->store()->readEntry($this->alice, $own, $this->aliceSk())['payload']['title'], 'the owner keeps the agent group');
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ? AND subject_id = ?', [$this->alice, $this->agentGroup($this->dave)]));

        // Re-enabled and re-shared, then disabled again: the next write sweeps first and is re-keyed inline.
        $this->container['userModel']->enable($this->dave);
        $this->grants()->grant($this->alice, 'group', $ag, $this->dave, 'read', null, $this->aliceSk());
        $epoch = $this->epoch('entry', $ae);
        $this->container['userModel']->disable($this->dave);
        $this->store()->updateEntry($this->alice, $ae, 1, Fixtures::entry('edited'), $this->aliceSk());
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$this->dave]));
        $this->assertSame($epoch + 1, $this->epoch('entry', $ae), 're-keyed before the write');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND object_type = ? AND object_id = ?', [$this->dave, 'entry', $ae]));
    }

    // Final review M1: a new entry or group in a group still shared with a just-disabled agent was sealed to that agent
    // until the next purge (up to a minute). Both create paths sweep disabled agents first, as beforeWrite does.
    // Kills: the sweep missing from createEntry or from createGroup.
    public function testCreateInGroupSharedWithDisabledAgentIsNotSealedToIt(): void
    {
        $this->enrolDave();
        [$g] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Alice shared');
        $this->container['userModel']->disable($this->dave);

        $e = $this->store()->createEntry($this->alice, $g, Fixtures::entry('After disable'));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND object_type = 'entry' AND object_id = ?", [$this->dave, $e]), 'createEntry');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants WHERE grantee_id = ?', [$this->dave]));

        $this->container['userModel']->enable($this->dave);
        $this->grants()->grant($this->alice, 'group', $g, $this->dave, 'read', null, $this->aliceSk());
        $this->container['userModel']->disable($this->dave);
        $sub = $this->store()->createGroup($this->alice, $g, ['name' => 'After disable sub']);
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND object_type = 'group' AND object_id = ?", [$this->dave, $sub]), 'createGroup');
    }

    // T10 minor: the agent's owner sees the agent's audit rows in the activity view; nobody else does.
    // Kills: AuditModel::visibleTo without the roster branch.
    public function testOwnerSeesTheAgentsRows(): void
    {
        $key = $this->enrolDave();
        [, $ae] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Alice shared');
        $this->asDave($key)->getVaultSecret($ae);
        $this->asDave(AgentVault::encodeKey(random_bytes(32)))->getVaultEntries();
        $mine = fn (int $viewer) => array_values(array_filter(AuditModel::of($this->container)->visibleTo($viewer, 0, 200), fn ($r) => $r['actor_user_id'] === $this->dave && in_array($r['action'], ['read', 'bad_vault_key'], true)));
        $this->assertSame(['bad_vault_key', 'read'], array_column($mine($this->alice), 'action'));
        $this->assertSame([], $mine($this->carol));
        $this->assertSame([], $mine($this->bob));
    }

    // Spec, Throttling: reads per hour are min(owner setting, admin maximum), default 60, with a burst of 10 (never more
    // than the cap). Only the owner sets the cap. Kills: max instead of min; the burst not capped; another user setting it.
    public function testReadCapIsTheLowerOfOwnerAndAdmin(): void
    {
        $key = $this->enrolDave();
        [, $ae] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Alice shared');
        $this->assertSame(60, $this->agentVault()->readCap($this->dave));
        $this->agentVault()->setReadCap($this->alice, $this->dave, 5);
        $this->assertVaultError('not_found', fn () => $this->agentVault()->setReadCap($this->carol, $this->dave, 500));
        $this->assertVaultError('payload_invalid', fn () => $this->agentVault()->setReadCap($this->alice, $this->dave, 0));
        $this->assertSame(5, $this->agentVault()->readCap($this->dave));
        $ok = 0;
        for ($i = 0; $i < 8; $i++) {
            $ok += $this->asDave($key)->getVaultSecret($ae)['ok'] ? 1 : 0;
        }
        $this->assertSame(5, $ok, 'burst = min(10, cap)');
        $this->settings()->set('vault_agent_cap_max', 3, self::ADMIN);
        $this->assertSame(3, $this->agentVault()->readCap($this->dave));
        $this->agentVault()->setReadCap($this->alice, $this->dave, 500);
        $this->assertSame(3, $this->agentVault()->readCap($this->dave));
    }

    // Spec, Throttling: the agent read cap is atomic under concurrency: 8 processes, each on its own connection, race 3
    // reads each through readSecret on a burst of 10 with no refill. Exactly 10 values come back, each audited. Kills: a
    // cap read and written outside one locked transaction (more than 10 served); reads not audited.
    public function testReadCapAtomic(): void
    {
        if (! function_exists('pcntl_fork') || ! function_exists('posix_kill')) {
            $this->markTestSkipped('pcntl and posix are needed for the concurrency test');
        }
        $path = VaultTestFileDb::create();
        $dir = sys_get_temp_dir().'/vault-t16-'.bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        try {
            $now = 1_800_000_000;
            $pdo = VaultTestFileDb::connect($path);
            $pdo->exec('CREATE TABLE settings ("option" TEXT PRIMARY KEY, value TEXT, changed_by INTEGER, changed_on INTEGER)');
            $sk = [];
            foreach ([1 => 'human', 2 => 'agent'] as $id => $kind) {
                $kp = sodium_crypto_box_keypair();
                $pdo->prepare('INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at, live_user_id) VALUES (?, ?, ?, 1, ?, ?, ?)')
                    ->execute([$id, $kind, base64_encode(sodium_crypto_box_publickey($kp)), 'active', $now, $id]);
                $sk[$id] = sodium_crypto_box_secretkey($kp);
            }
            $c = $this->fileContainer($path, $now);
            $g = (new ObjectStore($c, fn () => $now))->createGroup(1, null, ['name' => 'Shared']);
            $e = (new ObjectStore($c, fn () => $now))->createEntry(1, $g, Fixtures::entry('Raced'));
            (new GrantModel($c, fn () => $now))->grant(1, 'group', $g, 2, 'read', null, $sk[1]);

            $start = microtime(true) + 0.5;
            $pids = [];
            for ($i = 0; $i < 8; $i++) {
                $pid = pcntl_fork();
                $this->assertNotSame(-1, $pid, 'fork failed');
                if ($pid === 0) {
                    try {
                        $vault = new AgentVault($this->fileContainer($path, $now), fn () => $now);
                        while (microtime(true) < $start) {
                            usleep(100);
                        }
                        $out = '';
                        for ($n = 0; $n < 3; $n++) {
                            try {
                                $out .= $vault->readSecret(2, $sk[2], $e, 'password', '203.0.113.7') === Fixtures::ENTRY_PASSWORD ? '1' : 'X';
                            } catch (VaultException $ex) {
                                $out .= $ex->errorCode() === 'rate_limited' ? '0' : 'E';
                            }
                        }
                    } catch (\Throwable $ex) {
                        $out = 'E:'.get_class($ex);
                    }
                    file_put_contents("$dir/$i", $out);
                    posix_kill(getmypid(), SIGKILL);
                }
                $pids[] = $pid;
            }
            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
            }
            $results = [];
            for ($i = 0; $i < 8; $i++) {
                $results[] = (string) @file_get_contents("$dir/$i");
            }
            $this->assertSame([], array_values(array_filter($results, fn ($r) => ! preg_match('/^[01]{3}$/D', $r))), 'every worker finished cleanly: '.implode(',', $results));
            $this->assertSame(10, substr_count(implode('', $results), '1'), implode(',', $results));
            $check = VaultTestFileDb::connect($path);
            $this->assertSame(10, (int) $check->query("SELECT COUNT(*) FROM vault_audit WHERE action = 'read' AND actor_user_id = 2")->fetchColumn());
        } finally {
            foreach (glob($dir.'/*') ?: [] as $f) {
                unlink($f);
            }
            @rmdir($dir);
            VaultTestFileDb::remove($path);
        }
    }

    private function fileContainer(string $path, int $now): \Pimple\Container
    {
        $c = VaultTestFileDb::container(VaultTestFileDb::connect($path, 20));
        $c['logger'] = new \Psr\Log\NullLogger();
        $c['vaultNotifier'] = new class($c) extends \Kanboard\Plugin\Vault\Model\Notifier {
            protected function send(int $userId, string $subject, string $html): bool
            {
                return false;
            }
        };
        return $c;
    }

    // The re-key queue as "type:id", sorted (built in PHP: || is OR on MySQL).
    private function queuedRefs(): array
    {
        $refs = array_map(fn (array $r): string => $r['object_type'].':'.$r['object_id'], $this->pdo()->query('SELECT object_type, object_id FROM vault_rekey_queue')->fetchAll(PDO::FETCH_ASSOC));
        sort($refs);
        return $refs;
    }
}
