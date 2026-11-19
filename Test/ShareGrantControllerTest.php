<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';

use Kanboard\Core\Http\Request;
use Kanboard\Core\Security\Role;
use Kanboard\Plugin\Vault\Controller\ShareGrantController;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Records every afterWrite call; the real work still runs.
class VaultShareSpyHousekeeping extends Housekeeping
{
    public array $writes = [];

    public function afterWrite(int $userId, #[\SensitiveParameter] string $sk): void
    {
        $this->writes[] = $userId;
        parent::afterWrite($userId, $sk);
    }
}

// Spec: UI → The sharing dialog; Entries, groups and grants (grant, revoke, expiry, enrolled grantees, only the owner
// grants or revokes, revocation suggests rotating); Agents (they read, never write what a human shared); Audit → Who
// sees what. Alice, Bob and Carol share Kanboard project "Ops"; Dave is in no project of theirs.
class ShareGrantControllerTest extends Base
{
    use ServiceFixture;

    private int $carol;
    private int $dave;
    private int $project;
    private VaultShareSpyHousekeeping $hk;

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpVault();
        $this->carol = (int) $this->container['userModel']->create(['username' => 'carol', 'password' => 'carol login password 1']);
        $this->dave = (int) $this->container['userModel']->create(['username' => 'dave', 'name' => 'Dave Outside', 'password' => 'dave login password 1']);
        $this->project = (int) $this->container['projectModel']->create(['name' => 'Ops']);
        foreach ([$this->alice, $this->bob, $this->carol] as $u) {
            $this->container['projectUserRoleModel']->addUser($this->project, $u, Role::PROJECT_MEMBER);
        }
        $this->container['vaultUnlock'] = fn () => $this->unlockService();
        $this->container['vaultPrincipals'] = fn () => $this->principals();
        $this->hk = new VaultShareSpyHousekeeping($this->container, $this->clock(), $this->rotation());
        $this->container['vaultHousekeeping'] = fn () => $this->hk;
        $this->container['vaultStore'] = fn () => $this->store();
        $this->container['vaultGrants'] = fn () => $this->grants();
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->loginAs($this->alice);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function token(): string
    {
        return $this->container['token']->getReusableCSRFToken();
    }

    private function call(string $controller, string $action, string $method = 'POST', array $post = []): VaultTestResponse
    {
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        $this->container['request'] = new Request($this->container, [
            'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest', 'REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example',
            'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => '203.0.113.7',
        ], [], $post, [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new $controller($this->container))->$action();
        return $response;
    }

    private function post(string $action, array $post = []): VaultTestResponse
    {
        return $this->call(ShareGrantController::class, $action, 'POST', $post + ['csrf_token' => $this->token()]);
    }

    private function unlock(int $userId, string $passphrase): void
    {
        $this->sid = 'php-session-'.$userId;
        $this->loginAs($userId);
        $r = $this->call(VaultController::class, 'unlock', 'POST', ['passphrase' => $passphrase, 'csrf_token' => $this->token()]);
        $this->assertSame(['ok' => true], $r->json_(), 'unlocked');
    }

    private function aliceSk(): string
    {
        return $this->skFor($this->alice, Fixtures::PASSPHRASE);
    }

    private function bobSk(): string
    {
        return $this->skFor($this->bob, Fixtures::BOB_PASSPHRASE);
    }

    private function group(?int $parent = null, string $name = 'Infra', ?int $owner = null): int
    {
        return $this->store()->createGroup($owner ?? $this->alice, $parent, ['name' => $name]);
    }

    private function entry(int $group, string $title = 'Postgres', ?int $owner = null): int
    {
        return $this->store()->createEntry($owner ?? $this->alice, $group, Fixtures::entry($title));
    }

    private function grantRows(): array
    {
        $s = $this->pdo()->query('SELECT subject_type, subject_id, grantee_id, permission, expires_at FROM vault_grants ORDER BY id');
        return array_map(static fn (array $r): array => [$r['subject_type'], (int) $r['subject_id'], (int) $r['grantee_id'], $r['permission'], $r['expires_at'] === null ? null : (int) $r['expires_at']], $s->fetchAll(\PDO::FETCH_ASSOC));
    }

    private function assertFailure(VaultTestResponse $r, int $status, string $reason, string $what = ''): void
    {
        $this->assertSame([$status, ['ok' => false, 'reason' => $reason]], [$r->status, $r->json_()], $what);
        $this->assertSame('DENY', $r->headers['X-Frame-Options'] ?? null, "$what: hardened");
    }

    // An enrolled agent principal (a real keypair, kind agent), as T16's enrolment leaves it.
    private function agent(string $username): int
    {
        $id = (int) $this->container['userModel']->create(['username' => $username, 'password' => 'agent unusable password 1']);
        $kp = sodium_crypto_box_keypair();
        $this->pdo()->prepare("INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at, live_user_id) VALUES (?, 'agent', ?, 1, 'active', ?, ?)")
            ->execute([$id, base64_encode(sodium_crypto_box_publickey($kp)), $this->now, $id]);
        return $id;
    }

    // Spec: "Only the owner can grant, revoke, delete or move objects." An edit grantee holds the DEK, so only the gate
    // stops them. Every refusal is the generic not_found (no existence oracle), nothing changes, and the owner's grant
    // list stays private. Kills: the grant or revoke gate accepting edit; the sharing view without an owner check.
    public function testNonOwnerGrantForbidden(): void
    {
        $g = $this->group();
        $e = $this->entry($g);
        $this->principals()->enrolHuman($this->carol, 'VaultFixtureSecret-carolphrase-Ab1cD2');
        $this->grants()->grant($this->alice, 'group', $g, $this->bob, 'edit', null, $this->aliceSk());
        $before = $this->grantRows();
        $this->unlock($this->bob, Fixtures::BOB_PASSPHRASE);

        foreach ([['entry', $e], ['group', $g]] as [$type, $id]) {
            $r = $this->post('grant', ['type' => $type, 'id' => $id, 'grantee_id' => $this->carol, 'perm' => 'read', 'confirm' => 1]);
            $this->assertFailure($r, 404, 'not_found', "grant on $type");
            $this->assertFailure($this->post('sharing', ['type' => $type, 'id' => $id]), 404, 'not_found', "sharing view of $type");
        }
        $this->assertFailure($this->post('revoke', ['type' => 'group', 'id' => $g, 'grantee_id' => $this->bob]), 404, 'not_found', 'revoke');
        $this->assertFailure($this->post('grant', ['type' => 'group', 'id' => $g, 'grantee_id' => $this->carol, 'perm' => 'read']), 404, 'not_found', 'group preview');
        $this->assertSame($before, $this->grantRows(), 'nothing changed');
        $this->assertSame([], $this->hk->writes);
        $this->assertSame(1, count($this->auditRows('grant')), 'only alice\'s own grant');
    }

    // Spec: "When sharing a group, it warns how many entries that covers." Without confirm the answer is the count and
    // nothing is granted; with confirm the grant is made and the count comes back again. The count is the whole subtree.
    // Kills: counting only direct entries; counting other groups' entries; granting without the confirmation step.
    public function testGroupGrantReportsCoveredCount(): void
    {
        $g = $this->group();
        $sub = $this->group($g, 'DNS');
        $this->entry($g, 'one');
        $this->entry($g, 'two');
        $deep = $this->entry($sub, 'three');
        $this->entry($this->group(null, 'Other'), 'elsewhere');
        $this->unlock($this->alice, Fixtures::PASSPHRASE);

        $r = $this->post('grant', ['type' => 'group', 'id' => $g, 'grantee_id' => $this->bob, 'perm' => 'read']);
        $this->assertSame(['ok' => true, 'confirm_required' => true, 'covered_entries' => 3], $r->json_());
        $this->assertSame([], $this->grantRows(), 'nothing granted before the confirmation');
        $this->assertSame(3, $this->post('sharing', ['type' => 'group', 'id' => $g])->json_()['covered_entries']);

        $r = $this->post('grant', ['type' => 'group', 'id' => $g, 'grantee_id' => $this->bob, 'perm' => 'read', 'confirm' => 1]);
        $this->assertSame(['ok' => true, 'covered_entries' => 3], $r->json_());
        $this->assertSame([['group', $g, $this->bob, 'read', null]], $this->grantRows());
        $this->assertSame('three', $this->store()->readEntry($this->bob, $deep, $this->bobSk())['payload']['title']);
        $this->assertSame([$this->alice], $this->hk->writes, 'the grant is a write');

        // An entry is one entry: no confirmation step, no count.
        $one = $this->entry($this->group(null, 'Solo'), 'solo');
        $r = $this->post('grant', ['type' => 'entry', 'id' => $one, 'grantee_id' => $this->bob, 'perm' => 'edit']);
        $this->assertSame(['ok' => true], $r->json_());
        $this->assertSame(['entry', $one, $this->bob, 'edit', null], $this->grantRows()[1]);
    }

    // Spec, Revocation: the owner revokes, the object is re-keyed, and "afterwards the UI suggests rotating the secrets
    // themselves". Kills: the answer without suggest_rotate; the revoke not reaching GrantModel::revoke (no re-key);
    // no afterWrite; a refused revoke that still suggests rotation.
    public function testRevokeSuggestsRotation(): void
    {
        $g = $this->group();
        $e = $this->entry($g);
        $this->grants()->grant($this->alice, 'entry', $e, $this->bob, 'read', null, $this->aliceSk());
        $this->unlock($this->alice, Fixtures::PASSPHRASE);

        $this->assertFailure($this->post('revoke', ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->carol]), 404, 'not_found', 'no such grant');
        $r = $this->post('revoke', ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->bob]);
        $this->assertSame(['ok' => true, 'suggest_rotate' => true], $r->json_());
        $this->assertSame([], $this->grantRows());
        $this->assertSame(2, (int) $this->row('SELECT key_epoch FROM vault_entries WHERE id = ?', [$e])['key_epoch'], 're-keyed');
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->bob, $e, $this->bobSk()));
        $this->assertSame([$this->alice], $this->hk->writes);
        $rv = $this->auditRows('revoke')[0];
        $this->assertSame([$this->alice, 'entry', $e, $this->bob], [(int) $rv['actor_user_id'], $rv['object_type'], (int) $rv['object_id'], (int) $rv['target_user_id']]);
    }

    // Spec, Who sees what: the activity view shows exactly the rows AuditModel::visibleTo allows, newest first; object
    // titles only for objects the viewer can decrypt; names, never another user's private rows. Kills: listing every
    // audit row; titles for objects the viewer can't read; the viewer id taken from the request.
    public function testActivityHidesOthersRows(): void
    {
        $g = $this->group();
        $shared = $this->entry($g, 'Shared one');
        $this->grants()->grant($this->alice, 'entry', $shared, $this->bob, 'read', null, $this->aliceSk());
        $bobGroup = $this->group(null, 'Bob private', $this->bob);
        $bobEntry = $this->entry($bobGroup, 'Bob secret title', $this->bob);
        AuditModel::of($this->container)->record('read', ['actor_user_id' => $this->bob, 'object_type' => 'entry', 'object_id' => $bobEntry]);
        AuditModel::of($this->container)->record('read', ['actor_user_id' => $this->bob, 'object_type' => 'entry', 'object_id' => $shared]);
        $this->unlock($this->alice, Fixtures::PASSPHRASE);

        $r = $this->post('activity', ['offset' => 0, 'viewer_id' => $this->bob]);
        $rows = $r->json_()['rows'];
        $expected = array_column(AuditModel::of($this->container)->visibleTo($this->alice, 0, 50), 'id');
        $this->assertSame($expected, array_column($rows, 'id'), 'exactly visibleTo, newest first');
        $this->assertNotEmpty($rows);
        $bobOnly = array_map('intval', array_column(array_filter($this->auditRows(), fn (array $a): bool => (int) $a['actor_user_id'] === $this->bob && ! ((int) $a['object_id'] === $shared && $a['object_type'] === 'entry')), 'id'));
        $this->assertNotEmpty($bobOnly);
        $this->assertSame([], array_values(array_intersect($bobOnly, array_column($rows, 'id'))), 'none of bob\'s own rows');
        $this->assertStringNotContainsString('Bob secret title', $r->body);
        $this->assertStringNotContainsString('Bob private', $r->body);

        $byId = array_column($rows, null, 'id');
        $bobRead = (int) $this->row("SELECT MAX(id) AS id FROM vault_audit WHERE action = 'read'")['id'];
        $this->assertSame(['read', 'bob', 'entry', $shared, 'Shared one'], [$byId[$bobRead]['action'], $byId[$bobRead]['actor'], $byId[$bobRead]['object_type'], $byId[$bobRead]['object_id'], $byId[$bobRead]['title']], 'the owner sees reads of her entry, titled');
        $grant = array_values(array_filter($rows, fn (array $x): bool => $x['action'] === 'grant'))[0];
        $this->assertSame(['alice-the-auditor', 'bob'], [$grant['actor'], $grant['target']]);
        $this->assertNoSecretIn($r->body);
        $this->assertSame('no-store', $r->headers['Cache-Control'] ?? null);

        // A row on an object the viewer can't decrypt carries no title (here: a deleted entry).
        $this->store()->deleteObject($this->alice, 'entry', $shared, $this->aliceSk());
        $rows = $this->post('activity', ['offset' => 0])->json_()['rows'];
        foreach ($rows as $row) {
            if ($row['object_type'] === 'entry' && $row['object_id'] === $shared) {
                $this->assertNull($row['title']);
            }
        }
    }

    // The activity view pages: ShareGrantController::ACTIVITY_PAGE rows, then next_offset; null on the last page.
    // Kills: no page limit; the offset ignored; a next_offset on the last page.
    public function testActivityPaginates(): void
    {
        $g = $this->group();
        for ($i = 0; $i < ShareGrantController::ACTIVITY_PAGE + 7; $i++) {
            AuditModel::of($this->container)->record('update', ['actor_user_id' => $this->alice, 'object_type' => 'group', 'object_id' => $g]);
        }
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $total = count(AuditModel::of($this->container)->visibleTo($this->alice, 0, 200));
        $first = $this->post('activity', ['offset' => 0])->json_();
        $this->assertCount(ShareGrantController::ACTIVITY_PAGE, $first['rows']);
        $this->assertSame(ShareGrantController::ACTIVITY_PAGE, $first['next_offset']);
        $second = $this->post('activity', ['offset' => $first['next_offset']])->json_();
        $this->assertCount($total - ShareGrantController::ACTIVITY_PAGE, $second['rows']);
        $this->assertNull($second['next_offset']);
        $this->assertSame([], array_intersect(array_column($first['rows'], 'id'), array_column($second['rows'], 'id')));
        $onGroup = array_values(array_filter($first['rows'], fn (array $r): bool => $r['object_type'] === 'group'));
        $this->assertSame(['Infra', $g], [$onGroup[0]['title'], $onGroup[0]['object_id']]);
    }

    // Spec: grantees must be enrolled. The picker never shows more of the user directory than Kanboard shows the actor:
    // like Kanboard's own member pickers (mention, assignees), the people who share a project with them, plus their own
    // agents; an app admin, who sees Kanboard's whole user list, sees every enrolled user. A grant outside that set is the
    // generic not_found; a visible user without a vault is not_enrolled; a disabled user is not offered.
    // Kills: listing every enrolled user; listing unenrolled users; the grant not re-checking the picker's scope;
    // not_enrolled lost; disabled users offered.
    public function testGranteesMustBeEnrolledAndVisible(): void
    {
        $this->principals()->enrolHuman($this->dave, 'VaultFixtureSecret-davephrase-Ef3gH4');
        // Alice's own agent is offered though it shares no project with her (when Agents is installed).
        $this->agentsTable();
        $agent = $this->agent('alice.claude');
        $this->adoptAgent($this->alice, $agent);
        $agents = class_exists('\\Kanboard\\Plugin\\Agents\\Model\\AgentTable');
        $e = $this->entry($this->group());
        $this->unlock($this->alice, Fixtures::PASSPHRASE);

        $c = $this->post('sharing', ['type' => 'entry', 'id' => $e])->json_();
        $bob = ['id' => $this->bob, 'name' => 'bob', 'kind' => 'human'];
        $this->assertSame($agents ? [['id' => $agent, 'name' => 'alice.claude', 'kind' => 'agent'], $bob] : [$bob], $c['candidates']);
        $this->assertSame([], $c['grants']);

        $this->assertFailure($this->post('grant', ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->dave, 'perm' => 'read']), 404, 'not_found', 'dave is outside alice\'s projects');
        $this->assertFailure($this->post('grant', ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->carol, 'perm' => 'read']), 409, 'not_enrolled', 'carol has no vault');
        $this->assertFailure($this->post('grant', ['type' => 'entry', 'id' => $e, 'grantee_id' => 9999, 'perm' => 'read']), 404, 'not_found', 'no such user');
        $this->assertSame([], $this->grantRows());

        $this->assertSame(['ok' => true], $this->post('grant', ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->bob, 'perm' => 'read'])->json_());
        $grants = $this->post('sharing', ['type' => 'entry', 'id' => $e])->json_()['grants'];
        $this->assertSame([['grantee_id' => $this->bob, 'name' => 'bob', 'kind' => 'human', 'permission' => 'read', 'expires_at' => null]], $grants);

        // Bob is disabled in Kanboard: no longer offered, and no new grant.
        $this->container['userModel']->disable($this->bob);
        $ids = array_column($this->post('sharing', ['type' => 'entry', 'id' => $e])->json_()['candidates'], 'id');
        $this->assertNotContains($this->bob, $ids);
        $this->assertFailure($this->post('grant', ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->bob, 'perm' => 'edit']), 404, 'not_found', 'disabled');

        // The app admin sees Kanboard's whole user list, so every enrolled, active user.
        $this->principals()->enrolHuman(self::ADMIN, 'VaultFixtureSecret-adminphrase-Ij5kL6');
        $adminGroup = $this->group(null, 'Admin', self::ADMIN);
        $this->unlock(self::ADMIN, 'VaultFixtureSecret-adminphrase-Ij5kL6');
        $ids = array_column($this->post('sharing', ['type' => 'group', 'id' => $adminGroup])->json_()['candidates'], 'id');
        $this->assertSame([$this->alice, $agent, $this->dave], $ids, 'sorted by name');
        $this->assertSame(['ok' => true, 'covered_entries' => 0], $this->post('grant', ['type' => 'group', 'id' => $adminGroup, 'grantee_id' => $this->dave, 'perm' => 'read', 'confirm' => 1])->json_());
    }

    // Spec: "a permission (Read or Edit) and an optional expiry", which must be in the future. Kills: a past or present
    // expiry accepted; a non-numeric expiry read as 0 (no expiry); a perm other than read|edit accepted.
    public function testExpiryMustBeInTheFuture(): void
    {
        $e = $this->entry($this->group());
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $base = ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->bob, 'perm' => 'read'];
        foreach ([$this->now, $this->now - 1, 'tomorrow', '-5', '1e9'] as $bad) {
            $this->assertFailure($this->post('grant', ['expires_at' => $bad] + $base), 400, 'payload_invalid', "expiry $bad");
        }
        $this->assertFailure($this->post('grant', ['perm' => 'owner'] + $base), 400, 'payload_invalid', 'perm owner');
        $g = $this->group(null, 'G');
        $this->assertFailure($this->post('grant', ['type' => 'group', 'id' => $g, 'perm' => 'owner'] + $base), 400, 'payload_invalid', 'perm owner, group preview');
        $this->assertSame([], $this->grantRows());
        $this->assertSame(['ok' => true], $this->post('grant', ['expires_at' => $this->now + 3600] + $base)->json_());
        $this->assertSame([['entry', $e, $this->bob, 'read', $this->now + 3600]], $this->grantRows());
    }

    // Spec, Agents (decision 5): agents read what is granted to them and never overwrite entries a human shared, so a
    // grant to an agent is Read only (enforced in GrantModel, so the T16 API path is bound too). The picker marks agents.
    // Kills: an edit grant to an agent accepted.
    public function testAgentGranteesAreReadOnly(): void
    {
        $agent = $this->agent('ops.bot');
        $this->container['projectUserRoleModel']->addUser($this->project, $agent, Role::PROJECT_MEMBER);
        $g = $this->group();
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $this->assertFailure($this->post('grant', ['type' => 'group', 'id' => $g, 'grantee_id' => $agent, 'perm' => 'edit', 'confirm' => 1]), 422, 'agent_read_only', 'edit to an agent');
        $this->assertSame([], $this->grantRows());
        $this->assertSame(['ok' => true, 'covered_entries' => 0], $this->post('grant', ['type' => 'group', 'id' => $g, 'grantee_id' => $agent, 'perm' => 'read', 'confirm' => 1])->json_());
        $this->assertSame([['group', $g, $agent, 'read', null]], $this->grantRows());
    }

    // Spec: every state change is a POST with the CSRF token; failures are generic; every answer is hardened.
    // Kills: GET or a missing token accepted; a locked session served; an unknown type reaching the model.
    public function testShareEndpointsArePostCsrfAndGeneric(): void
    {
        $e = $this->entry($this->group());
        foreach (['grant', 'revoke', 'sharing', 'activity'] as $action) {
            $this->sid = 'php-session-locked';
            $this->assertFailure($this->post($action, ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->bob, 'perm' => 'read']), 401, 'locked', "$action locked");
        }
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        foreach (['grant', 'revoke', 'sharing', 'activity'] as $action) {
            $get = $this->call(ShareGrantController::class, $action, 'GET', ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->bob, 'perm' => 'read', 'csrf_token' => $this->token()]);
            $this->assertFailure($get, 403, 'forbidden', "$action GET");
            $noToken = $this->call(ShareGrantController::class, $action, 'POST', ['type' => 'entry', 'id' => $e, 'grantee_id' => $this->bob, 'perm' => 'read']);
            $this->assertFailure($noToken, 403, 'forbidden', "$action without token");
        }
        $this->assertFailure($this->post('grant', ['type' => 'project', 'id' => $e, 'grantee_id' => $this->bob, 'perm' => 'read']), 400, 'failed', 'unknown type');
        $this->assertSame([], $this->grantRows());
    }

    // The unlocked shell carries the dialog, the activity view and vault-share.js (no inline JS); the dialog's form
    // posts natively with the CSRF token, never as a GET; the locked page has none of it. Kills: the shell without the
    // script or a template; the form without method or token; the dialog on the locked page.
    public function testShellCarriesTheDialogAndActivity(): void
    {
        $locked = $this->call(VaultController::class, 'index', 'GET');
        $this->assertStringNotContainsString('vault-share.js', $locked->body);
        $this->assertStringNotContainsString('data-vault-share', $locked->body);
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $html = $this->call(VaultController::class, 'index', 'GET')->body;
        $this->assertSame(1, preg_match('~<script [^>]*src="[^"]*plugins/Vault/Assets/js/vault-share\.js~', $html));
        $this->assertStringNotContainsString('<script>', $html, 'no inline script');
        $doc = new DOMDocument();
        @$doc->loadHTML($html);
        $xp = new DOMXPath($doc);
        $form = $xp->query('//section[@data-vault-share]//form[@data-vault-form="share"]')->item(0);
        $this->assertNotNull($form);
        $this->assertSame('post', strtolower($form->getAttribute('method')));
        $this->assertStringContainsString('grant', $form->getAttribute('action'));
        $this->assertSame(1, $xp->query('.//input[@type="hidden"][@name="csrf_token"][@value!=""]', $form)->length);
        $this->assertSame(1, $xp->query('//section[@data-vault-activity]//tbody[@data-vault-activity-rows]')->length);
        $this->assertSame(1, $xp->query('//button[@data-vault-action="activity"]')->length);
        $endpoints = json_decode($xp->query('//*[@id="vault-app"]')->item(0)->getAttribute('data-endpoints'), true);
        foreach (['sharing', 'grant', 'revoke', 'activity'] as $a) {
            $this->assertArrayHasKey($a, $endpoints);
        }
    }

    private function assertNoSecretIn(string $body): void
    {
        foreach ([Fixtures::ENTRY_PASSWORD, Fixtures::ENTRY_NOTES, Fixtures::ENTRY_OTP, Fixtures::FIELD_VALUE, Fixtures::PASSPHRASE] as $s) {
            $this->assertStringNotContainsString($s, $body);
        }
    }
}
