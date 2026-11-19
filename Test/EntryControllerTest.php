<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Controller\EntryController;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Records every afterWrite call; the real work still runs.
class VaultSpyHousekeeping extends Housekeeping
{
    public array $writes = [];

    public function afterWrite(int $userId, #[\SensitiveParameter] string $sk): void
    {
        $this->writes[] = $userId;
        parent::afterWrite($userId, $sk);
    }
}

// Spec: UI (layout, secrets never in the HTML, copy, escaping) and Audit (read). Carries: R18, R23, R28, R29,
// Housekeeping::afterWrite on every write, requireUnlocked()'s two branches (T11 M5), generic errors.
class EntryControllerTest extends Base
{
    use ServiceFixture;

    private const PLAIN_FIELD = 'VaultFixtureSecret-plainfield-Rk2wQ8';

    private VaultSpyHousekeeping $hk;

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpVault();
        $this->container['vaultUnlock'] = fn () => $this->unlockService();
        $this->container['vaultPrincipals'] = fn () => $this->principals();
        $this->hk = new VaultSpyHousekeeping($this->container, $this->clock(), $this->rotation());
        $this->container['vaultHousekeeping'] = fn () => $this->hk;
        $this->container['vaultStore'] = fn () => $this->store();
        $this->container['vaultGrants'] = fn () => $this->grants();
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

    // One request, as VaultControllerTest makes them: HTTPS on kb.example from 203.0.113.7, the last cookie sent back,
    // POSTs from vault.js (X-Requested-With) unless $ajax is false.
    private function call(string $controller, string $action, string $method = 'POST', array $post = [], ?bool $ajax = null): VaultTestResponse
    {
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        $server = ($ajax ?? $method === 'POST') ? ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'] : [];
        $this->container['request'] = new Request($this->container, $server + [
            'REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => '203.0.113.7',
        ], [], $post, [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new $controller($this->container))->$action();
        return $response;
    }

    private function post(string $action, array $post = [], ?bool $ajax = null): VaultTestResponse
    {
        return $this->call(EntryController::class, $action, 'POST', $post + ['csrf_token' => $this->token()], $ajax);
    }

    // Enrols $userId, logs them in and unlocks through the real endpoint (a fresh PHP session per user).
    private function unlock(int $userId, string $passphrase): void
    {
        if ($this->principals()->get($userId) === null) {
            $this->principals()->enrolHuman($userId, $passphrase);
        }
        $this->sid = 'php-session-'.$userId;
        $this->loginAs($userId);
        $r = $this->call(VaultController::class, 'unlock', 'POST', ['passphrase' => $passphrase, 'csrf_token' => $this->token()]);
        $this->assertSame(['ok' => true], $r->json_(), 'unlocked');
    }

    private function aliceSk(): string
    {
        return $this->skFor($this->alice, Fixtures::PASSPHRASE);
    }

    // Alice's group with one entry carrying every secret marker, a protected and a plain custom field.
    /** @return array{0:int,1:int} [group, entry] */
    private function aliceEntry(): array
    {
        $this->principals()->get($this->alice) ?? $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'Infra']);
        $payload = Fixtures::entry('Postgres');
        $payload['fields'][] = ['name' => 'region', 'value' => self::PLAIN_FIELD, 'protected' => false];
        return [$g, $this->store()->createEntry($this->alice, $g, $payload)];
    }

    private function assertHardened(VaultTestResponse $r, string $what): void
    {
        $this->assertTrue($r->sent, "$what: a response was sent");
        $this->assertSame('DENY', $r->headers['X-Frame-Options'] ?? null, "$what: X-Frame-Options");
        $this->assertStringContainsString("frame-ancestors 'none';", $r->headers['Content-Security-Policy'] ?? '', "$what: frame-ancestors");
        $this->assertSame('no-store', $r->headers['Cache-Control'] ?? null, "$what: no-store");
    }

    private function assertNoSecret(string $body, string $what): void
    {
        foreach ([Fixtures::ENTRY_PASSWORD, Fixtures::ENTRY_NOTES, Fixtures::ENTRY_OTP, Fixtures::FIELD_VALUE, self::PLAIN_FIELD, Fixtures::PASSPHRASE] as $secret) {
            $this->assertStringNotContainsString($secret, $body, "$what carries no secret");
        }
    }

    // Spec, Secrets never go into the HTML: the page, the tree, the list and the entry (the detail pane's data) carry
    // metadata only; password, notes, OTP seed and every custom field value (protected or not) come only from
    // vault/field. Kills: the entry answer returning the payload wholesale or any secret key; the list returning notes
    // or field values; the shell rendering an entry.
    public function testDetailHtmlHasNoSecret(): void
    {
        [$g, $e] = $this->aliceEntry();
        $this->unlock($this->alice, Fixtures::PASSPHRASE);

        $page = $this->call(VaultController::class, 'index', 'GET');
        $this->assertStringContainsString('data-vault-panes', $page->body);
        $this->assertStringContainsString('vault-browser.js', $page->body);
        $this->assertNoSecret($page->body, 'the shell');

        $tree = $this->post('tree');
        $this->assertSame('Infra', $tree->json_()['groups'][0]['name']);
        $this->assertNoSecret($tree->body, 'the tree');

        $list = $this->post('list', ['group_id' => $g]);
        $this->assertSame(['Postgres', 'fixture-user'], [$list->json_()['entries'][0]['title'], $list->json_()['entries'][0]['username']]);
        $this->assertNoSecret($list->body, 'the list');

        $entry = $this->post('entry', ['id' => $e]);
        $data = $entry->json_()['entry'];
        $this->assertSame(['Postgres', 'fixture-user', 'https://example.test/login', 'owner'], [$data['title'], $data['username'], $data['url'], $data['permission']]);
        $this->assertSame(['password' => true, 'notes' => true, 'otp' => true], $data['secrets']);
        $this->assertSame([['name' => 'api key', 'protected' => true], ['name' => 'region', 'protected' => false]], $data['fields']);
        $this->assertNoSecret($entry->body, 'the entry');
    }

    // Spec, Secrets never go into the HTML: "every reveal or copy is audited as read" (Audit: actor, object, ip_trunc).
    // A refused read writes no row. Kills: no audit; the audit written before the read succeeds (a row for a refusal);
    // the ip_trunc or object missing; a protected custom field reachable without the field:<name> form.
    public function testFieldEndpointAuditsRead(): void
    {
        [, $e] = $this->aliceEntry();
        $this->unlock($this->alice, Fixtures::PASSPHRASE);

        $r = $this->post('field', ['id' => $e, 'field' => 'password']);
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $r->json_());
        $r = $this->post('field', ['id' => $e, 'field' => 'field:api key']);
        $this->assertSame(Fixtures::FIELD_VALUE, $r->json_()['value']);

        $rows = $this->auditRows('read');
        $this->assertCount(2, $rows);
        foreach ($rows as $row) {
            $this->assertSame([$this->alice, 'entry', $e, '203.0.113.0/24'], [(int) $row['actor_user_id'], $row['object_type'], (int) $row['object_id'], $row['ip_trunc']]);
            $this->assertNull($row['ua_family']);
        }
        $this->assertStringNotContainsString(Fixtures::ENTRY_PASSWORD, json_encode($this->auditRows()), 'no value in the audit');

        $r = $this->post('field', ['id' => $e, 'field' => 'api key']);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']], 'a custom field only as field:<name>');
        $r = $this->post('field', ['id' => $e + 99, 'field' => 'password']);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']]);

        // Bob has no grant: the same generic not_found, and no read row.
        $this->unlock($this->bob, Fixtures::BOB_PASSPHRASE);
        $r = $this->post('field', ['id' => $e, 'field' => 'password']);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']]);
        $this->assertNoSecret($r->body, 'a refused read');
        $this->assertCount(2, $this->auditRows('read'), 'refusals are not audited as read');
    }

    // Spec: responses that carry secrets are no-store, and a secret is only ever returned to a POST with the CSRF
    // token. Kills: the field answer sent without respond() (no no-store / XFO); GET or a missing token accepted.
    public function testFieldNoStore(): void
    {
        [, $e] = $this->aliceEntry();
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $r = $this->post('field', ['id' => $e, 'field' => 'password']);
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $r->json_()['value']);
        $this->assertHardened($r, 'field');
        $this->assertSame('no-cache', $r->headers['Pragma'] ?? null);

        $get = $this->call(EntryController::class, 'field', 'GET', ['id' => $e, 'field' => 'password', 'csrf_token' => $this->token()], true);
        $this->assertSame([403, 'forbidden'], [$get->status, $get->json_()['reason']]);
        $noToken = $this->call(EntryController::class, 'field', 'POST', ['id' => $e, 'field' => 'password']);
        $this->assertSame([403, 'forbidden'], [$noToken->status, $noToken->json_()['reason']]);
        foreach ([$get, $noToken] as $refused) {
            $this->assertHardened($refused, 'refused');
            $this->assertStringNotContainsString(Fixtures::ENTRY_PASSWORD, $refused->body);
        }
        $this->assertCount(1, $this->auditRows('read'));
    }

    // T11 M5: requireUnlocked() answers vault.js with a hardened JSON 401 "locked", and a native POST with a hardened
    // 303 to the page; neither runs the action. Kills: the branches swapped; the guard falling through (no
    // ResponseSent); a locked request reaching the model.
    public function testLockedRequestsAreRefused(): void
    {
        [$g, $e] = $this->aliceEntry();
        $this->loginAs($this->alice);
        foreach (['tree' => [], 'list' => ['group_id' => $g], 'entry' => ['id' => $e], 'field' => ['id' => $e, 'field' => 'password'],
            'save' => ['type' => 'entry', 'group_id' => $g, 'payload' => json_encode(['title' => 'x'])], 'delete' => ['type' => 'entry', 'id' => $e],
            'move' => ['type' => 'entry', 'id' => $e, 'parent_id' => $g]] as $action => $post) {
            $r = $this->post($action, $post);
            $this->assertSame([401, ['ok' => false, 'reason' => 'locked']], [$r->status, $r->json_()], "$action (vault.js)");
            $this->assertHardened($r, $action);
            $native = $this->post($action, $post, false);
            $this->assertSame(303, $native->status, "$action (native)");
            $this->assertMatchesRegularExpression('~(/vault|controller=VaultController&action=index&plugin=Vault)$~', $native->headers['Location'] ?? '', 'back to the page, no code');
            $this->assertHardened($native, "$action native");
            $this->assertNoSecret($r->body.$native->body, $action);
        }
        $this->assertSame([], $this->auditRows('read'));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
        $this->assertSame([], $this->hk->writes);
    }

    // Spec, Edit permission: a read grantee can see and reveal but never write; an edit grantee can update. The save
    // goes through ObjectStore's gate (CAN_EDIT), and a create in a group needs edit on it. Kills: the controller
    // gating on "can read" or calling a store path that skips the gate.
    public function testReadGranteeCannotSave(): void
    {
        [$g, $e] = $this->aliceEntry();
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->grants()->grant($this->alice, 'group', $g, $this->bob, 'read', null, $this->aliceSk());
        $this->unlock($this->bob, Fixtures::BOB_PASSPHRASE);

        $entry = $this->post('entry', ['id' => $e])->json_()['entry'];
        $this->assertSame('read', $entry['permission']);
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->post('field', ['id' => $e, 'field' => 'password'])->json_()['value']);

        $payload = json_encode(['title' => 'hijacked', 'password' => 'x']);
        $r = $this->post('save', ['type' => 'entry', 'id' => $e, 'version' => 1, 'payload' => $payload]);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']]);
        $r = $this->post('save', ['type' => 'entry', 'group_id' => $g, 'payload' => $payload]);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']]);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
        $this->assertSame(1, (int) $this->row('SELECT version FROM vault_entries WHERE id = ?', [$e])['version']);

        $this->grants()->grant($this->alice, 'group', $g, $this->bob, 'edit', null, $this->aliceSk());
        $r = $this->post('save', ['type' => 'entry', 'id' => $e, 'version' => 1, 'payload' => json_encode(Fixtures::entry('Postgres 2'))]);
        $this->assertSame(['ok' => true, 'id' => $e, 'version' => 2], $r->json_());
        $this->assertSame('Postgres 2', $this->store()->readEntry($this->alice, $e, $this->aliceSk())['payload']['title']);
    }

    // The editor: create an entry and a group, update with optimistic concurrency (a stale version is a conflict),
    // an invalid payload is payload_invalid, and the payload round-trips byte for byte. Kills: version not passed
    // (a stale save overwrites); the payload not decoded as JSON; the group create not reaching createGroup.
    public function testSaveCreatesAndUpdatesWithVersion(): void
    {
        [$g] = $this->aliceEntry();
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $payload = ['title' => "Tab\tand émoji 🔑", 'password' => Fixtures::UPDATED_PASSWORD, 'tags' => ['db'], 'expires_at' => 1_900_000_000];
        $r = $this->post('save', ['type' => 'entry', 'group_id' => $g, 'payload' => json_encode($payload)]);
        $this->assertSame(true, $r->json_()['ok']);
        $id = $r->json_()['id'];
        $this->assertSame(1, $r->json_()['version']);
        $this->assertNoSecret($r->body, 'the save answer');
        $read = $this->store()->readEntry($this->alice, $id, $this->aliceSk())['payload'];
        $this->assertSame([$payload['title'], Fixtures::UPDATED_PASSWORD, ['db'], 1_900_000_000], [$read['title'], $read['password'], $read['tags'], $read['expires_at']]);

        $this->assertSame(2, $this->post('save', ['type' => 'entry', 'id' => $id, 'version' => 1, 'payload' => json_encode(['title' => 'v2'])])->json_()['version']);
        $stale = $this->post('save', ['type' => 'entry', 'id' => $id, 'version' => 1, 'payload' => json_encode(['title' => 'stale'])]);
        $this->assertSame([409, 'conflict'], [$stale->status, $stale->json_()['reason']]);
        $this->assertSame('v2', $this->store()->readEntry($this->alice, $id, $this->aliceSk())['payload']['title']);

        foreach (['not json', json_encode('a string'), json_encode(['title' => 1]), json_encode(['nope' => 'x'])] as $bad) {
            $r = $this->post('save', ['type' => 'entry', 'group_id' => $g, 'payload' => $bad]);
            $this->assertSame([400, 'payload_invalid'], [$r->status, $r->json_()['reason']], $bad);
        }

        $r = $this->post('save', ['type' => 'group', 'parent_id' => $g, 'payload' => json_encode(['name' => 'DNS'])]);
        $child = $r->json_()['id'];
        $this->assertSame(['DNS', $g], [$this->store()->readGroup($this->alice, $child, $this->aliceSk())['payload']['name'], $this->store()->readGroup($this->alice, $child, $this->aliceSk())['parent_id']]);
        $top = $this->post('save', ['type' => 'group', 'parent_id' => '', 'payload' => json_encode(['name' => 'Clients'])])->json_()['id'];
        $this->assertNull($this->store()->readGroup($this->alice, $top, $this->aliceSk())['parent_id']);
    }

    // Carry: Housekeeping::afterWrite runs after every write (save, move, delete), and never after a read or a
    // refused write. Kills: any one write endpoint without afterWrite; afterWrite on reads.
    public function testEveryWriteRunsHousekeeping(): void
    {
        [$g, $e] = $this->aliceEntry();
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $this->post('tree');
        $this->post('list', ['group_id' => $g]);
        $this->post('entry', ['id' => $e]);
        $this->post('field', ['id' => $e, 'field' => 'password']);
        $this->assertSame([], $this->hk->writes, 'reads do not');

        $steps = [
            'save entry' => ['save', ['type' => 'entry', 'id' => $e, 'version' => 1, 'payload' => json_encode(['title' => 'v2'])]],
            'save new entry' => ['save', ['type' => 'entry', 'group_id' => $g, 'payload' => json_encode(['title' => 'n'])]],
            'save group' => ['save', ['type' => 'group', 'parent_id' => '', 'payload' => json_encode(['name' => 'Other'])]],
        ];
        $n = 0;
        foreach ($steps as $what => [$action, $post]) {
            $this->assertTrue($this->post($action, $post)->json_()['ok'] ?? false, $what);
            $this->assertCount(++$n, $this->hk->writes, $what);
        }
        $other = (int) $this->row("SELECT MAX(id) AS id FROM vault_groups")['id'];
        $this->assertSame(['ok' => true], $this->post('move', ['type' => 'entry', 'id' => $e, 'parent_id' => $other])->json_());
        $this->assertCount(++$n, $this->hk->writes, 'move');
        $this->assertSame($other, (int) $this->row('SELECT group_id FROM vault_entries WHERE id = ?', [$e])['group_id']);
        $this->assertSame(['ok' => true], $this->post('delete', ['type' => 'entry', 'id' => $e])->json_());
        $this->assertCount(++$n, $this->hk->writes, 'delete');
        $this->assertNull($this->row('SELECT id FROM vault_entries WHERE id = ?', [$e]));
        $this->assertSame(array_fill(0, $n, $this->alice), $this->hk->writes);

        $this->post('save', ['type' => 'entry', 'id' => 999, 'version' => 1, 'payload' => json_encode(['title' => 'x'])]);
        $this->assertCount($n, $this->hk->writes, 'a refused write does not');
    }

    // R28 and the T6 minor: invalid_move keeps its reason; an unknown type and a crypto failure are the generic
    // 'failed' with no detail. R29: an entry needs a destination group; only the owner moves or deletes. Kills: the
    // type passed through unchecked; an exception message echoed; a grantee allowed to delete.
    public function testFailuresAreGenericAndOwnerOnly(): void
    {
        [$g, $e] = $this->aliceEntry();
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $r = $this->post('move', ['type' => 'entry', 'id' => $e, 'parent_id' => '']);
        $this->assertSame([400, 'invalid_move'], [$r->status, $r->json_()['reason']]);
        $r = $this->post('move', ['type' => 'group', 'id' => $g, 'parent_id' => $g]);
        $this->assertSame([400, 'invalid_move'], [$r->status, $r->json_()['reason']]);
        foreach (['save' => ['type' => 'share', 'payload' => '{}'], 'delete' => ['type' => 'share', 'id' => $e], 'move' => ['type' => 'vault_keys', 'id' => $e, 'parent_id' => $g]] as $action => $post) {
            $r = $this->post($action, $post);
            $this->assertSame([400, ['ok' => false, 'reason' => 'failed']], [$r->status, $r->json_()], $action);
        }
        $this->pdo()->prepare('UPDATE vault_entries SET ciphertext = ? WHERE id = ?')->execute([base64_encode(random_bytes(64)), $e]);
        $r = $this->post('field', ['id' => $e, 'field' => 'password']);
        $this->assertSame([404, ['ok' => false, 'reason' => 'not_found']], [$r->status, $r->json_()]);

        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $g2 = $this->store()->createGroup($this->alice, null, ['name' => 'Shared']);
        $e2 = $this->store()->createEntry($this->alice, $g2, ['title' => 'shared']);
        $this->grants()->grant($this->alice, 'group', $g2, $this->bob, 'edit', null, $this->aliceSk());
        $this->unlock($this->bob, Fixtures::BOB_PASSPHRASE);
        $r = $this->post('delete', ['type' => 'entry', 'id' => $e2]);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']]);
        $this->assertNotNull($this->row('SELECT id FROM vault_entries WHERE id = ?', [$e2]));
    }

    // Review focus 2 (very large vaults): the list pages at 200 rows, with next_offset for the rest.
    // Kills: no limit; the offset ignored; next_offset given on the last page.
    public function testListPaginatesAt200(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'big']);
        for ($i = 0; $i < 201; $i++) {
            $this->store()->createEntry($this->alice, $g, ['title' => "e$i"]);
        }
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $first = $this->post('list', ['group_id' => $g])->json_();
        $this->assertCount(200, $first['entries']);
        $this->assertSame(['e0', 'e199'], [$first['entries'][0]['title'], $first['entries'][199]['title']]);
        $this->assertSame(200, $first['next_offset']);
        $second = $this->post('list', ['group_id' => $g, 'offset' => 200])->json_();
        $this->assertSame(['e200'], array_column($second['entries'], 'title'));
        $this->assertNull($second['next_offset']);
    }

    // R23: lists show only what the caller is entitled to (live grants), and an entitled object that fails to
    // decrypt is one integrity_error row with no data instead of a failed page. The tree shows own groups and
    // groups shared with the caller (with the sharer's name), never anyone else's; entries shared one by one are
    // listed under "shared". Kills: the tree listing every group; an expired grant still listed; a bad row failing
    // the whole list; integrity rows carrying a title.
    public function testListsShowOnlyEntitledAndMarkIntegrityErrors(): void
    {
        [$g, $e] = $this->aliceEntry();
        $private = $this->store()->createGroup($this->alice, null, ['name' => 'Private']);
        $loose = $this->store()->createEntry($this->alice, $private, ['title' => 'one entry shared']);
        $hidden = $this->store()->createEntry($this->alice, $private, ['title' => 'not shared']);
        $child = $this->store()->createGroup($this->alice, $g, ['name' => 'DNS']);
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->grants()->grant($this->alice, 'group', $g, $this->bob, 'read', null, $this->aliceSk());
        $this->grants()->grant($this->alice, 'entry', $loose, $this->bob, 'read', $this->now + 60, $this->aliceSk());
        $bobs = $this->store()->createGroup($this->bob, null, ['name' => 'Bob own']);
        $bad = $this->store()->createEntry($this->alice, $g, ['title' => 'corrupt']);
        $this->pdo()->prepare('UPDATE vault_entries SET ciphertext = ? WHERE id = ?')->execute([base64_encode(random_bytes(80)), $bad]);

        $this->unlock($this->bob, Fixtures::BOB_PASSPHRASE);
        $tree = $this->post('tree')->json_();
        $byId = array_column($tree['groups'], null, 'id');
        $this->assertSame([$g, $child, $bobs], array_keys($byId), 'own and shared groups only');
        $this->assertSame(['Infra', 'read', 'alice-the-auditor', null], [$byId[$g]['name'], $byId[$g]['permission'], $byId[$g]['shared_by'], $byId[$g]['parent_id']]);
        $this->assertSame([$g, 'read'], [$byId[$child]['parent_id'], $byId[$child]['permission']]);
        $this->assertSame(['Bob own', 'owner', null], [$byId[$bobs]['name'], $byId[$bobs]['permission'], $byId[$bobs]['shared_by']]);
        $this->assertTrue($tree['shared_entries']);

        $list = $this->post('list', ['group_id' => $g])->json_()['entries'];
        $this->assertSame([$e, $bad], array_column($list, 'id'));
        $this->assertSame(['id' => $bad, 'group_id' => $g, 'integrity_error' => true], $list[1]);

        $shared = $this->post('list', ['shared' => 1])->json_()['entries'];
        $this->assertSame([[$loose, 'one entry shared']], array_map(fn ($r) => [$r['id'], $r['title']], $shared));
        $r = $this->post('list', ['group_id' => $private]);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']]);
        $r = $this->post('entry', ['id' => $hidden]);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']]);

        $this->now += 61;
        // The purge is throttled, so the expired grant row is still there: the read path alone must ignore it.
        $this->pdo()->exec('UPDATE vault_meta SET last_purge_at = '.$this->now.' WHERE id = 1');
        $this->assertSame([], $this->post('list', ['shared' => 1])->json_()['entries'], 'an expired grant is gone at once');
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_grants WHERE subject_type = 'entry'"), 'not purged yet');
        $this->assertFalse($this->post('tree')->json_()['shared_entries']);

        $this->pdo()->prepare('UPDATE vault_groups SET ciphertext = ? WHERE id = ?')->execute([base64_encode(random_bytes(80)), $child]);
        $byId = array_column($this->post('tree')->json_()['groups'], null, 'id');
        $this->assertSame(['id' => $child, 'parent_id' => $g, 'permission' => 'read', 'shared_by' => 'alice-the-auditor', 'integrity_error' => true], $byId[$child]);
    }

    // Fix C1 applies to the editor too: its form holds a password input, so it posts natively to vault/save with the
    // CSRF token; a failed JS never sends the password in a URL. The page has no inline script or handler.
    // Kills: method="post" or the action removed from the editor; an inline handler in a pane template.
    public function testEditorFormPostsNatively(): void
    {
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $html = $this->call(VaultController::class, 'index', 'GET')->body;
        $doc = new DOMDocument();
        @$doc->loadHTML($html);
        $forms = 0;
        foreach ($doc->getElementsByTagName('form') as $form) {
            $hasPassword = false;
            foreach ($form->getElementsByTagName('input') as $input) {
                $hasPassword = $hasPassword || $input->getAttribute('type') === 'password';
            }
            if (! $hasPassword) {
                continue;
            }
            $forms++;
            $this->assertSame('post', strtolower($form->getAttribute('method')));
            $this->assertMatchesRegularExpression('~(/vault/save|controller=EntryController&(amp;)?action=save&(amp;)?plugin=Vault)$~', $form->getAttribute('action'));
            $token = null;
            foreach ($form->getElementsByTagName('input') as $input) {
                if ($input->getAttribute('name') === 'csrf_token') {
                    $token = $input->getAttribute('value');
                }
            }
            $this->assertTrue($token !== null && $this->container['token']->validateReusableCSRFToken($token), 'a valid CSRF token');
        }
        $this->assertSame(1, $forms, 'the editor form');
        $this->assertDoesNotMatchRegularExpression('~<script>~', $html);
        $this->assertDoesNotMatchRegularExpression('~\son[a-z]+="~i', $html);
        $r = $this->post('save', ['type' => 'entry', 'title' => 'x', 'password' => Fixtures::ENTRY_PASSWORD], false);
        $this->assertSame(303, $r->status);
        $this->assertStringNotContainsString(Fixtures::ENTRY_PASSWORD, $r->headers['Location'] ?? '');
    }
}
