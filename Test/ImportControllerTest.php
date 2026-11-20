<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Controller\ImportController;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Model\EntryPayload;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\Importer;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Records every afterWrite call; the real work still runs.
class VaultImportSpyHousekeeping extends Housekeeping
{
    public array $writes = [];

    public function afterWrite(int $userId, #[\SensitiveParameter] string $sk): void
    {
        $this->writes[] = $userId;
        parent::afterWrite($userId, $sk);
    }
}

// Spec: KeePassXC import and export → Import (mapping, what's dropped, upload), Audit (import), Entries, groups and
// grants. The page (vault-import.js) opens the file; these are the server's two endpoints, vault/import/start and
// vault/import/batch, and the page that loads the import scripts. The batches posted here are the ones the real page
// scripts build from the real KeePassXC fixtures (Test/fixtures/kdbx/kpxc-mapped.json, checked by vault-import.test.mjs).
class ImportControllerTest extends Base
{
    use ServiceFixture;

    private const FILE_NAME = 'Private-Passwords-Rk2wQ8.kdbx';

    private VaultImportSpyHousekeeping $hk;

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpVault();
        $this->container['vaultUnlock'] = fn () => $this->unlockService();
        $this->container['vaultPrincipals'] = fn () => $this->principals();
        $this->hk = new VaultImportSpyHousekeeping($this->container, $this->clock(), $this->rotation());
        $this->container['vaultHousekeeping'] = fn () => $this->hk;
        $this->container['vaultStore'] = fn () => $this->store();
        $this->container['vaultGrants'] = fn () => $this->grants();
        $this->container['vaultImporter'] = fn () => new Importer($this->container, $this->clock());
        unset($_SESSION['vaultImport']);
        $this->loginAs($this->alice);
    }

    protected function tearDown(): void
    {
        unset($_SESSION['vaultImport']);
        $this->tearDownVault();
        parent::tearDown();
    }

    private function token(): string
    {
        return $this->container['token']->getReusableCSRFToken();
    }

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
        return $this->call(ImportController::class, $action, 'POST', $post + ['csrf_token' => $this->token()], $ajax);
    }

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

    private function sk(int $userId, string $passphrase): string
    {
        return $this->skFor($userId, $passphrase);
    }

    /** @return array<string, array{total:int, groups:int, skippedAttachments:int, batches: list<array{group_path: list<string>, entries: list<array>}>}> */
    private function mapped(): array
    {
        return json_decode((string) file_get_contents(__DIR__.'/fixtures/kdbx/kpxc-mapped.json'), true, 32, JSON_THROW_ON_ERROR);
    }

    private function start(int $total): VaultTestResponse
    {
        return $this->post('start', ['total' => (string) $total]);
    }

    private function batch(int $importId, mixed $path, array $entries, array $extra = []): VaultTestResponse
    {
        return $this->post('batch', ['import_id' => (string) $importId, 'group_path' => json_encode($path), 'entries' => json_encode($entries)] + $extra);
    }

    private function assertHardened(VaultTestResponse $r, string $what): void
    {
        $this->assertSame('DENY', $r->headers['X-Frame-Options'] ?? null, "$what: X-Frame-Options");
        $this->assertStringContainsString("frame-ancestors 'none';", $r->headers['Content-Security-Policy'] ?? '', "$what: frame-ancestors");
        $this->assertSame('no-store', $r->headers['Cache-Control'] ?? null, "$what: no-store");
    }

    // [path below the import group => [payload, …]] for everything under $root, read back through the store.
    private function readBack(int $userId, int $root, string $sk): array
    {
        $tree = $this->store()->tree($userId, $sk)['groups'];
        $byId = [];
        foreach ($tree as $g) {
            $byId[$g['id']] = $g;
        }
        $pathOf = function (int $id) use ($byId, $root): ?array {
            $path = [];
            for ($at = $id; $at !== $root; $at = (int) $byId[$at]['parent_id']) {
                if (! isset($byId[$at]) || $byId[$at]['parent_id'] === null) {
                    return null;
                }
                array_unshift($path, $byId[$at]['name']);
            }
            return $path;
        };
        $out = [];
        foreach ($tree as $g) {
            $path = $pathOf((int) $g['id']);
            if ($path === null) {
                continue;
            }
            $key = json_encode($path, JSON_UNESCAPED_UNICODE);
            $out[$key] = [];
            foreach ($this->store()->listEntries($userId, (int) $g['id'], $sk) as $row) {
                $out[$key][] = $this->store()->readEntry($userId, (int) $row['id'], $sk)['payload'];
            }
        }
        ksort($out);
        return $out;
    }

    // Spec, Import 3–5 and the CI gate's "match field for field": the batches the page builds from the KDBX 3.1
    // AES-KDF, 4.0 Argon2d + AES, 4.0 Argon2id + ChaCha20 and key-file KeePassXC fixtures each store title, username,
    // password, URL, notes, tags, expiry and custom fields with their protection; otp is a protected field; the groups
    // are rebuilt below one new "Imported <date>" group. Kills: a payload key dropped or rewritten; protection lost;
    // group paths flattened or merged; entries landing in the wrong group.
    public function testMappingFieldForField(): void
    {
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $sk = $this->sk($this->alice, Fixtures::PASSPHRASE);
        $date = date('Y-m-d', $this->now);
        $seen = [];
        foreach ($this->mapped() as $case => $m) {
            $start = $this->start($m['total']);
            $this->assertSame(200, $start->status, $case.': '.$start->body);
            $root = $start->json_()['import_id'];
            $this->assertNotContains($root, $seen, 'each import gets its own group');
            $seen[] = $root;
            $created = 0;
            $want = [];
            foreach ($m['batches'] as $b) {
                $r = $this->batch($root, $b['group_path'], $b['entries']);
                $this->assertSame(200, $r->status, $case.': '.$r->body);
                $created += $r->json_()['created'];
                $key = json_encode($b['group_path'], JSON_UNESCAPED_UNICODE);
                $want[$key] = array_merge($want[$key] ?? [], array_map(static fn (array $p): array => EntryPayload::validate($p), $b['entries']));
            }
            $this->assertSame($m['total'], $created, $case);
            $this->assertSame('Imported '.$date, $this->store()->readGroup($this->alice, $root, $sk)['payload']['name'], $case);
            $want['[]'] ??= [];
            ksort($want);
            $this->assertSame($want, $this->readBack($this->alice, $root, $sk), $case.': field for field');
            $this->assertSame(4, count($want) - 1, $case.': Servers, Servers/Linux, Dup, Dup (2)');

            // Spot checks against the KeePassXC source (Test/fixtures/kdbx/fixtures.mjs): protection and whitespace.
            $mail = $this->readBack($this->alice, $root, $sk)['[]'][0];
            $this->assertSame(['Mail', "Mail\tpass word ", "line one\n\tline two  ", ['mail', 'work'], 1893553445], [$mail['title'], $mail['password'], $mail['notes'], $mail['tags'], $mail['expires_at']], $case);
            $this->assertSame([['Plain custom', false], ['Secret custom', true], ['otp', true]], array_map(static fn (array $f): array => [$f['name'], $f['protected']], $mail['fields']), $case);
            $this->assertSame('', $mail['otp'], $case);
        }
        sodium_memzero($sk);
    }

    // Spec, Import 5: batches of at most 100. The server refuses a bigger one itself, whole: nothing of it is stored.
    // Kills: no server-side cap; the cap off by one; a refused batch partly written.
    public function testBatchOver100Refused(): void
    {
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $root = $this->start(201)->json_()['import_id'];
        $entry = fn (int $i): array => ['title' => 'e'.$i, 'password' => 'p'.$i];
        $r = $this->batch($root, [], array_map($entry, range(1, 101)));
        $this->assertSame([413, 'import_limit'], [$r->status, $r->json_()['reason']]);
        $this->assertHardened($r, 'refused batch');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
        $r = $this->batch($root, [], array_map($entry, range(1, 100)));
        $this->assertSame(['ok' => true, 'created' => 100], $r->json_());
        $this->assertSame(100, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
    }

    // Spec, Import 4: an import of more than 20,000 entries is refused; the server keeps count itself (the total given
    // at start is a ceiling, and no batch may pass it). Kills: no total cap; the start cap off by one; the running
    // count not kept or reset per batch.
    public function testImportOver20000Refused(): void
    {
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        foreach ([20001, 0, -1] as $total) {
            $r = $this->start($total);
            $this->assertSame([413, 'import_limit'], [$r->status, $r->json_()['reason']], (string) $total);
        }
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_groups'), 'a refused start makes no group');
        $this->assertSame(200, $this->start(20000)->status);
        $root = $this->start(3)->json_()['import_id'];
        $this->assertSame(2, $this->batch($root, [], [['title' => 'a'], ['title' => 'b']])->json_()['created']);
        $r = $this->batch($root, [], [['title' => 'c'], ['title' => 'd']]);
        $this->assertSame([413, 'import_limit'], [$r->status, $r->json_()['reason']], 'past the total given at start');
        $this->assertSame(1, $this->batch($root, [], [['title' => 'c']])->json_()['created']);
        $r = $this->batch($root, [], [['title' => 'e']]);
        $this->assertSame([413, 'import_limit'], [$r->status, $r->json_()['reason']], 'the total is reached');
        $this->assertSame(3, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
    }

    // Spec: an entry over 256 KB is refused (EntryPayload::MAX_BYTES, the store's own check), and so is a malformed
    // payload or path; the batch is all or nothing. Kills: a batch committed entry by entry; the path not checked.
    public function testOversizedOrMalformedBatchIsRefusedWhole(): void
    {
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $root = $this->start(10)->json_()['import_id'];
        $big = ['title' => 'big', 'notes' => str_repeat('n', EntryPayload::MAX_BYTES)];
        $r = $this->batch($root, ['G'], [['title' => 'fine'], $big]);
        $this->assertSame([413, 'payload_too_large'], [$r->status, $r->json_()['reason']]);
        $r = $this->batch($root, ['G'], [['title' => 'fine'], ['title' => 'x', 'nope' => 1]]);
        $this->assertSame([400, 'payload_invalid'], [$r->status, $r->json_()['reason']]);
        foreach ([['G', ''], ['G', 5], array_fill(0, 33, 'deep'), 'G'] as $path) {
            $r = $this->batch($root, $path, [['title' => 'x']]);
            $this->assertSame([400, 'payload_invalid'], [$r->status, $r->json_()['reason']], json_encode($path));
        }
        $r = $this->post('batch', ['import_id' => (string) $root, 'group_path' => '[]', 'entries' => '{"title":"not a list"}']);
        $this->assertSame([400, 'payload_invalid'], [$r->status, $r->json_()['reason']]);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_groups'), 'no group "G" left behind');
        $this->assertSame(1, $this->batch($root, array_fill(0, 32, 'deep'), [['title' => 'ok']])->json_()['created']);
    }

    // Spec, Import 5: "The file name isn't stored". The server never asks for it; a client that sends one anyway has
    // it ignored: no table, session value or audit row holds it, and the group is named by the date alone.
    // Kills: the group named after the file; a name parameter echoed into storage, the audit or the session.
    public function testNoFilenameStored(): void
    {
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $sk = $this->sk($this->alice, Fixtures::PASSPHRASE);
        $extra = ['name' => self::FILE_NAME, 'file_name' => self::FILE_NAME, 'filename' => self::FILE_NAME, 'title' => self::FILE_NAME];
        $root = $this->post('start', ['total' => '1'] + $extra)->json_()['import_id'];
        $this->assertSame(1, $this->batch($root, [], [['title' => 'Mail']], $extra)->json_()['created']);

        $names = array_column($this->store()->tree($this->alice, $sk)['groups'], 'name');
        $this->assertSame(['Imported '.date('Y-m-d', $this->now)], $names);
        $dump = vault_test_dump($this->pdo());
        $this->assertStringNotContainsString('Rk2wQ8', $dump, 'no table holds the file name');
        $this->assertStringNotContainsString('Rk2wQ8', json_encode($_SESSION), 'nor the session');
        $this->assertStringNotContainsString('Rk2wQ8', json_encode($this->store()->readEntry($this->alice, $this->countRows('SELECT MAX(id) FROM vault_entries'), $sk)), 'nor the entry');
        sodium_memzero($sk);
    }

    // Spec: the import group is a new top-level group that only the importer can see (owner-only, no grants), written
    // through ObjectStore (sealed to the owner, created rows audited), with one import row per batch carrying only
    // actor_user_id and count (Audit's allowlist); afterWrite runs after each batch. Kills: the group parented under
    // something else; another user's group reachable as an import id; the import row missing or carrying more;
    // housekeeping skipped.
    public function testImportGroupIsOwnerOnlyAndAudited(): void
    {
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $root = $this->start(3)->json_()['import_id'];
        $this->assertSame(2, $this->batch($root, ['A', 'B'], [['title' => 'x'], ['title' => 'y']])->json_()['created']);
        $this->assertSame(1, $this->batch($root, ['A'], [['title' => 'z']])->json_()['created']);
        $g = $this->row('SELECT * FROM vault_groups WHERE id = ?', [$root]);
        $this->assertSame([null, $this->alice], [$g['parent_id'], (int) $g['owner_id']]);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_grants'));
        $this->assertSame([$this->alice], array_map('intval', array_column($this->pdo()->query('SELECT DISTINCT principal_id FROM vault_keys')->fetchAll(\PDO::FETCH_ASSOC), 'principal_id')));
        $this->assertSame(3, $this->countRows("SELECT COUNT(*) FROM vault_groups WHERE owner_id = ?", [$this->alice]), 'the import group, A and A/B; A reused');

        $rows = $this->auditRows('import');
        $this->assertCount(2, $rows);
        $this->assertSame([2, 1], array_map(static fn (array $r): int => (int) $r['count'], $rows));
        foreach ($rows as $row) {
            $this->assertSame($this->alice, (int) $row['actor_user_id']);
            foreach (['object_type', 'object_id', 'share_hash', 'target_user_id', 'ip_trunc', 'ua_family'] as $col) {
                $this->assertNull($row[$col], $col);
            }
        }
        $creates = array_count_values(array_column($this->auditRows('create'), 'object_type'));
        $this->assertSame(['group' => 3, 'entry' => 3], $creates, 'each group and entry is created through the store');
        $this->assertSame([$this->alice, $this->alice], $this->hk->writes);

        // Bob can't write into Alice's import, even with its id, and gets nothing from her session's state.
        $this->unlock($this->bob, Fixtures::BOB_PASSPHRASE);
        $r = $this->batch($root, [], [['title' => 'bob was here']]);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']]);
        $_SESSION['vaultImport'] = ['user' => $this->bob, 'root' => $root, 'total' => 5, 'sent' => 0];
        $r = $this->batch($root, [], [['title' => 'bob was here']]);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']], 'the store refuses a group he does not own');
        $this->assertSame(3, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
    }

    // Carry: the import writes through the T7 write path. The target group goes through ObjectStore::beforeWrite under
    // the batch's lock, so a group waiting in the re-key queue (a removal happened) is re-keyed inline before anything
    // is written into it. Housekeeping is a no-op here, so only the barrier can do it. Kills: beforeWrite skipped.
    public function testBatchGoesThroughTheWriteBarrier(): void
    {
        $this->container['vaultHousekeeping'] = fn () => new class($this->container) extends Housekeeping {
            public function afterWrite(int $userId, #[\SensitiveParameter] string $sk): void
            {
            }
        };
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $root = $this->start(2)->json_()['import_id'];
        $this->pdo()->prepare("INSERT INTO vault_rekey_queue (object_type, object_id, expected_key_epoch, created_at) VALUES ('group', ?, 1, ?)")->execute([$root, $this->now]);
        $this->assertSame(1, $this->batch($root, [], [['title' => 'x']])->json_()['created']);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rekey_queue'));
        $this->assertSame(2, (int) $this->row('SELECT key_epoch FROM vault_groups WHERE id = ?', [$root])['key_epoch']);
    }

    // Global constraints: every state change is a POST with the CSRF token, from an unlocked vault, answered hardened
    // with a fixed reason. Kills: GET or no token accepted; the locked guard skipped; a batch without a started import.
    public function testPostCsrfUnlockedAndGeneric(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $r = $this->start(1);
        $this->assertSame([401, 'locked'], [$r->status, $r->json_()['reason']]);
        $this->assertHardened($r, 'locked');
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $get = $this->call(ImportController::class, 'start', 'GET', ['total' => '1', 'csrf_token' => $this->token()], true);
        $this->assertSame([403, 'forbidden'], [$get->status, $get->json_()['reason']]);
        $noToken = $this->call(ImportController::class, 'start', 'POST', ['total' => '1']);
        $this->assertSame([403, 'forbidden'], [$noToken->status, $noToken->json_()['reason']]);
        $r = $this->batch(1, [], [['title' => 'x']]);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']], 'no import started');
        $root = $this->start(2)->json_()['import_id'];
        $r = $this->batch($root + 1, [], [['title' => 'x']]);
        $this->assertSame([404, 'not_found'], [$r->status, $r->json_()['reason']], 'not this session\'s import');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_entries'));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_groups WHERE parent_id IS NOT NULL'));
    }

    // Carry (T21): the import page, and only it, loads kdbxweb.js, vault-kdbx.js, vault-kdbx-header.js and
    // vault-import.js, in that order, as page-scoped scripts (no inline JS). Locked, it goes back to the vault page.
    // Every reason the page can show has a message. Kills: a script missing or out of order; the scripts on the
    // vault shell; the page served while locked; a reason without its message.
    public function testImportPageLoadsTheImportScripts(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $locked = $this->call(ImportController::class, 'index', 'GET');
        $this->assertSame(303, $locked->status);
        $this->unlock($this->alice, Fixtures::PASSPHRASE);
        $page = $this->call(ImportController::class, 'index', 'GET');
        $this->assertSame(200, $page->status);
        $this->assertHardened($page, 'page');
        preg_match_all('~<script[^>]*src="[^"]*plugins/Vault/Assets/((?:vendor/kdbxweb|js)/[a-z0-9-]+\.js)~', $page->body, $m);
        $this->assertSame(['js/vault.js', 'vendor/kdbxweb/kdbxweb.js', 'js/vault-kdbx.js', 'js/vault-kdbx-header.js', 'js/vault-import.js'], $m[1]);
        $this->assertDoesNotMatchRegularExpression('~<script(?![^>]*\bsrc=)[^>]*>~', $page->body, 'no inline script');
        $this->assertStringContainsString('data-vault-import-form', $page->body);
        $this->assertDoesNotMatchRegularExpression('~<input[^>]*\bname=~', substr($page->body, (int) strpos($page->body, 'data-vault-import')), 'no named input: a native submit carries nothing');

        $shell = $this->call(VaultController::class, 'index', 'GET');
        $this->assertStringNotContainsString('kdbxweb.js', $shell->body);
        $this->assertStringNotContainsString('vault-import.js', $shell->body);
        $this->assertStringContainsString('ImportController', $shell->body, 'the vault links to the import page');

        $this->assertSame(1, preg_match('~data-messages="([^"]*)"~', $page->body, $dm));
        $messages = json_decode(html_entity_decode($dm[1], ENT_QUOTES), true);
        $this->assertIsArray($messages);
        $reasons = ['too_large', 'not_kdbx', 'unsupported', 'file_corrupt', 'twofish', 'argon_mem', 'argon_iter', 'argon_lanes', 'aes_rounds', 'yubikey_cr',
            'invalid_key', 'cancelled', 'timeout', 'kdf_limits', 'worker_failed', 'load_failed', 'busy', 'unavailable', 'bad_input',
            'opening', 'uploading', 'done', 'partial'];
        foreach ($reasons as $reason) {
            $this->assertNotEmpty($messages['import_'.$reason] ?? '', 'import_'.$reason);
        }
        $this->assertStringContainsString('Twofish', $messages['import_twofish']);
        $this->assertStringContainsString('YubiKey', $messages['import_yubikey_cr']);
        $this->assertStringContainsString('delete', $messages['import_yubikey_cr']);
        // The server's own refusal (and vault-import.js's, before upload) is a plain reason, like payload_too_large.
        $this->assertStringContainsString('20,000', $messages['import_limit'] ?? '');
    }
}
