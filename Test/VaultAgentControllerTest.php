<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/AgentFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Controller\VaultAgentController;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Model\AgentVault;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// The owner UI (task 16 carry): enrol or re-enrol shows the vault key once (no-store, POST + CSRF, the hardened handler,
// a native-form fallback, no inline JS), for the owner's own agents only.
class VaultAgentControllerTest extends Base
{
    use AgentFixture;

    private int $eve;

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        $this->container['api'] = new \JsonRPC\Server('{}', []);
        (new Plugin($this->container))->initialize();
        $this->setUpAgents();
        $this->eve = (int) $this->container['userModel']->create(['username' => 'eve.bot', 'password' => 'eve usable password 1']);
        $this->roster([$this->dave => $this->alice, $this->eve => $this->bob]);
        $this->container['vaultUnlock'] = fn () => $this->unlockService();
        $this->container['vaultHousekeeping'] = fn () => new Housekeeping($this->container, $this->clock(), $this->rotation());
        $this->loginAs($this->alice);
    }

    protected function tearDown(): void
    {
        session_flush();
        $this->tearDownVault();
        parent::tearDown();
    }

    private function call(string $controller, string $action, string $method = 'POST', array $post = [], ?bool $ajax = null, array $server = []): VaultTestResponse
    {
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        if ($ajax ?? $method === 'POST') {
            $server += ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'];
        }
        $this->container['request'] = new Request($this->container, $server + [
            'REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => self::IP,
        ], [], $post, [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new $controller($this->container))->$action();
        return $response;
    }

    private function post(string $action, array $post = [], ?bool $ajax = null, array $server = []): VaultTestResponse
    {
        return $this->call(VaultAgentController::class, $action, 'POST', $post + ['csrf_token' => $this->container['token']->getReusableCSRFToken()], $ajax, $server);
    }

    // Back from an API call (session scope 'API') to alice's UI session.
    private function backToUi(): void
    {
        session_flush();
        $this->loginAs($this->alice);
    }

    private function unlockAlice(): void
    {
        $r = $this->call(VaultController::class, 'unlock', 'POST', ['passphrase' => Fixtures::PASSPHRASE, 'csrf_token' => $this->container['token']->getReusableCSRFToken()]);
        $this->assertSame(['ok' => true], $r->json_());
    }

    private function assertHardened(VaultTestResponse $r, string $what): void
    {
        $this->assertTrue($r->sent, "$what: sent");
        $this->assertSame('DENY', $r->headers['X-Frame-Options'] ?? null, "$what: X-Frame-Options");
        $this->assertStringContainsString("frame-ancestors 'none';", $r->headers['Content-Security-Policy'] ?? '', "$what: frame-ancestors");
        $this->assertSame('no-store', $r->headers['Cache-Control'] ?? null, "$what: no-store");
    }

    private function dom(string $html): \DOMXPath
    {
        $doc = new \DOMDocument();
        @$doc->loadHTML('<?xml encoding="utf-8"?>'.$html);
        return new \DOMXPath($doc);
    }

    // The page lists the logged-in user's own agents only, an admin included, with native POST forms carrying the
    // CSRF token, no inline script, and the buttons disabled until the owner is unlocked. Kills: every roster agent
    // listed; forms without method, action or token; an inline script; buttons live while locked.
    public function testPageListsOnlyTheOwnersAgents(): void
    {
        $locked = $this->call(VaultAgentController::class, 'index', 'GET');
        $this->assertHardened($locked, 'locked page');
        $x = $this->dom($locked->body);
        $this->assertSame(1, $x->query('//*[@data-vault-owner-state="locked"]')->length);
        $this->assertSame(1, $x->query('//button[@disabled and ancestor::form[@data-vault-form="agent-enrol"]]')->length);

        $this->unlockAlice();
        $page = $this->call(VaultAgentController::class, 'index', 'GET');
        $this->assertHardened($page, 'page');
        $x = $this->dom($page->body);
        $this->assertSame([(string) $this->dave], array_map(fn ($n) => $n->nodeValue, iterator_to_array($x->query('//tr/@data-vault-agent'))));
        $this->assertStringNotContainsString('eve.bot', $page->body);
        foreach (['agent-enrol' => 'action=enrol', 'agent-cap' => 'action=cap'] as $form => $action) {
            $f = $x->query('//form[@data-vault-form="'.$form.'"]')->item(0);
            $this->assertNotNull($f, $form);
            $this->assertSame('post', $f->getAttribute('method'));
            $this->assertStringContainsString($action, $f->getAttribute('action'));
            $this->assertTrue($this->container['token']->validateReusableCSRFToken($x->query('.//input[@name="csrf_token"]/@value', $f)->item(0)?->nodeValue));
            $this->assertSame((string) $this->dave, $x->query('.//input[@name="agent_id"]/@value', $f)->item(0)?->nodeValue);
            $this->assertSame(0, $x->query('.//button[@disabled]', $f)->length, "$form live when unlocked");
        }
        foreach ($x->query('//script') as $s) {
            $this->assertNotSame('', $s->getAttribute('src'), 'no inline script');
        }
        $this->assertStringContainsString('vault-agents.js', $page->body);
        $this->assertSame(1, $x->query('//*[@data-vault-agent-key-panel and @hidden]')->length, 'no key on the page');

        // An admin sees their own agents (none), not everyone's.
        $this->loginAs(self::ADMIN);
        $admin = $this->call(VaultAgentController::class, 'index', 'GET');
        $this->assertStringNotContainsString('dave.bot', $admin->body);
        $this->assertSame(1, $this->dom($admin->body)->query('//*[@data-vault-owner-state="none"]')->length, 'explains why there is nothing to enable');
    }

    // Enrol and re-enrol answer the vault key once as JSON (no-store) with the ready-to-paste line; the key works and is
    // nowhere in the headers. GET, a missing token, a locked vault, plain HTTP and someone else's agent are refused with
    // fixed reasons and nothing enrolled. Kills: GET or no-CSRF accepted; a locked owner; the key on plain HTTP; another
    // owner's agent enrolled; a cacheable answer; the key in a header.
    public function testEnrolShowsTheKeyOnceAndNoStore(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'locked'], $this->post('enrol', ['agent_id' => $this->dave])->json_());
        $this->unlockAlice();
        $get = $this->call(VaultAgentController::class, 'enrol', 'GET', ['agent_id' => $this->dave], true);
        $this->assertSame([403, ['ok' => false, 'reason' => 'forbidden']], [$get->status, $get->json_()]);
        $noToken = $this->call(VaultAgentController::class, 'enrol', 'POST', ['agent_id' => $this->dave]);
        $this->assertSame(['ok' => false, 'reason' => 'forbidden'], $noToken->json_());
        $plain = $this->post('enrol', ['agent_id' => $this->dave], null, ['HTTPS' => 'off']);
        $this->assertSame(['ok' => false, 'reason' => 'https_required'], $plain->json_());
        $this->assertSame(['ok' => false, 'reason' => 'not_found'], $this->post('enrol', ['agent_id' => $this->eve])->json_());
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_principals WHERE user_id IN (?, ?)', [$this->dave, $this->eve]));

        $r = $this->post('enrol', ['agent_id' => $this->dave]);
        $this->assertHardened($r, 'enrol');
        $j = $r->json_();
        $this->assertSame(['ok', 'agent_id', 'vault_key', 'env'], array_keys($j));
        $this->assertSame('KANBOARD_VAULT_KEY='.$j['vault_key'], $j['env']);
        $this->assertStringNotContainsString($j['vault_key'], json_encode($r->headers));
        [, $e] = $this->sharedEntry($this->alice, $this->aliceSk(), 'Prod DB');
        $this->assertSame(['ok' => true, 'value' => Fixtures::ENTRY_PASSWORD], $this->asDave($j['vault_key'])->getVaultSecret($e));

        $this->backToUi();
        $this->assertSame(['ok' => false, 'reason' => 'already_enrolled'], $this->post('enrol', ['agent_id' => $this->dave])->json_());
        $re = $this->post('reenrol', ['agent_id' => $this->dave])->json_();
        $this->assertTrue($re['ok']);
        $this->assertNotSame($j['vault_key'], $re['vault_key']);
        $this->assertSame(['ok' => false, 'reason' => 'bad_vault_key'], $this->asDave($j['vault_key'])->getVaultSecret($e));
        $this->backToUi();
        $this->assertSame(['ok' => true], $this->post('cap', ['agent_id' => $this->dave, 'cap' => '7'])->json_());
        $this->assertSame(7, $this->agentVault()->readCap($this->dave));
        $this->assertSame(['ok' => false, 'reason' => 'not_found'], $this->post('cap', ['agent_id' => $this->eve, 'cap' => '7'])->json_());
    }

    // Without vault.js the form POSTs natively: the answer is the page itself, with the key shown once in the
    // ready-to-paste line (no-store), never a redirect that would carry it in a URL. Kills: a redirect with the key; the
    // key shown twice or in an attribute.
    public function testNativeEnrolShowsTheKeyOnTheNoStorePage(): void
    {
        $this->unlockAlice();
        $r = $this->post('enrol', ['agent_id' => $this->dave], false);
        $this->assertHardened($r, 'native enrol');
        $this->assertSame(200, $r->status);
        $this->assertArrayNotHasKey('Location', $r->headers);
        $x = $this->dom($r->body);
        $line = $x->query('//*[@data-vault-agent-env]')->item(0)?->nodeValue;
        $this->assertMatchesRegularExpression('/^KANBOARD_VAULT_KEY=[A-Za-z0-9_-]{43}$/D', (string) $line);
        $key = substr($line, strlen('KANBOARD_VAULT_KEY='));
        $this->assertSame(1, substr_count($r->body, $key), 'shown once');
        $this->assertSame(0, $x->query('//*[@data-vault-agent-key-panel and @hidden]')->length);
        $this->assertNotNull(AgentVault::decodeKey($key));

        $fail = $this->post('enrol', ['agent_id' => $this->eve], false);
        $this->assertSame(303, $fail->status);
        $this->assertStringContainsString('vault_error=not_found', $fail->headers['Location'] ?? '');
    }
}
