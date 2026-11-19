<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';

use Kanboard\Controller\DashboardController;
use Kanboard\Core\Http\Request;
use Kanboard\Core\Http\Response;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Model\ArgonSlots;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultFailure;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec: UI → States, Assets and headers, Unlocked sessions; carries R18, R21, R22, R28, T6, T7, T9.
class VaultControllerTest extends Base
{
    use ServiceFixture;

    private array $cookies = [];
    private array $server = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpVault();
        $this->container['vaultUnlock'] = fn () => $this->unlockService();
        $this->container['vaultPrincipals'] = fn () => $this->principals();
        $this->container['vaultHousekeeping'] = fn () => new Housekeeping($this->container, $this->clock(), $this->rotation());
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

    // One request to the controller. HTTPS on kb.example from 203.0.113.7 unless $server says otherwise; the cookie
    // the last response set travels with it, as a browser would send it.
    // POSTs are vault.js's fetch (X-Requested-With) unless $ajax is false: a native form submission.
    private function call(string $action, string $method = 'POST', array $post = [], array $server = [], ?bool $ajax = null, array $get = []): VaultTestResponse
    {
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        if ($ajax ?? $method === 'POST') {
            $server += ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'];
        }
        $this->container['request'] = new Request($this->container, $server + $this->server + [
            'REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => '203.0.113.7',
        ], $get, $post, [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new VaultController($this->container))->$action();
        return $response;
    }

    private function post(string $action, array $post = [], array $server = []): VaultTestResponse
    {
        return $this->call($action, 'POST', $post + ['csrf_token' => $this->token()], $server);
    }

    private function enrol(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
    }

    private function assertHardened(VaultTestResponse $r, string $what): void
    {
        $this->assertTrue($r->sent, "$what: a response was sent");
        $this->assertSame('DENY', $r->headers['X-Frame-Options'] ?? null, "$what: X-Frame-Options");
        $csp = $r->headers['Content-Security-Policy'] ?? '';
        $this->assertStringContainsString("frame-ancestors 'none';", $csp, "$what: frame-ancestors");
        $this->assertStringContainsString("default-src 'self';", $csp, "$what: the app's rules are kept");
        $this->assertSame('no-store', $r->headers['Cache-Control'] ?? null, "$what: no-store");
    }

    // Spec, Assets and headers: every Vault response sets XFO DENY, its own CSP with frame-ancestors 'none', and
    // no-store, whatever the outcome: each page state, success, refusal, CSRF failure and a generic error.
    // Kills: any path that answers through $this->response without respond() (the guards, the error handler,
    // the page), and a respond() missing any one header.
    public function testHeadersOnEveryVaultResponse(): void
    {
        $this->assertHardened($this->call('index', 'GET'), 'enrol page');
        $this->assertHardened($this->post('enrol', ['passphrase' => 'short', 'confirm' => 'short']), 'enrol refused');
        $this->assertHardened($this->post('enrol', ['passphrase' => Fixtures::PASSPHRASE, 'confirm' => Fixtures::PASSPHRASE]), 'enrol ok');
        $this->assertHardened($this->post('lock'), 'lock');
        $this->assertHardened($this->call('index', 'GET'), 'locked page');
        $this->assertHardened($this->call('unlock', 'POST', ['passphrase' => Fixtures::PASSPHRASE]), 'csrf refused');
        $this->assertHardened($this->post('unlock', ['passphrase' => Fixtures::WRONG_PASSPHRASE]), 'unlock failed');
        $ok = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertHardened($ok, 'unlock ok');
        $this->assertSame(['ok' => true], $ok->json_());
        $shell = $this->call('index', 'GET');
        $this->assertHardened($shell, 'shell');
        $this->assertStringContainsString('data-vault-state="unlocked"', $shell->body);
        unset($this->container['vaultUnlock']);
        $this->container['vaultUnlock'] = fn () => throw new RuntimeException('boom');
        $this->assertHardened($this->post('unlock', ['passphrase' => 'x']), 'generic failure');
    }

    // Spec: the app-wide rules aren't changed. After Vault responses, cspRules has no frame-ancestors, and a non-Vault
    // page's CSP (built from cspRules as BootstrapMiddleware does) has none either. Kills: respond() writing
    // frame-ancestors into $container['cspRules'] instead of a copy.
    public function testGlobalCspUnchanged(): void
    {
        $before = $this->container['cspRules'];
        $this->enrol();
        $this->call('index', 'GET');
        $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->call('index', 'GET');
        $this->assertSame($before, $this->container['cspRules']);
        $this->assertArrayNotHasKey('frame-ancestors', $this->container['cspRules']);
        $page = new VaultTestResponse($this->container);
        $page->withContentSecurityPolicy($this->container['cspRules']);
        $this->assertStringNotContainsString('frame-ancestors', $page->headers['Content-Security-Policy']);
    }

    // Spec: every state change is a POST with Kanboard's CSRF token. A GET (even with a valid token), a POST without
    // a token and a POST with a wrong one are refused 403 before any work: no Argon2, no session, no cookie.
    // Kills: the isPost() check dropped; the token check dropped or reading the query string.
    public function testUnlockRequiresPostAndCsrf(): void
    {
        $this->enrol();
        $calls = $this->argonCalls;
        $refused = [
            'GET' => $this->call('unlock', 'GET', ['passphrase' => Fixtures::PASSPHRASE, 'csrf_token' => $this->token()], [], true),
            'no token' => $this->call('unlock', 'POST', ['passphrase' => Fixtures::PASSPHRASE]),
            'bad token' => $this->call('unlock', 'POST', ['passphrase' => Fixtures::PASSPHRASE, 'csrf_token' => str_repeat('0', 64)]),
        ];
        foreach ($refused as $what => $r) {
            $this->assertSame(403, $r->status, $what);
            $this->assertSame(['ok' => false, 'reason' => 'forbidden'], $r->json_(), $what);
        }
        foreach (['enrol', 'lock'] as $action) {
            $this->assertSame(403, $this->call($action, 'POST', [])->status, $action);
        }
        $native = $this->call('unlock', 'GET', [], [], false, ['passphrase' => Fixtures::PASSPHRASE, 'csrf_token' => $this->token()]);
        $this->assertSame(403, $native->status, 'a native GET is refused with a page');
        $this->assertStringNotContainsString(Fixtures::PASSPHRASE, $native->body);
        $this->assertSame($calls, $this->argonCalls, 'no Argon2 for a refused request');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));
        $this->assertNull($this->jar->last());

        $ok = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame(200, $ok->status);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));
    }

    // Spec, Unlocked sessions; Review Focus 1: plain HTTP off localhost refuses to unlock (and to enrol) with
    // https_required before any Argon2, and the page says so; the dev exception needs both the opt-in and an exact
    // localhost Host (R20, R22), and then uses the kb_vault_dev cookie. Kills: the transport check after Argon2;
    // the Host alone or the env alone opening the dev exception; enrol skipping the check.
    public function testHttpsRequiredOffLocalhost(): void
    {
        $http = ['HTTPS' => '', 'HTTP_HOST' => 'kb.example'];
        $page = $this->call('index', 'GET', [], $http);
        $this->assertStringContainsString('class="alert alert-error vault-https"', $page->body);
        $this->assertStringNotContainsString('data-vault-form="enrol"', $page->body, 'no passphrase form on plain HTTP');
        $r = $this->post('enrol', ['passphrase' => Fixtures::PASSPHRASE, 'confirm' => Fixtures::PASSPHRASE], $http);
        $this->assertSame([403, ['ok' => false, 'reason' => 'https_required']], [$r->status, $r->json_()]);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_principals'));

        $this->enrol();
        $calls = $this->argonCalls;
        putenv('VAULT_DEV_INSECURE_LOCALHOST=1');
        foreach (['plain HTTP, opt-in, other host' => $http, 'opt-in, localhost-looking host' => ['HTTPS' => '', 'HTTP_HOST' => 'localhost.kb.example']] as $what => $server) {
            $r = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE], $server);
            $this->assertSame([403, ['ok' => false, 'reason' => 'https_required']], [$r->status, $r->json_()], $what);
        }
        putenv('VAULT_DEV_INSECURE_LOCALHOST');
        $r = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE], ['HTTPS' => '', 'HTTP_HOST' => 'localhost:8081']);
        $this->assertSame('https_required', $r->json_()['reason'], 'localhost without the opt-in');
        $this->assertSame($calls, $this->argonCalls, 'refused before any Argon2');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));

        putenv('VAULT_DEV_INSECURE_LOCALHOST=1');
        $r = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE], ['HTTPS' => '', 'HTTP_HOST' => 'localhost:8081']);
        $this->assertSame(['ok' => true], $r->json_());
        $this->assertSame('kb_vault_dev', $this->jar->last()['name']);
    }

    // R41: a plain-HTTP unlock carrying X-Forwarded-Proto: https from an untrusted REMOTE_ADDR gets https_required
    // before any Argon2; from a trusted proxy it unlocks. Kills: the gate on Request::isHTTPS() (header from anyone).
    public function testForwardedProtoOnlyFromATrustedProxy(): void
    {
        $this->enrol();
        $calls = $this->argonCalls;
        $forged = ['HTTPS' => '', 'HTTP_HOST' => 'kb.example', 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_PROTO' => 'https'];
        $r = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE], $forged);
        $this->assertSame([403, ['ok' => false, 'reason' => 'https_required']], [$r->status, $r->json_()]);
        $this->assertSame($calls, $this->argonCalls, 'refused before any Argon2');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));

        (new VaultSettings($this->container))->set('vault_trusted_proxy_cidrs', '198.51.100.0/24', self::ADMIN);
        $r = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE], $forged);
        $this->assertSame(['ok' => true], $r->json_());
        $this->assertSame('__Host-kb_vault', $this->jar->last()['name']);
    }

    // Spec, Assets and headers: vault.js loads only on Vault pages (Vault never uses template:layout:js). The
    // dashboard renders without it, but with the sidebar link; the avatar menu links the Vault too. Kills: loading
    // vault.js or vault.css through a layout hook; the menu hooks missing.
    public function testVaultScriptsOnlyOnVaultPages(): void
    {
        $this->container['request'] = new Request($this->container, ['REQUEST_METHOD' => 'GET', 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php'], ['controller' => 'DashboardController', 'action' => 'show'], [], [], []);
        $dash = new VaultTestResponse($this->container);
        $this->container['response'] = $dash;
        (new DashboardController($this->container))->show();
        $this->assertStringContainsString('<body', $dash->body, 'the full layout rendered');
        $this->assertStringNotContainsString('Vault/Assets/js/vault.js', $dash->body);
        $this->assertStringNotContainsString('Vault/Assets/css/vault.css', $dash->body);
        $this->assertSame(2, preg_match_all('~href="[^"]*controller=VaultController[^"]*plugin=Vault~', $dash->body), 'sidebar + avatar menu');

        $vault = $this->call('index', 'GET');
        $this->assertStringContainsString('plugins/Vault/Assets/js/vault.js', $vault->body);
        $this->assertStringContainsString('plugins/Vault/Assets/css/vault.css', $vault->body);
        $this->assertStringNotContainsString('<script>', $vault->body, 'no inline script');
        $this->assertDoesNotMatchRegularExpression('~\son[a-z]+="~i', $vault->body, 'no inline handlers');
    }

    // Each page state: first visit (enrolment with the policy notice), locked, unlocked (the shell with its lock
    // button and the CSRF token for vault.js). Kills: the states mixed up; the shell shown without a session.
    public function testPageStates(): void
    {
        $enrol = $this->call('index', 'GET')->body;
        $this->assertStringContainsString('data-vault-form="enrol"', $enrol);
        $this->assertStringContainsString('There is no recovery', $enrol);
        $this->enrol();
        $locked = $this->call('index', 'GET')->body;
        $this->assertStringContainsString('data-vault-form="unlock"', $locked);
        $this->assertStringNotContainsString('data-vault-action="lock"', $locked);
        $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $shell = $this->call('index', 'GET')->body;
        $this->assertStringContainsString('data-vault-action="lock"', $shell);
        $this->assertMatchesRegularExpression('~data-csrf="[0-9a-f]{64}"~', $shell);
        $this->assertMatchesRegularExpression('~data-idle-ms="\d+"~', $shell);
        $this->assertStringNotContainsString(Fixtures::PASSPHRASE, $shell);
    }

    // Enrolment: the two passphrases must match and meet the rules; a good one enrols and unlocks at once.
    // Kills: the confirmation ignored; enrol not unlocking (the next page would be the locked one).
    public function testEnrolThenUnlocked(): void
    {
        $r = $this->post('enrol', ['passphrase' => Fixtures::PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE]);
        $this->assertSame([422, 'passphrase_mismatch'], [$r->status, $r->json_()['reason']]);
        $r = $this->post('enrol', ['passphrase' => 'too short', 'confirm' => 'too short']);
        $this->assertSame([422, 'passphrase_weak'], [$r->status, $r->json_()['reason']]);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_principals'));
        $r = $this->post('enrol', ['passphrase' => Fixtures::PASSPHRASE, 'confirm' => Fixtures::PASSPHRASE]);
        $this->assertSame(['ok' => true], $r->json_());
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_principals WHERE user_id = ?', [$this->alice]));
        $this->assertStringContainsString('data-vault-state="unlocked"', $this->call('index', 'GET')->body);
        $r = $this->post('enrol', ['passphrase' => Fixtures::PASSPHRASE, 'confirm' => Fixtures::PASSPHRASE]);
        $this->assertSame([409, 'already_enrolled'], [$r->status, $r->json_()['reason']]);
    }

    // Interface: unlock_failed 401; rate_limited 429; a principal's concurrent derivation 429 (spec, Throttling);
    // all Argon2 slots busy → busy, 503, Retry-After: 2. Kills: the status map flipped or the Retry-After missing.
    public function testUnlockFailureStatuses(): void
    {
        $this->enrol();
        $r = $this->post('unlock', ['passphrase' => Fixtures::WRONG_PASSPHRASE]);
        $this->assertSame([401, ['ok' => false, 'reason' => 'unlock_failed']], [$r->status, $r->json_()]);

        $held = [];
        for ($i = 0; $i < ArgonSlots::SLOTS; $i++) {
            $held[] = $this->slots()->acquire(1000 + $i);
        }
        $r = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([503, ['ok' => false, 'reason' => 'busy'], '2'], [$r->status, $r->json_(), $r->headers['Retry-After'] ?? null]);
        foreach ($held as $slot) {
            $slot->release();
        }
        $mine = $this->slots()->acquire($this->alice);
        $r = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([429, ['ok' => false, 'reason' => 'rate_limited']], [$r->status, $r->json_()]);
        $this->assertArrayNotHasKey('Retry-After', $r->headers);
        $mine->release();

        for ($i = 0; $i < 4; $i++) {
            $this->post('unlock', ['passphrase' => Fixtures::WRONG_PASSPHRASE]);
        }
        $r = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([429, ['ok' => false, 'reason' => 'rate_limited']], [$r->status, $r->json_()]);
    }

    // "Lock now" deletes this session's row, clears the cookie and is audited; the page is locked again.
    // Kills: lock not deleting the row, or locking without the CSRF token.
    public function testLockNow(): void
    {
        $this->enrol();
        $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));
        $this->assertSame(['ok' => true], $this->post('lock')->json_());
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));
        $this->assertSame('', $this->jar->last()['value'], 'the cookie is cleared');
        $this->assertContains('lock', $this->auditActions());
        $this->assertStringContainsString('data-vault-form="unlock"', $this->call('index', 'GET')->body);
    }

    // R21: the controller resolves the client IP with ClientIp and the admin's trusted proxies, never
    // Request::getIpAddress(): a forwarding header from an untrusted sender is ignored; from a trusted proxy it
    // counts. Kills: getIpAddress() (it trusts the header from anyone); the trusted list not passed.
    public function testClientIpUsesTrustedProxiesOnly(): void
    {
        $this->enrol();
        $fwd = ['REMOTE_ADDR' => '198.51.100.20', 'HTTP_X_FORWARDED_FOR' => '192.0.2.99', 'HTTP_X_REAL_IP' => '192.0.2.99'];
        $this->post('unlock', ['passphrase' => Fixtures::WRONG_PASSPHRASE], $fwd);
        (new VaultSettings($this->container))->set('vault_trusted_proxy_cidrs', '198.51.100.20/32', 1);
        $this->post('unlock', ['passphrase' => Fixtures::WRONG_PASSPHRASE], $fwd);
        $this->assertSame(['198.51.100.0/24', '192.0.2.0/24'], array_column($this->auditRows('unlock_failed'), 'ip_trunc'));
    }

    // R28 / T7: after an unlock the user's re-key queue drains through Rekeyer::drainQueue (the only re-key path a
    // request reaches). Kills: no drain after unlock.
    public function testUnlockDrainsTheRekeyQueue(): void
    {
        $this->enrol();
        $sk = $this->skFor($this->alice, Fixtures::PASSPHRASE);
        $e = $this->store()->createEntry($this->alice, $this->store()->createGroup($this->alice, null, ['name' => 'g']), ['title' => 't']);
        $this->pdo()->prepare("INSERT INTO vault_rekey_queue (object_type, object_id, expected_key_epoch, created_at) VALUES ('entry', ?, 1, ?)")->execute([$e, $this->now]);
        $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rekey_queue'));
        $this->assertSame(2, (int) $this->row('SELECT key_epoch FROM vault_entries WHERE id = ?', [$e])['key_epoch']);
        $this->assertSame('t', $this->store()->readEntry($this->alice, $e, $sk)['payload']['title']);
    }

    // T7: Rekeyer::rekey (it re-keys objects that aren't queued) is never reachable from a request; controllers and
    // Housekeeping use drainQueue only. Kills: a controller or Housekeeping calling ->rekey(.
    public function testRequestsNeverReachRekey(): void
    {
        $files = array_merge(glob(__DIR__.'/../Controller/*.php'), [__DIR__.'/../Model/Housekeeping.php']);
        $this->assertNotEmpty($files);
        foreach ($files as $f) {
            $this->assertDoesNotMatchRegularExpression('/->rekey\s*\(/', file_get_contents($f), basename($f));
        }
        $this->assertStringContainsString('->drainQueue(', file_get_contents(__DIR__.'/../Model/Housekeeping.php'));
    }

    // T9: vault requests run the purge (its own 60 s throttle). Kills: no purge on vault requests.
    public function testVaultRequestsRunThePurge(): void
    {
        $this->pdo()->exec('UPDATE vault_meta SET last_purge_at = NULL');
        $this->post('lock');
        $this->assertNotNull($this->row('SELECT last_purge_at FROM vault_meta WHERE id = 1')['last_purge_at']);
        $this->pdo()->exec('UPDATE vault_meta SET last_purge_at = NULL');
        $this->call('index', 'GET');
        $this->assertNotNull($this->row('SELECT last_purge_at FROM vault_meta WHERE id = 1')['last_purge_at']);
    }

    // T6 / R28: only a VaultException's fixed code reaches the client; a CryptoException on a write, an unknown
    // object type or any other error is the generic 'failed', with nothing of its message. invalid_move and
    // integrity_error have their own reasons. Kills: the exception message or class echoed; a crypto or type
    // error answered 500 with detail; the busy statuses swapped.
    public function testFailuresAreGeneric(): void
    {
        $cases = [
            [new VaultException('invalid_move'), [400, 'invalid_move']],
            [new VaultException('integrity_error'), [409, 'integrity_error']],
            [new VaultException('busy'), [429, 'rate_limited']],
            [new VaultException('busy_global'), [503, 'busy']],
            [new VaultException('some_internal_code'), [400, 'failed']],
            [new CryptoException('aead: tag mismatch on entry 7'), [400, 'failed']],
            [new InvalidArgumentException('Vault: unknown object type share'), [400, 'failed']],
            [new RuntimeException('SQLSTATE detail'), [500, 'failed']],
        ];
        foreach ($cases as [$e, $expected]) {
            $this->assertSame($expected, VaultFailure::map($e), get_class($e).' '.$e->getMessage());
        }
        $this->enrol();
        foreach ([new CryptoException('crypto-detail-xyz'), new InvalidArgumentException('type-detail-xyz'), new RuntimeException('db-detail-xyz')] as $e) {
            unset($this->container['vaultUnlock']);
            $this->container['vaultUnlock'] = fn () => new class($this->container, $e) extends UnlockService {
                public function __construct($c, private Throwable $e) { parent::__construct($c); }
                public function unlock(int $userId, #[\SensitiveParameter] string $passphrase, string $ip, #[\SensitiveParameter] ?array $prf = null): string { throw $this->e; }
            };
            $r = $this->post('unlock', ['passphrase' => Fixtures::PASSPHRASE]);
            $this->assertSame('failed', $r->json_()['reason']);
            $this->assertStringNotContainsString('detail-xyz', $r->body);
            $this->assertStringNotContainsString('Exception', $r->body);
        }
    }

    // R33: a passphrase ceremony that returns PENDING is a success ("finishes at next unlock"), and the answer
    // carries the recovery-code offer when the policy allows codes (R36; the hook T13 uses). Kills: PENDING shown
    // as a failure; the offer made under the none policy.
    public function testRotationPendingIsSuccess(): void
    {
        $pending = VaultFailure::rotationResult(RotationService::PENDING, VaultSettings::POLICY_CODE);
        $this->assertSame([true, 'pending', true], [$pending['ok'], $pending['rotation'], $pending['offer_recovery_code']]);
        $this->assertStringContainsString('next unlock', $pending['message']);
        $done = VaultFailure::rotationResult(RotationService::ROTATED, VaultSettings::POLICY_NONE);
        $this->assertSame(['ok' => true, 'rotation' => 'done', 'offer_recovery_code' => false], $done);
    }

    // R32/R33: after a write, Housekeeping continues a pending rotation for at most ROTATION_BATCHES batches, with
    // the session's key (sk2), then drains the queue. Kills: an unbounded sweep (complete); no continuation.
    public function testHousekeepingAdvancesAPendingRotationInBoundedBatches(): void
    {
        $this->enrol();
        $sk1 = $this->skFor($this->alice, Fixtures::PASSPHRASE);
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'g']);
        for ($i = 0; $i < Housekeeping::ROTATION_BATCHES + 2; $i++) {
            $this->store()->createEntry($this->alice, $g, ['title' => "e$i"]);
        }
        $crash = fn (string $p) => $p === 'start' ? throw new RuntimeException('injected crash') : null;
        try {
            (new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session(), $crash))->requestManual($this->alice, $sk1, Fixtures::PASSPHRASE, self::IP);
        } catch (RuntimeException) {
        }
        $rot = $this->row('SELECT new_pk FROM vault_rotations WHERE user_id = ?', [$this->alice]);
        $this->assertNotNull($rot);
        $pending = $this->row("SELECT * FROM vault_wraps WHERE user_id = ? AND status = 'pending'", [$this->alice]);
        $kek = \Kanboard\Plugin\Vault\Crypto\Kdf::kek(($this->argon())(Fixtures::PASSPHRASE, base64_decode($pending['kdf_salt']), (int) $pending['kdf_ops'], (int) $pending['kdf_mem']), 'passphrase');
        $sk2 = \Kanboard\Plugin\Vault\Crypto\Wraps::unwrap($pending, $kek, base64_decode($rot['new_pk']));
        $old = fn () => $this->countRows('SELECT COUNT(*) FROM (SELECT DISTINCT object_type, object_id FROM vault_keys WHERE principal_id = ? AND principal_key_gen = 1)', [$this->alice]);
        $this->assertSame(Housekeeping::ROTATION_BATCHES + 3, $old());

        $batch1 = new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session(), null, 1);
        (new Housekeeping($this->container, $this->clock(), $batch1))->afterWrite($this->alice, $sk2);
        $this->assertSame(3, $old(), 'ROTATION_BATCHES batches of one');
        (new Housekeeping($this->container, $this->clock(), $batch1))->afterWrite($this->alice, $sk2);
        $this->assertSame(0, $old());
        $this->assertNull($this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]), 'finished');
    }

    // Fix C1: every form holding a password input submits as POST to its own endpoint and carries the CSRF token,
    // so without vault.js (disabled, 404, or a submit before the deferred script runs) the browser never sends the
    // passphrase as a GET query string. Kills: method="post" removed from either form; the action removed (a form
    // without one posts to the page URL); the hidden token removed.
    public function testPassphraseFormsPostToTheirEndpoint(): void
    {
        $pages = ['enrol' => $this->call('index', 'GET')->body];
        $this->enrol();
        $pages['unlock'] = $this->call('index', 'GET')->body;
        foreach ($pages as $endpoint => $html) {
            $doc = new DOMDocument();
            @$doc->loadHTML($html);
            $forms = [];
            foreach ($doc->getElementsByTagName('form') as $form) {
                $hasPassword = false;
                foreach ($form->getElementsByTagName('input') as $input) {
                    $hasPassword = $hasPassword || strtolower($input->getAttribute('type')) === 'password';
                }
                if ($hasPassword) {
                    $forms[] = $form;
                }
            }
            $this->assertCount(1, $forms, "$endpoint: one passphrase form");
            $form = $forms[0];
            $this->assertSame('post', strtolower($form->getAttribute('method')), "$endpoint: method=post");
            $this->assertMatchesRegularExpression('~controller=VaultController&action='.$endpoint.'&plugin=Vault$~', $form->getAttribute('action'), "$endpoint: posts to its endpoint");
            $token = null;
            foreach ($form->getElementsByTagName('input') as $input) {
                if ($input->getAttribute('name') === 'csrf_token' && $input->getAttribute('type') === 'hidden') {
                    $token = $input->getAttribute('value');
                }
                if ($input->getAttribute('type') === 'password') {
                    $this->assertContains($input->getAttribute('autocomplete'), ['current-password', 'new-password'], "$endpoint: autocomplete");
                }
            }
            $this->assertTrue($this->container['token']->validateReusableCSRFToken($token), "$endpoint: a valid hidden csrf_token");
        }
    }

    // Fix C1: a native form POST (no vault.js, so no X-Requested-With) works and answers with a hardened redirect to
    // the page. Only a fixed reason code ever goes into that URL, never the passphrase; the page then shows the
    // message. Kills: native POSTs answered with JSON (a dead end without JS); the passphrase or a raw message in
    // the Location; the redirect without the Vault headers; the reason not shown on the page.
    public function testNativeFormPostIsSafeWithoutJs(): void
    {
        $r = $this->call('enrol', 'POST', ['passphrase' => Fixtures::PASSPHRASE, 'confirm' => Fixtures::PASSPHRASE, 'csrf_token' => $this->token()], [], false);
        $this->assertHardened($r, 'native enrol');
        $this->assertSame('/?controller=VaultController&action=index&plugin=Vault', $r->headers['Location'] ?? null);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));
        $this->post('lock');

        $r = $this->call('unlock', 'POST', ['passphrase' => Fixtures::WRONG_PASSPHRASE, 'csrf_token' => $this->token()], [], false);
        $this->assertHardened($r, 'native unlock failed');
        $location = $r->headers['Location'] ?? '';
        $this->assertSame('/?controller=VaultController&action=index&plugin=Vault&vault_error=unlock_failed', $location);
        $this->assertStringNotContainsString('passphrase', $location);
        $page = $this->call('index', 'GET', [], [], false, ['vault_error' => 'unlock_failed']);
        $this->assertMatchesRegularExpression('~<p class="vault-error" role="alert">Unlock failed\.</p>~', $page->body);
        $forged = $this->call('index', 'GET', [], [], false, ['vault_error' => '<script>x</script>']);
        $this->assertStringNotContainsString('<script>x</script>', $forged->body);
        $this->assertMatchesRegularExpression('~<p class="vault-error" role="alert" hidden></p>~', $forged->body, 'an unknown code shows nothing');

        $r = $this->call('unlock', 'POST', ['passphrase' => Fixtures::PASSPHRASE], [], false);
        $this->assertStringEndsWith('&vault_error=forbidden', $r->headers['Location'] ?? '', 'no token: refused, by redirect');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));

        $r = $this->call('unlock', 'POST', ['passphrase' => Fixtures::PASSPHRASE, 'csrf_token' => $this->token()], [], false);
        $this->assertHardened($r, 'native unlock ok');
        $this->assertSame('/?controller=VaultController&action=index&plugin=Vault', $r->headers['Location'] ?? null);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));
        $this->assertStringNotContainsString(Fixtures::PASSPHRASE, $r->body.implode('', $r->headers));
    }

    // Fix I1: the page goes through the hardened handler too. An exception in index gives a generic 500 page with
    // X-Frame-Options, frame-ancestors and no-store, never the raw message (Kanboard's index.php would print
    // "Internal Error: <message>" with none of the headers). Kills: index outside handle(); the message echoed.
    public function testIndexFailureIsHardenedAndGeneric(): void
    {
        unset($this->container['vaultPrincipals']);
        $this->container['vaultPrincipals'] = fn () => throw new RuntimeException('secret-detail-xyz');
        $r = $this->call('index', 'GET');
        $this->assertHardened($r, 'index failure');
        $this->assertSame(500, $r->status);
        $this->assertStringNotContainsString('secret-detail-xyz', $r->body);
        $this->assertStringNotContainsString('RuntimeException', $r->body);
        $this->assertStringContainsString('Something went wrong', $r->body);
    }
}
