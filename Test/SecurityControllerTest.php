<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Controller\SecurityController;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Crypto\RecoveryCode;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// R40: the "My vault security" page for the logged-in, unlocked user: change passphrase, Rotate my keys, create a
// personal recovery code. Spec: Key rotation (triggers), Recovery (shown once, confirmed by group 3), UI (every state
// change is a POST with the CSRF token); carries R21 (ClientIp), R33 (PENDING is a success), R36 (a new code is
// offered after a passphrase change), T11 M1 (bounded re-key), T13 (the generator for the new passphrase).
class SecurityControllerTest extends Base
{
    use ServiceFixture;

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpVault();
        $this->container['vaultUnlock'] = fn () => $this->unlockService();
        $this->container['vaultPrincipals'] = fn () => new PrincipalModel($this->container, $this->slots(), $this->argon(), $this->clock(), $this->rotation());
        $this->container['vaultRotation'] = fn () => $this->rotation();
        $this->container['vaultRecovery'] = fn () => $this->recovery();
        $this->container['vaultHousekeeping'] = fn () => new Housekeeping($this->container, $this->clock(), $this->rotation());
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
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

    // One request, carrying the cookie the last response set. POSTs are vault.js fetches unless $ajax is false.
    private function call(string $controller, string $action, string $method = 'POST', array $post = [], array $server = [], ?bool $ajax = null): VaultTestResponse
    {
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        if ($ajax ?? $method === 'POST') {
            $server += ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'];
        }
        $this->container['request'] = new Request($this->container, $server + [
            'REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => '203.0.113.7',
        ], [], $post, [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new $controller($this->container))->$action();
        return $response;
    }

    private function post(string $action, array $post = [], array $server = [], ?bool $ajax = null): VaultTestResponse
    {
        return $this->call(SecurityController::class, $action, 'POST', $post + ['csrf_token' => $this->token()], $server, $ajax);
    }

    private function unlock(string $passphrase = Fixtures::PASSPHRASE): void
    {
        $r = $this->call(VaultController::class, 'unlock', 'POST', ['passphrase' => $passphrase, 'csrf_token' => $this->token()]);
        $this->assertSame(['ok' => true], $r->json_(), 'unlocked');
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

    private function keyGen(): int
    {
        return (int) $this->row('SELECT key_gen FROM vault_principals WHERE user_id = ?', [$this->alice])['key_gen'];
    }

    private function manyEntries(int $n): void
    {
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'bulk']);
        for ($i = 0; $i < $n; $i++) {
            $this->store()->createEntry($this->alice, $g, ['title' => "e$i"]);
        }
    }

    // R40: the page is for an unlocked user (locked: back to the Vault page). Its passphrase forms POST natively to
    // their own endpoints with the CSRF token (fix C1), offer the T13 generator for the new passphrase, and load
    // their scripts by tag (no inline JS). The recovery section shows only when the policy allows codes.
    // Kills: the page served while locked; a form without method/action/token; no generator; inline script; the
    // recovery section shown under policy none.
    public function testPageIsForTheUnlockedUserWithItsForms(): void
    {
        $locked = $this->call(SecurityController::class, 'index', 'GET');
        $this->assertHardened($locked, 'locked page');
        $this->assertSame(303, $locked->status);
        $this->assertSame('/?controller=VaultController&action=index&plugin=Vault', $locked->headers['Location'] ?? null);

        $this->unlock();
        $page = $this->call(SecurityController::class, 'index', 'GET');
        $this->assertHardened($page, 'page');
        $this->assertSame(200, $page->status);
        $x = $this->dom($page->body);
        $forms = [
            'passphrase' => ['current' => 'current-password', 'passphrase' => 'new-password', 'confirm' => 'new-password'],
            'rotate' => ['passphrase' => 'current-password'],
        ];
        foreach ($forms as $form => $inputs) {
            $f = $x->query('//form[@data-vault-form="'.$form.'"]')->item(0);
            $this->assertNotNull($f, "$form form");
            $this->assertSame('post', $f->getAttribute('method'), $form);
            $this->assertStringContainsString('action='.$form, $f->getAttribute('action'), $form);
            $this->assertTrue($this->container['token']->validateReusableCSRFToken($x->query('.//input[@name="csrf_token"]/@value', $f)->item(0)?->nodeValue), "$form token");
            foreach ($inputs as $name => $autocomplete) {
                $in = $x->query('.//input[@name="'.$name.'"]', $f)->item(0);
                $this->assertSame(['password', $autocomplete], [$in?->getAttribute('type'), $in?->getAttribute('autocomplete')], "$form.$name");
            }
        }
        $panel = $x->query('//form[@data-vault-form="passphrase"]//*[@data-vault-generator]')->item(0);
        $this->assertNotNull($panel, 'the generator is offered for the new passphrase');
        $target = $x->query('//*[@id="'.$panel->getAttribute('data-vault-gen-target').'"]')->item(0);
        $this->assertSame('passphrase', $target?->getAttribute('name'));
        $this->assertSame('confirm', $x->query('//*[@id="'.$panel->getAttribute('data-vault-gen-confirm').'"]')->item(0)?->getAttribute('name'));
        foreach (['vault.js', 'vault-generator.js', 'vault-security.js'] as $js) {
            $this->assertStringContainsString('Vault/Assets/js/'.$js, $page->body);
        }
        $this->assertDoesNotMatchRegularExpression('~<script(?![^>]*\bsrc=)[^>]*>~', $page->body, 'no inline script');
        $this->assertSame(0, $x->query('//*[@data-vault-recovery]')->length, 'policy none: no recovery section');

        $this->recovery()->setPolicy('code', self::ADMIN);
        $x = $this->dom($this->call(SecurityController::class, 'index', 'GET')->body);
        $this->assertSame(1, $x->query('//*[@data-vault-recovery]')->length, 'policy code: the recovery section');
        $this->assertSame('button', $x->query('//*[@data-vault-action="recovery-create"]/@type')->item(0)?->nodeValue);
    }

    // R40 / R33: a passphrase change. Pre-commit errors are failures (wrong current passphrase, mismatch, a weak one);
    // ROTATED is a success; PENDING (work left after CEREMONY_BATCHES) is a success that says the rotation finishes
    // at the next unlock. The session keeps working with the new key, and with a recovery policy the answer offers a
    // new code (R36). The IP is ClientIp's, so a forged X-Forwarded-For from an untrusted sender is ignored (R21).
    // Kills: an error mapped to success or PENDING mapped to failure; no confirm check; Request::getIpAddress();
    // the change not bounded (ROTATED for 12 objects at batch 1).
    public function testPassphraseChangeMapsResults(): void
    {
        $this->unlock();
        $tokens = fn (string $ip): ?float => ($row = $this->row('SELECT tokens FROM vault_rate WHERE bucket = ?', [UnlockService::ipBucket($ip)])) === null ? null : (float) $row['tokens'];
        $before = $tokens('203.0.113.7');
        $r = $this->post('passphrase', ['current' => Fixtures::WRONG_PASSPHRASE, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE], ['HTTP_X_FORWARDED_FOR' => '198.51.100.77']);
        $this->assertHardened($r, 'wrong current');
        $this->assertSame([401, ['ok' => false, 'reason' => 'unlock_failed']], [$r->status, $r->json_()]);
        $this->assertEqualsWithDelta(($before ?? (float) UnlockService::IP_FAILURES) - 1, $tokens('203.0.113.7'), 0.01, 'the real IP bucket paid for the guess');
        $this->assertNull($tokens('198.51.100.77'), 'not the forged one');
        $this->assertNull($tokens(''), 'nor an unknown IP');
        $r = $this->post('passphrase', ['current' => Fixtures::PASSPHRASE, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => 'something else entirely']);
        $this->assertSame([422, ['ok' => false, 'reason' => 'passphrase_mismatch']], [$r->status, $r->json_()]);
        $r = $this->post('passphrase', ['current' => Fixtures::PASSPHRASE, 'passphrase' => 'short', 'confirm' => 'short']);
        $this->assertSame([422, ['ok' => false, 'reason' => 'passphrase_weak']], [$r->status, $r->json_()]);
        $this->assertSame(1, $this->keyGen(), 'nothing changed');

        $r = $this->post('passphrase', ['current' => Fixtures::PASSPHRASE, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE]);
        $this->assertHardened($r, 'rotated');
        $this->assertSame(['ok' => true, 'rotation' => 'done', 'offer_recovery_code' => false], $r->json_());
        $this->assertSame(2, $this->keyGen());
        $this->assertSame(200, $this->call(SecurityController::class, 'index', 'GET')->status, 'the session still works');

        // PENDING: more objects than CEREMONY_BATCHES batches cover; with a recovery policy, a new code is offered.
        $this->recovery()->setPolicy('code', self::ADMIN);
        unset($this->container['vaultRotation'], $this->container['vaultPrincipals']);
        $this->container['vaultRotation'] = fn () => new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session(), null, 1);
        $this->container['vaultPrincipals'] = fn () => new PrincipalModel($this->container, $this->slots(), $this->argon(), $this->clock(), $this->container['vaultRotation']);
        $this->manyEntries(RotationService::CEREMONY_BATCHES + 2);
        $r = $this->post('passphrase', ['current' => Fixtures::NEW_PASSPHRASE, 'passphrase' => Fixtures::PASSPHRASE, 'confirm' => Fixtures::PASSPHRASE]);
        $json = $r->json_();
        $this->assertSame([200, true, 'pending', true], [$r->status, $json['ok'], $json['rotation'], $json['offer_recovery_code']]);
        $this->assertStringContainsString('next unlock', $json['message']);
        $this->assertNotNull($this->row('SELECT user_id FROM vault_rotations WHERE user_id = ?', [$this->alice]));
        $this->assertSame(200, $this->call(SecurityController::class, 'index', 'GET')->status, 'the session holds sk2');
        foreach ([$r->body, implode('', $r->headers)] as $out) {
            $this->assertStringNotContainsString(Fixtures::PASSPHRASE, $out);
        }
    }

    // R40: Rotate my keys (requestManual) maps results the same way: a wrong passphrase is a failure, ROTATED a
    // success with a new key generation, PENDING a success that finishes at the next unlock. Kills: the endpoint
    // calling the wrong ceremony (no key_gen bump), and failures reported as success.
    public function testRotateMyKeysMapsResults(): void
    {
        $this->unlock();
        $r = $this->post('rotate', ['passphrase' => Fixtures::WRONG_PASSPHRASE]);
        $this->assertSame([401, ['ok' => false, 'reason' => 'unlock_failed']], [$r->status, $r->json_()]);
        $this->assertSame(1, $this->keyGen());
        $r = $this->post('rotate', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame(['ok' => true, 'rotation' => 'done', 'offer_recovery_code' => false], $r->json_());
        $this->assertSame(2, $this->keyGen());
        $this->assertNotNull($this->skFor($this->alice, Fixtures::PASSPHRASE), 'the same passphrase opens the new key');

        unset($this->container['vaultRotation']);
        $this->container['vaultRotation'] = fn () => new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session(), null, 1);
        $this->manyEntries(RotationService::CEREMONY_BATCHES + 2);
        $json = $this->post('rotate', ['passphrase' => Fixtures::PASSPHRASE])->json_();
        $this->assertSame([true, 'pending'], [$json['ok'], $json['rotation']]);
        $this->assertStringContainsString('next unlock', $json['message']);
    }

    // Spec, Recovery: a personal code is created after an unlock when the policy allows it, and shown once: the
    // answer carries it (no-store), the DB holds only its wrap, and the audit has recovery_code_create without it.
    // Under policy none it is refused. A new code replaces the old. Kills: ignoring the policy; the code in the page
    // HTML or the audit; a cacheable answer.
    public function testRecoveryCodeCreatedOnceUnderPolicy(): void
    {
        $this->unlock();
        $r = $this->post('recoveryCode');
        $this->assertSame([403, ['ok' => false, 'reason' => 'policy_forbids']], [$r->status, $r->json_()]);
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE method = 'recovery'"));

        $this->recovery()->setPolicy('code', self::ADMIN);
        $r = $this->post('recoveryCode');
        $this->assertHardened($r, 'code');
        $code = $r->json_()['code'] ?? '';
        $this->assertMatchesRegularExpression('/^([0-9A-Z]{4}-){8}[0-9A-Z]{2}$/', $code);
        $this->assertSame(20, strlen(RecoveryCode::parse($code)));
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE method = 'recovery' AND user_id = ?", [$this->alice]));
        $this->assertContains('recovery_code_create', $this->auditActions());
        $this->assertStringNotContainsString($code, json_encode($this->auditRows()));
        $page = $this->call(SecurityController::class, 'index', 'GET');
        $this->assertStringNotContainsString($code, $page->body, 'never in the page HTML');

        $second = $this->post('recoveryCode')->json_()['code'];
        $this->assertNotSame($code, $second);
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE method = 'recovery' AND user_id = ?", [$this->alice]), 'replaced');
    }

    // Spec, UI: every state change is a POST with Kanboard's CSRF token, answered through the hardened handler with a
    // generic reason. A GET, a missing token, a locked vault and plain HTTP are each refused before any work.
    // Kills: any endpoint without requirePostCsrf, requireUnlocked or the transport check.
    public function testEndpointsArePostCsrfUnlockedAndHttps(): void
    {
        $bodies = [
            'passphrase' => ['current' => Fixtures::PASSPHRASE, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE],
            'rotate' => ['passphrase' => Fixtures::PASSPHRASE],
            'recoveryCode' => [],
        ];
        $this->recovery()->setPolicy('code', self::ADMIN);
        foreach ($bodies as $action => $body) {
            $r = $this->post($action, $body);
            $this->assertHardened($r, "$action locked");
            $this->assertSame([401, ['ok' => false, 'reason' => 'locked']], [$r->status, $r->json_()], "$action locked");
        }
        $this->unlock();
        $calls = $this->argonCalls;
        foreach ($bodies as $action => $body) {
            $get = $this->call(SecurityController::class, $action, 'GET', $body + ['csrf_token' => $this->token()], [], true);
            $this->assertSame([403, 'forbidden'], [$get->status, $get->json_()['reason'] ?? null], "$action GET");
            $none = $this->call(SecurityController::class, $action, 'POST', $body);
            $this->assertSame([403, 'forbidden'], [$none->status, $none->json_()['reason'] ?? null], "$action no token");
            $this->assertHardened($none, "$action no token");
        }
        foreach (['passphrase', 'rotate'] as $action) {
            $r = $this->post($action, $bodies[$action], ['HTTPS' => '', 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_PROTO' => 'https']);
            $this->assertSame('https_required', $r->json_()['reason'] ?? null, "$action plain HTTP");
        }
        $this->assertSame($calls, $this->argonCalls, 'no Argon2 for a refused request');
        $this->assertSame(1, $this->keyGen());
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE method = 'recovery'"));
    }

    // Fix C1 for these forms: without vault.js the passphrase forms POST natively. Success and failure redirect back
    // to this page carrying only a fixed code; the passphrase never reaches a URL or the response. Kills: a JSON
    // answer to a native POST; a redirect to the wrong page; a code outside the fixed list shown.
    public function testNativeFormsRedirectWithCodesOnly(): void
    {
        $this->unlock();
        $r = $this->post('passphrase', ['current' => Fixtures::WRONG_PASSPHRASE, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE], [], false);
        $this->assertHardened($r, 'native failure');
        $this->assertSame('/?controller=SecurityController&action=index&plugin=Vault&vault_error=unlock_failed', $r->headers['Location'] ?? null);
        $r = $this->post('passphrase', ['current' => Fixtures::PASSPHRASE, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE], [], false);
        $this->assertSame('/?controller=SecurityController&action=index&plugin=Vault&vault_notice=rotated', $r->headers['Location'] ?? null);
        $this->assertStringNotContainsString(Fixtures::NEW_PASSPHRASE, $r->body.implode('', $r->headers));

        $page = $this->call(SecurityController::class, 'index', 'GET', [], [], false);
        $this->container['request'] = new Request($this->container, ['REQUEST_METHOD' => 'GET', 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => '203.0.113.7'],
            ['vault_notice' => 'rotated'], [], [], [$this->jar->last()['name'] => $this->jar->last()['value']]);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new SecurityController($this->container))->index();
        $this->assertMatchesRegularExpression('~<p class="alert alert-success[^"]*"[^>]*>Your passphrase is changed\.</p>~', $response->body, 'the notice, by its fixed code');
        $this->container['request'] = new Request($this->container, ['REQUEST_METHOD' => 'GET', 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => '203.0.113.7'],
            ['vault_notice' => '<b>x</b>', 'vault_error' => '<b>y</b>'], [], [], [$this->jar->last()['name'] => $this->jar->last()['value']]);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new SecurityController($this->container))->index();
        $this->assertStringNotContainsString('<b>', $response->body, 'unknown codes show nothing');
        $this->assertStringNotContainsString('alert-success', $response->body, 'no notice for an unknown code');
        $this->assertStringNotContainsString('&lt;b&gt;', $response->body, 'not even escaped');
        $this->assertSame(200, $page->status);
    }
}
