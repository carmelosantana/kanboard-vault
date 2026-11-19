<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';
require_once __DIR__.'/Support/ShareSpyNotifier.php';

use Kanboard\Core\Http\Request;
use Kanboard\Core\Security\Role;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Controller\VaultShareController;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\ShareModel;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec: One-time shares → Opening a share (one static shell for real, burned and fake ids; Reveal is a POST with the
// page's session CSRF token; headers on Vault public responses), Creating a share (reservation, finalise, revoke, the
// list of links) and Throttling. The visitor is logged out unless a test logs someone in: shares open for "anyone
// with the link".
class VaultShareControllerTest extends Base
{
    use ServiceFixture;

    private VaultShareSpyNotifier $notifier;

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpVault();
        $this->container['vaultUnlock'] = fn () => $this->unlockService();
        $this->container['vaultPrincipals'] = fn () => $this->principals();
        $this->container['vaultHousekeeping'] = fn () => new Housekeeping($this->container, $this->clock(), $this->rotation());
        $this->container['vaultShares'] = fn () => $this->shares();
        $this->notifier = new VaultShareSpyNotifier($this->container);
        $this->container['vaultNotifier'] = fn () => $this->notifier;
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function shares(): ShareModel
    {
        return new ShareModel($this->container, $this->clock());
    }

    private function token(): string
    {
        return $this->container['token']->getReusableCSRFToken();
    }

    // One request. HTTPS on kb.example from 203.0.113.7 unless $server says otherwise. POSTs are fetch() calls.
    private function call(string $controller, string $action, string $method = 'POST', array $post = [], array $server = [], array $get = []): VaultTestResponse
    {
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        if ($method === 'POST') {
            $server += ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'];
        }
        $this->container['request'] = new Request($this->container, $server + [
            'REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => '203.0.113.7',
        ], $get, $post, [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new $controller($this->container))->$action();
        return $response;
    }

    private function show(array $get = [], array $server = []): VaultTestResponse
    {
        return $this->call(VaultShareController::class, 'show', 'GET', [], $server, $get + ['controller' => 'VaultShareController', 'action' => 'show', 'plugin' => 'Vault']);
    }

    private function reveal(array $post, array $server = []): VaultTestResponse
    {
        return $this->call(VaultShareController::class, 'reveal', 'POST', $post + ['csrf_token' => $this->token()], $server);
    }

    private function post(string $action, array $post = []): VaultTestResponse
    {
        return $this->call(VaultShareController::class, $action, 'POST', $post + ['csrf_token' => $this->token()]);
    }

    /** @return array{0:string,1:string} [share_id, b], created by Alice as the browser would */
    private function share(string $label = 'a label'): array
    {
        $sid = bin2hex(sodium_crypto_generichash('creator-session', '', 32));
        $burn = bin2hex(random_bytes(16));
        $r = $this->shares()->reserve($this->alice, $sid, '1d');
        $this->shares()->finalize($this->alice, $sid, [
            'share_id' => $r['share_id'], 'ciphertext' => base64_encode(random_bytes(64)), 'iv' => base64_encode(random_bytes(12)),
            'salt' => '', 'has_passphrase' => '0', 'burn_hash' => ShareModel::burnHash($burn), 'label' => $label,
        ]);
        return [$r['share_id'], $burn];
    }

    private function unlockAlice(): void
    {
        $this->sid = 'php-session-alice';
        $this->loginAs($this->alice);
        $r = $this->call(VaultController::class, 'unlock', 'POST', ['passphrase' => Fixtures::PASSPHRASE, 'csrf_token' => $this->token()]);
        $this->assertSame(['ok' => true], $r->json_(), 'unlocked');
    }

    private static function masked(string $html): string
    {
        return (string) preg_replace('/data-csrf="[0-9a-f]{64}"/', 'data-csrf="*"', $html);
    }

    private function assertPublicHeaders(VaultTestResponse $r, string $what): void
    {
        $this->assertTrue($r->sent, "$what: sent");
        $this->assertSame('no-store', $r->headers['Cache-Control'] ?? null, "$what: no-store");
        $this->assertSame('no-referrer', $r->headers['Referrer-Policy'] ?? null, "$what: Referrer-Policy");
        $this->assertSame('noindex, nofollow', $r->headers['X-Robots-Tag'] ?? null, "$what: X-Robots-Tag");
        $this->assertSame('DENY', $r->headers['X-Frame-Options'] ?? null, "$what: X-Frame-Options");
        $this->assertStringContainsString("frame-ancestors 'none';", $r->headers['Content-Security-Policy'] ?? '', "$what: frame-ancestors");
    }

    // Spec: "The public page is the same static shell for real, burned and fake ids: identical apart from Kanboard's
    // per-session CSRF and session values ... it never looks the id up." Rendered for a live id, a burned one, a fake
    // one, no id and a hostile one, the pages are byte-identical once the CSRF token is masked, and none carries the id.
    // Kills: the id echoed into the page, a lookup that changes the page (a "not available" shell, a passphrase field
    // shown only for passphrase links), the token left unmasked by a changed attribute name.
    public function testShellIndependentOfId(): void
    {
        [$live] = $this->share();
        [$burned, $burnedB] = $this->share();
        $this->assertNotNull($this->shares()->reveal($burned, $burnedB, '192.0.2.1'));
        $ids = ['live' => $live, 'burned' => $burned, 'fake' => bin2hex(random_bytes(16)), 'none' => null, 'hostile' => '"><script>x</script>'];
        $pages = [];
        foreach ($ids as $what => $id) {
            $r = $this->show($id === null ? [] : ['id' => $id]);
            $this->assertSame(200, $r->status, $what);
            $this->assertMatchesRegularExpression('/data-csrf="[0-9a-f]{64}"/', $r->body, "$what: the token is where the mask expects it");
            if ($id !== null) {
                $this->assertStringNotContainsString($id, $r->body, "$what: the id is not in the page");
            }
            $pages[$what] = self::masked($r->body);
        }
        $this->assertSame(1, count(array_unique($pages)), 'one shell for every id');
        $page = $pages['live'];
        $this->assertStringContainsString(t('Passphrase (only if the sender gave you one)'), $page);
        $this->assertStringContainsString('plugins/Vault/Assets/js/vault-reveal.js', $page);
        $this->assertStringNotContainsString('<script>', $page, 'no inline script');
        $this->assertDoesNotMatchRegularExpression('~\son[a-z]+="~i', $page, 'no inline handlers');
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_shares'), 'viewing the page burns nothing');
    }

    // Spec: headers on Vault public responses: Cache-Control no-store, Referrer-Policy no-referrer, X-Robots-Tag
    // noindex, X-Frame-Options DENY (plus Vault's frame-ancestors 'none'), on every answer of both public actions:
    // the page, a reveal, a not-available reveal, a CSRF refusal, a rate-limit refusal and an HTTPS refusal.
    // Kills: any one header missing, or any path answering without it.
    public function testPublicHeaders(): void
    {
        [$id, $b] = $this->share();
        $this->assertPublicHeaders($this->show(['id' => $id]), 'page');
        $this->assertPublicHeaders($this->show([], ['HTTPS' => '']), 'page over http');
        $this->assertPublicHeaders($this->call(VaultShareController::class, 'reveal', 'POST', ['id' => $id, 'b' => $b]), 'csrf refused');
        $this->assertPublicHeaders($this->reveal(['id' => $id, 'b' => $b], ['HTTPS' => '']), 'https refused');
        $this->assertPublicHeaders($this->reveal(['id' => $id, 'b' => bin2hex(random_bytes(16))]), 'not available');
        $ok = $this->reveal(['id' => $id, 'b' => $b]);
        $this->assertPublicHeaders($ok, 'revealed');
        $this->assertTrue($ok->json_()['ok']);
        for ($i = 0; $i < 20; $i++) {
            $this->reveal(['id' => $id, 'b' => $b], ['REMOTE_ADDR' => '198.51.100.20']);
        }
        $limited = $this->reveal(['id' => $id, 'b' => $b], ['REMOTE_ADDR' => '198.51.100.20']);
        $this->assertSame([429, ['ok' => false, 'reason' => 'rate_limited']], [$limited->status, $limited->json_()]);
        $this->assertPublicHeaders($limited, 'rate limited');
    }

    // Spec: "Reveal POSTs {id, b} together with the page's session CSRF token." A GET (even with a token), a POST
    // without a token and a POST with a wrong one are refused 403 and burn nothing. A logged-out visitor's reveal works
    // with the token the shell gave them (Kanboard signs it with a key in the anonymous visitor's session).
    // Kills: the POST check dropped, the token check dropped, the token read from the query string.
    public function testRevealNeedsCsrf(): void
    {
        [$id, $b] = $this->share();
        $refused = [
            'GET' => $this->call(VaultShareController::class, 'reveal', 'GET', [], [], ['id' => $id, 'b' => $b, 'csrf_token' => $this->token()]),
            'no token' => $this->call(VaultShareController::class, 'reveal', 'POST', ['id' => $id, 'b' => $b]),
            'bad token' => $this->call(VaultShareController::class, 'reveal', 'POST', ['id' => $id, 'b' => $b, 'csrf_token' => str_repeat('0', 64)]),
        ];
        foreach ($refused as $what => $r) {
            $this->assertSame(403, $r->status, $what);
        }
        $this->assertSame(['ok' => false, 'reason' => 'forbidden'], $refused['no token']->json_());
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_shares'), 'nothing burned');

        $this->assertSame(0, (int) $this->container['userSession']->getId(), 'logged out');
        preg_match('/data-csrf="([0-9a-f]{64})"/', $this->show(['id' => $id])->body, $m);
        $r = $this->call(VaultShareController::class, 'reveal', 'POST', ['id' => $id, 'b' => $b, 'csrf_token' => $m[1]]);
        $this->assertSame(200, $r->status);
        $this->assertSame(['ok', 'ciphertext', 'iv', 'salt', 'has_passphrase', 'expires_at'], array_keys($r->json_()));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_shares'));
        $this->assertSame([$this->alice], $this->notifier->revealed, 'the sender is notified');
    }

    // Every failure of a reveal is one answer: 404 {ok:false, reason:not_available}, byte for byte, whether the id is
    // unknown, the b wrong or missing, the id malformed or sent as an array. Kills: a reason or status that tells a
    // wrong b from an unknown id, a TypeError on an array parameter turning into a different (500) answer.
    public function testRevealFailuresAreIdentical(): void
    {
        [$id, $b] = $this->share();
        $answers = [];
        foreach ([
            'unknown id' => ['id' => bin2hex(random_bytes(16)), 'b' => $b],
            'wrong b' => ['id' => $id, 'b' => bin2hex(random_bytes(16))],
            'no b' => ['id' => $id],
            'no id' => ['b' => $b],
            'malformed id' => ['id' => 'x', 'b' => $b],
            'array id' => ['id' => [$id], 'b' => $b],
            'array b' => ['id' => $id, 'b' => [$b]],
        ] as $what => $post) {
            $r = $this->reveal($post);
            $answers[$what] = [$r->status, $r->body];
        }
        $this->assertSame([[404, json_encode(['ok' => false, 'reason' => 'not_available'])]], array_values(array_unique($answers, SORT_REGULAR)));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_shares'));
    }

    // R41, R20/R22: a reveal needs a secure transport, decided by ClientIp::secureTransport (a forwarded proto counts
    // only from a trusted proxy), or the opted-in dev localhost. Off it, the reveal is refused before the share is
    // touched or a throttle token spent, and the page says HTTPS is needed. Kills: no transport check, Kanboard's
    // isHTTPS (trusts X-Forwarded-Proto from anyone), the dev exception on the Host alone.
    public function testRevealNeedsSecureTransport(): void
    {
        [$id, $b] = $this->share();
        $http = ['HTTPS' => '', 'HTTP_HOST' => 'kb.example'];
        foreach ([
            'plain http' => $http,
            'spoofed proto' => $http + ['HTTP_X_FORWARDED_PROTO' => 'https'],
            'localhost without opt-in' => ['HTTPS' => '', 'HTTP_HOST' => 'localhost:8081'],
        ] as $what => $server) {
            $r = $this->reveal(['id' => $id, 'b' => $b], $server);
            $this->assertSame([403, ['ok' => false, 'reason' => 'https_required']], [$r->status, $r->json_()], $what);
        }
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_rate WHERE bucket LIKE 'reveal:%'"), 'no throttle token spent');
        $this->assertStringContainsString('data-vault-https="0"', $this->show([], $http)->body);
        $this->assertStringContainsString('data-vault-https="1"', $this->show()->body);
        putenv('VAULT_DEV_INSECURE_LOCALHOST=1');
        $r = $this->reveal(['id' => $id, 'b' => $b], ['HTTPS' => '', 'HTTP_HOST' => 'localhost:8081']);
        $this->assertSame(200, $r->status, 'the opted-in dev localhost');
    }

    // R21: the throttle and the audit use ClientIp::resolve with the admin's trusted proxies, never a header a client
    // sets and never Kanboard's own resolution. From an untrusted sender a forwarded address is ignored; from a trusted
    // proxy the forwarded client is the one throttled and audited. Kills: Request::getIpAddress() (it ignores Vault's
    // trusted-proxy setting, so the proxied reveal would be recorded under the proxy's address).
    public function testRevealUsesTheResolvedClientIp(): void
    {
        $ua = ['HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0'];
        [$id, $b] = $this->share();
        $this->reveal(['id' => $id, 'b' => $b], ['REMOTE_ADDR' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '198.51.100.99'] + $ua);
        $this->settings()->set('vault_trusted_proxy_cidrs', '10.0.0.0/8', self::ADMIN);
        [$id, $b] = $this->share();
        $this->reveal(['id' => $id, 'b' => $b], ['REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '192.0.2.77'] + $ua);
        $rows = $this->auditRows('share_reveal');
        $this->assertSame([['203.0.113.0/24', 'Firefox 140 / Linux'], ['192.0.2.0/24', 'Firefox 140 / Linux']], array_map(static fn ($r) => [$r['ip_trunc'], $r['ua_family']], $rows));
    }

    // Spec: shares are created, listed and revoked from an unlocked vault, each a POST with CSRF. reserve gives a
    // share_id and expires_at; create finalises it (the label sealed); mine lists the live links with their labels;
    // revoke removes one. A locked vault gets locked, a missing token forbidden. Kills: an endpoint without the
    // unlock or the CSRF check, create not bound to this session's reservation.
    public function testCreatorEndpoints(): void
    {
        $this->assertSame([401, 'locked'], [($r = $this->post('reserve', ['expiry' => '1d']))->status, $r->json_()['reason'] ?? null], 'logged out');
        $this->unlockAlice();
        $this->assertSame(403, $this->call(VaultShareController::class, 'reserve', 'POST', ['expiry' => '1d'])->status, 'no token');
        $res = $this->post('reserve', ['expiry' => '1h'])->json_();
        $this->assertSame(['ok', 'share_id', 'expires_at'], array_keys($res));
        $this->assertSame($this->now + 3600, $res['expires_at']);
        $burn = bin2hex(random_bytes(16));
        $created = $this->post('create', [
            'share_id' => $res['share_id'], 'ciphertext' => base64_encode(random_bytes(64)), 'iv' => base64_encode(random_bytes(12)),
            'salt' => '', 'has_passphrase' => '0', 'burn_hash' => ShareModel::burnHash($burn), 'label' => 'for ACME',
        ]);
        $this->assertSame(['ok' => true], $created->json_());
        $links = $this->post('mine')->json_()['links'];
        $this->assertSame([[ShareModel::idHash($res['share_id']), 'for ACME', $res['expires_at']]], array_map(static fn ($l) => [$l['id_hash'], $l['label'], $l['expires_at']], $links));

        $this->sid = 'php-session-other';
        $this->assertSame(401, $this->post('mine')->status, 'another PHP session is locked');
        $this->sid = 'php-session-alice';
        $this->assertSame(['ok' => true], $this->post('revoke', ['id_hash' => ShareModel::idHash($res['share_id'])])->json_());
        $this->assertSame([], $this->post('mine')->json_()['links']);
        $this->assertSame([404, 'not_found'], [($r = $this->post('revoke', ['id_hash' => ShareModel::idHash($res['share_id'])]))->status, $r->json_()['reason']]);
    }

    // Only show and reveal are open to anonymous visitors (APP_PUBLIC); creating, listing and revoking links need a
    // Kanboard login. Kills: a '*' wildcard, or a public creator endpoint.
    public function testOnlyShowAndRevealArePublic(): void
    {
        $acl = $this->container['applicationAuthorization'];
        foreach (['show' => true, 'reveal' => true, 'reserve' => false, 'create' => false, 'revoke' => false, 'mine' => false] as $action => $public) {
            $this->assertSame($public, $acl->isAllowed('VaultShareController', $action, Role::APP_PUBLIC), $action);
        }
    }
}
