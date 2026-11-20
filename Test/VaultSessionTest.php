<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Event\AuthSuccessEvent;
use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Model\VaultSession;
use Kanboard\Plugin\Vault\Plugin;
use KanboardTests\units\Base;
use Symfony\Contracts\EventDispatcher\Event;

class VaultSessionTest extends Base
{
    use VaultFixture;

    private string $sk;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->loginAs($this->alice);
        $this->sk = sodium_crypto_box_secretkey(sodium_crypto_box_keypair());
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    // Creates a vault session for the logged-in user and sends its cookie back on the next request.
    private function unlocked(?int $userId = null): string
    {
        $key = $this->session()->create($userId ?? $this->alice, $this->sk);
        $this->sendCookieBack();
        return $key;
    }

    private function sessions(): int
    {
        return $this->countRows('SELECT COUNT(*) FROM vault_sessions');
    }

    // R21: deleting a Kanboard user removes that user's vault sessions through the FK cascade, and only theirs.
    // Kills: a vault_sessions.user_id without ON DELETE CASCADE (the delete would fail or leave the row).
    public function testUserDeleteCascadesVaultSessions(): void
    {
        vault_test_sqlite_only(); // T24: SQLite-specific (PRAGMA, sqlite_master or Schema/Sqlite.php)
        $this->unlocked();
        $this->sid = 'php-session-B';
        $this->loginAs($this->bob);
        $this->unlocked($this->bob);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->alice]));
        $this->assertSame(1, $this->countRows('PRAGMA foreign_keys'));
        $this->assertTrue($this->container['userModel']->remove($this->alice));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->alice]));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->bob]));
    }

    public function testRoundTrip(): void
    {
        $this->unlocked();
        $this->assertSame($this->sk, $this->session()->secretKey());
    }

    // A stolen backup holds enc_sk but not session_key: any other key fails authentication.
    public function testDbRowAloneCannotDecrypt(): void
    {
        $key = $this->unlocked();
        $row = $this->row('SELECT * FROM vault_sessions');
        $this->assertStringNotContainsString(base64_encode($this->sk), implode('|', $row));
        $ad = VaultSession::ad($row['sid_hash'], (int) $row['user_id'], (int) $row['created_at']);
        $nonce = base64_decode($row['nonce']);
        $ct = base64_decode($row['enc_sk']);
        $this->assertSame($this->sk, Aead::open($nonce, $ct, $key, $ad));
        $this->expectException(CryptoException::class);
        Aead::open($nonce, $ct, random_bytes(32), $ad);
    }

    public function testMissingOrForeignCookieGivesNothing(): void
    {
        $this->unlocked();
        $this->https();
        $this->assertNull($this->session()->secretKey(), 'no cookie');
        $this->https([VaultSession::COOKIE => sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)]);
        $this->assertNull($this->session()->secretKey(), 'a random cookie');
        $this->https([VaultSession::COOKIE => 'not base64 !!']);
        $this->assertNull($this->session()->secretKey(), 'garbage');
        // A wrong cookie is not a reason to drop the row: the right one still works.
        $this->assertSame(1, $this->sessions());
    }

    // The row is bound to the PHP session id: another session presenting the same cookie gets nothing.
    public function testOtherPhpSessionGetsNothing(): void
    {
        $this->unlocked();
        $this->sid = 'php-session-B';
        $this->assertNull($this->session()->secretKey());
    }

    // Kills a missing row.user_id check: the PHP session now belongs to bob, so alice's unlock dies.
    public function testRowUserMismatchRefused(): void
    {
        $this->unlocked();
        $this->loginAs($this->bob);
        $this->assertNull($this->session()->secretKey());
        $this->assertSame(0, $this->sessions());
    }

    // Kills a missing API check: JSON-RPC requests never use or touch vault_sessions.
    public function testApiRequestIgnoresVaultSession(): void
    {
        $this->unlocked();
        $before = $this->row('SELECT * FROM vault_sessions');
        $this->now += 60;
        $cookies = [VaultSession::COOKIE => $this->jar->last()['value']];

        session_set('scope', 'API');
        $this->assertTrue($this->session()->isApiRequest());
        $this->assertNull($this->session()->secretKey());
        $this->assertNull($this->session()->sidHash());
        session_remove('scope');

        $this->request(['HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/kanboard/jsonrpc.php'], $cookies);
        $this->assertNull($this->session()->secretKey());
        $this->assertSame($before, $this->row('SELECT * FROM vault_sessions'), 'not even last_used_at moved');

        $this->request(['HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/kanboard/index.php'], $cookies);
        $this->assertSame($this->sk, $this->session()->secretKey());
    }

    // No PHP session id (CLI, or the API, which never starts one): nothing to bind to.
    public function testNoPhpSessionMeansNoVaultSession(): void
    {
        $this->sid = '';
        $this->assertVaultError('unlock_failed', fn () => $this->session()->create($this->alice, $this->sk));
        $this->assertNull($this->session()->secretKey());
    }

    public function testDisabledUserLocks(): void
    {
        $this->unlocked();
        $this->container['userModel']->disable($this->alice);
        $this->assertNull($this->session()->secretKey());
        $this->assertSame(0, $this->sessions());
        $this->assertSame('', $this->jar->last()['value'], 'the cookie is cleared');
    }

    // Kills a missing slide (use at +800 then +1600 must work), a missing idle check and a missing absolute check.
    public function testIdleAndAbsoluteExpiry(): void
    {
        $start = $this->now;
        $this->unlocked();
        $this->now = $start + 800;
        $this->assertSame($this->sk, $this->session()->secretKey());
        $this->now = $start + 1600;
        $this->assertSame($this->sk, $this->session()->secretKey(), 'the idle expiry slid forward on use');
        $this->now += VaultSession::IDLE_TIMEOUT;
        $this->assertNull($this->session()->secretKey(), 'idle for 15 minutes');
        $this->assertSame(0, $this->sessions());

        // Used every 10 minutes, it still ends 8 hours after the unlock.
        $start = $this->now;
        $this->unlocked();
        for ($t = 600; $t < VaultSession::ABSOLUTE_TIMEOUT; $t += 600) {
            $this->now = $start + $t;
            $this->assertSame($this->sk, $this->session()->secretKey(), "at +$t s");
        }
        $this->assertSame($start + VaultSession::ABSOLUTE_TIMEOUT, (int) $this->row('SELECT idle_expires_at FROM vault_sessions')['idle_expires_at'], 'the slide never passes the absolute expiry');
        $this->now = $start + VaultSession::ABSOLUTE_TIMEOUT;
        $this->assertNull($this->session()->secretKey());
        $this->assertSame(0, $this->sessions());
    }

    // T9 carry: the idle timeout is the admin's vault_idle_timeout (minutes, default 15), and it never outlives the
    // Kanboard session: SESSION_DURATION, or gc_maxlifetime when that is 0 (PHP's 1440 s when unset).
    // Kills: the setting ignored (the constant used), and the cap dropped or taken from the wrong source.
    public function testIdleTimeoutIsCappedBySessionLifetime(): void
    {
        $this->assertSame(600, VaultSession::effectiveIdleTimeout(900, 0, 600));
        $this->assertSame(900, VaultSession::effectiveIdleTimeout(900, 0, 1440));
        $this->assertSame(900, VaultSession::effectiveIdleTimeout(900, 0, 0), "PHP's 1440 s default");
        $this->assertSame(1440, VaultSession::effectiveIdleTimeout(3600, 0, 0), "PHP's 1440 s default caps an hour");
        $this->assertSame(300, VaultSession::effectiveIdleTimeout(900, 300, 1440));
        $this->assertSame(900, VaultSession::effectiveIdleTimeout(900, 3600, 600), 'SESSION_DURATION wins over gc_maxlifetime');
        $this->assertSame(300, VaultSession::effectiveIdleTimeout(300, 3600, 600));
        $lifetime = [(int) SESSION_DURATION, (int) ini_get('session.gc_maxlifetime')];
        $this->assertSame(VaultSession::effectiveIdleTimeout(900, ...$lifetime), $this->session()->idleTimeout(), 'default 15 min');
        (new \Kanboard\Plugin\Vault\Model\VaultSettings($this->container))->set('vault_idle_timeout', 5, 1);
        $expected = VaultSession::effectiveIdleTimeout(300, ...$lifetime);
        $this->assertSame($expected, $this->session()->idleTimeout(), 'the admin setting');
        $start = $this->now;
        $this->unlocked();
        $this->assertSame($start + $expected, (int) $this->row('SELECT idle_expires_at FROM vault_sessions')['idle_expires_at']);
    }

    // R41: Kanboard's Request::isHTTPS() trusts X-Forwarded-Proto from anyone. Vault honours X-Forwarded-Proto (its
    // right-most value) or X-Forwarded-Ssl only when REMOTE_ADDR is a trusted proxy; otherwise only the connection's
    // own HTTPS counts. Kills: transportAllowed() on Request::isHTTPS(); the trust check dropped; the left-most
    // (client-supplied) value read; X-Forwarded-Ssl ignored.
    public function testForwardedProtoCountsOnlyFromATrustedProxy(): void
    {
        $plain = ['HTTP_HOST' => 'kb.example', 'REMOTE_ADDR' => '198.51.100.9'];
        $this->request($plain + ['HTTP_X_FORWARDED_PROTO' => 'https']);
        $this->assertFalse($this->session()->transportAllowed(), 'untrusted sender');
        $this->assertVaultError('https_required', fn () => $this->session()->create($this->alice, $this->sk));
        $this->request($plain + ['HTTP_X_FORWARDED_SSL' => 'on']);
        $this->assertFalse($this->session()->transportAllowed(), 'untrusted sender, X-Forwarded-Ssl');

        (new \Kanboard\Plugin\Vault\Model\VaultSettings($this->container))->set('vault_trusted_proxy_cidrs', '198.51.100.0/24', 1);
        $this->request($plain + ['HTTP_X_FORWARDED_PROTO' => 'https']);
        $this->assertTrue($this->session()->transportAllowed(), 'trusted proxy');
        $this->assertSame('__Host-kb_vault', $this->session()->cookieName());
        $this->request($plain + ['HTTP_X_FORWARDED_SSL' => 'on']);
        $this->assertTrue($this->session()->transportAllowed(), 'trusted proxy, X-Forwarded-Ssl');
        $this->request($plain + ['HTTP_X_FORWARDED_PROTO' => 'https, http']);
        $this->assertFalse($this->session()->transportAllowed(), 'the proxy saw http: the right-most value counts');
        $this->request($plain);
        $this->assertFalse($this->session()->transportAllowed(), 'trusted proxy, no header');
        $this->request(['HTTP_HOST' => 'kb.example', 'REMOTE_ADDR' => '203.0.113.50', 'HTTP_X_FORWARDED_PROTO' => 'https']);
        $this->assertFalse($this->session()->transportAllowed(), 'outside the trusted range');
        $this->request(['HTTP_HOST' => 'kb.example', 'REMOTE_ADDR' => '203.0.113.50', 'HTTPS' => 'on']);
        $this->assertTrue($this->session()->transportAllowed(), "the connection's own HTTPS");
        $this->request(['HTTP_HOST' => 'kb.example', 'REMOTE_ADDR' => '203.0.113.50', 'HTTPS' => 'off']);
        $this->assertFalse($this->session()->transportAllowed(), 'HTTPS=off');
    }

    public function testLockNowDeletesTheRowAndClearsTheCookie(): void
    {
        $this->unlocked();
        $this->session()->lock($this->alice);
        $this->assertSame(0, $this->sessions());
        $last = $this->jar->last();
        $this->assertSame([VaultSession::COOKIE, ''], [$last['name'], $last['value']]);
        $this->assertSame(1, $last['options']['expires']);
        $this->assertNull($this->session()->secretKey());
    }

    // Locking another user (an admin disabling someone) must not clear the current user's cookie.
    public function testLockingSomeoneElseKeepsMyCookie(): void
    {
        $this->unlocked();
        $sets = count($this->jar->sets);
        $this->session()->lock($this->bob);
        $this->assertCount($sets, $this->jar->sets);
        $this->assertSame($this->sk, $this->session()->secretKey());
    }

    private function initPlugin(): void
    {
        $plugin = new Plugin($this->container);
        $plugin->initialize();
        // The plugin registers the production vaultSession; keep the fixture's (its injected PHP session id).
        $this->container['vaultSession'] = fn ($c) => $this->session();
    }

    // Kanboard's logout dispatches session.destroy before it destroys the PHP session.
    public function testLogoutLocks(): void
    {
        $this->initPlugin();
        $this->unlocked();
        $this->sid = 'php-session-other-device';
        $this->unlocked();
        $this->sid = 'php-session-A';
        $this->container['dispatcher']->dispatch(new Event(), 'session.destroy');
        $this->assertNull($this->row('SELECT * FROM vault_sessions WHERE sid_hash = ?', [bin2hex(sodium_crypto_generichash('php-session-A', '', 32))]));
        $this->assertSame(1, $this->sessions(), 'only this session is logged out');
        $this->assertSame('', $this->jar->last()['value']);
    }

    // Login keeps the old PHP session (session_regenerate_id(false)), so every vault row of the user goes.
    public function testAuthSuccessDeletesUsersVaultSessions(): void
    {
        $this->initPlugin();
        $this->unlocked();
        $this->sid = 'php-session-other-device';
        $this->unlocked();
        $this->loginAs($this->bob);
        $this->sid = 'php-session-bob';
        $this->unlocked($this->bob);
        $this->assertSame(3, $this->sessions());

        $this->loginAs($this->alice);
        $this->sid = 'php-session-new';
        $this->container['dispatcher']->dispatch(new AuthSuccessEvent('Database'), 'auth.success');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->alice]));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->bob]));
    }

    // Kanboard's API middleware fires auth.success for every JSON-RPC call made with user credentials or a
    // personal API token. The spec says API requests never touch vault_sessions, and an API call has no PHP
    // session to regenerate, so it must not lock the user's browser vault on each call.
    public function testApiAuthSuccessLeavesVaultSessionsAlone(): void
    {
        $this->initPlugin();
        $this->unlocked();
        session_set('scope', 'API');
        $this->container['dispatcher']->dispatch(new AuthSuccessEvent('Database'), 'auth.success');
        session_remove('scope');
        $this->assertSame(1, $this->sessions());
    }

    public function testCookieNames(): void
    {
        $this->assertSame('__Host-kb_vault', $this->session()->cookieName());
        // R20: without the opt-in, Host: localhost over plain HTTP gets the __Host- name and no unlock.
        $this->request(['HTTP_HOST' => 'localhost']);
        $this->assertSame('__Host-kb_vault', $this->session()->cookieName());
        $this->assertFalse($this->session()->transportAllowed());
        $this->assertVaultError('https_required', fn () => $this->session()->create($this->alice, $this->sk));
        putenv('VAULT_DEV_INSECURE_LOCALHOST=1');
        $this->assertSame('kb_vault_dev', $this->session()->cookieName());
        $this->assertTrue($this->session()->transportAllowed());
        $this->request(['HTTP_HOST' => 'localhost:8081', 'HTTPS' => 'on']);
        $this->assertSame('__Host-kb_vault', $this->session()->cookieName());
        $this->request(['HTTP_HOST' => 'kb.example']);
        $this->assertFalse($this->session()->transportAllowed());
        $this->assertVaultError('https_required', fn () => $this->session()->create($this->alice, $this->sk));
    }
}
