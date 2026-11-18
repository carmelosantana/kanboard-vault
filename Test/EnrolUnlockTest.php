<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\ArgonSlots;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RateLimiter;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultSession;
use KanboardTests\units\Base;

class EnrolUnlockTest extends Base
{
    use VaultFixture;

    private const IP = '203.0.113.9';
    private array $held = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->loginAs($this->alice);
    }

    protected function tearDown(): void
    {
        foreach ($this->held as $slot) {
            $slot->release();
        }
        $this->tearDownVault();
        parent::tearDown();
    }

    private function enrolAlice(): void
    {
        $this->principals()->enrolHuman($this->alice, $this->alicePassphrase);
    }

    // Kills: no length check, a byte (not character) length, a case-sensitive username check, and no
    // password_verify against the login hash. Nothing is written and no Argon2 runs for a refused passphrase.
    public function testEnrolRejectsShortAndLoginPassword(): void
    {
        $p = $this->principals();
        $this->assertVaultError('passphrase_weak', fn () => $p->enrolHuman($this->alice, 'thirteen-char'));
        // 13 characters, 26 bytes: the minimum counts characters.
        $this->assertVaultError('passphrase_weak', fn () => $p->enrolHuman($this->alice, 'ééééééééééééé'));
        $this->assertVaultError('passphrase_weak', fn () => $p->enrolHuman($this->alice, 'Alice-The-Auditor'));
        $this->assertVaultError('passphrase_reuse', fn () => $p->enrolHuman($this->alice, $this->alicePassword));
        $this->assertSame(0, $this->argonCalls);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_principals'));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_wraps'));
        $this->assertNull($p->get($this->alice));

        // Exactly 14 characters is enough.
        $p->enrolHuman($this->bob, 'fourteen-chars');
        $this->assertSame(1, $this->argonCalls);
        $this->assertVaultError('already_enrolled', fn () => $p->enrolHuman($this->bob, 'another passphrase'));
    }

    // The enrolled wrap is a passphrase wrap at the default KDF parameters, bound to its own row id (R10),
    // and it opens to a secret key whose public key is the stored one.
    public function testEnrolCreatesPrincipalAndPassphraseWrap(): void
    {
        $this->enrolAlice();
        $principal = $this->principals()->get($this->alice);
        $this->assertSame($this->alice, $principal['user_id']);
        $this->assertSame('human', $principal['kind']);
        $this->assertSame(1, $principal['key_gen']);
        $this->assertSame('active', $principal['state']);
        $pk = base64_decode($principal['public_key'], true);
        $this->assertSame(SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, strlen($pk));

        $wrap = $this->row('SELECT * FROM vault_wraps WHERE user_id = ?', [$this->alice]);
        $this->assertSame('passphrase', $wrap['method']);
        $this->assertNull($wrap['credential_id']);
        $this->assertSame(Kdf::DEFAULT_OPS, (int) $wrap['kdf_ops']);
        $this->assertSame(Kdf::DEFAULT_MEM, (int) $wrap['kdf_mem']);
        $this->assertSame('active', $wrap['status']);
        $this->assertSame(1, (int) $wrap['key_gen']);
        $this->assertSame(1, (int) $wrap['crypto_v']);
        $salt = base64_decode($wrap['kdf_salt'], true);
        $this->assertSame(SODIUM_CRYPTO_PWHASH_SALTBYTES, strlen($salt));
        $kek = Kdf::kek(Kdf::argon2id($this->alicePassphrase, $salt, Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM), 'passphrase');
        $sk = Wraps::unwrap($wrap, $kek, $pk);
        $this->assertSame($pk, sodium_crypto_box_publickey_from_secretkey($sk));
        // The AD binds the real row id: a row claiming another id doesn't open.
        $this->expectException(\Kanboard\Plugin\Vault\Crypto\CryptoException::class);
        Wraps::unwrap(['id' => (int) $wrap['id'] + 1] + $wrap, $kek, $pk);
    }

    // Kills any failure path with its own code or message: wrong passphrase, unknown user, not enrolled,
    // disabled user, a PRF output with no PRF wrap, and a public-key mismatch all read 'unlock_failed'.
    public function testUnlockWrongPassphraseIsGeneric(): void
    {
        $this->enrolAlice();
        $this->argonCalls = 0;
        $u = $this->unlocker();
        $errors = [];
        $errors[] = $this->assertVaultError('unlock_failed', fn () => $u->unlock($this->alice, 'wrong passphrase here', self::IP));
        $errors[] = $this->assertVaultError('unlock_failed', fn () => $u->unlock(9999, $this->alicePassphrase, self::IP));
        $errors[] = $this->assertVaultError('unlock_failed', fn () => $u->unlock($this->bob, $this->alicePassphrase, self::IP));
        $errors[] = $this->assertVaultError('unlock_failed', fn () => $u->unlock($this->alice, $this->alicePassphrase, self::IP, ['credential_id' => 'x', 'output' => str_repeat("\1", 32)]));
        $this->pdo()->prepare('UPDATE vault_principals SET public_key = ? WHERE user_id = ?')
            ->execute([base64_encode(sodium_crypto_box_publickey(sodium_crypto_box_keypair())), $this->alice]);
        $errors[] = $this->assertVaultError('unlock_failed', fn () => $u->unlock($this->alice, $this->alicePassphrase, self::IP));
        foreach ($errors as $e) {
            $this->assertSame(get_class($errors[0]), get_class($e));
            $this->assertSame(0, $e->getCode());
            $this->assertNull($e->getPrevious(), 'no crypto error label leaks through the chain');
        }
        // Every path ran the same Argon2 work, so timing tells them apart no better than the message.
        $this->assertSame(5, $this->argonCalls);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));
    }

    public function testDisabledUserCannotUnlock(): void
    {
        $this->enrolAlice();
        $this->container['userModel']->disable($this->alice);
        $this->assertVaultError('unlock_failed', fn () => $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP));
    }

    // Kills throttling that runs after Argon2: the sixth attempt is refused before any derivation, even
    // with the right passphrase. The back-off ends after 60 s, and the five failures are kept for the banner.
    public function testBackoffAfterFiveFailures(): void
    {
        $this->enrolAlice();
        $this->argonCalls = 0;
        for ($i = 0; $i < 5; $i++) {
            $this->assertVaultError('unlock_failed', fn () => $this->unlocker()->unlock($this->alice, 'wrong passphrase '.$i, self::IP));
        }
        $this->assertSame(5, $this->argonCalls);
        $this->assertVaultError('rate_limited', fn () => $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP));
        $this->assertSame(5, $this->argonCalls, 'no Argon2 while backing off');

        $this->now += 59;
        $this->assertVaultError('rate_limited', fn () => $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP));
        $this->now += 1;
        $key = $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP);
        $this->assertSame(32, strlen($key));
        $this->assertSame(5, $this->principals()->failedAttemptsSinceLastUnlock($this->alice));
        $this->assertSame(PrincipalModel::NOTIFY_AFTER, 5);

        // A clean unlock clears both the back-off and the banner count.
        $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP);
        $this->assertSame(0, $this->principals()->failedAttemptsSinceLastUnlock($this->alice));
        $this->assertSame(0, $this->limiter()->backoffSeconds(UnlockService::userBucket($this->alice)));
    }

    // Per client IP: 30 failures per 10 min. An attempt spends a token before Argon2; success gives it back.
    public function testIpBucketCountsFailuresNotSuccesses(): void
    {
        $this->enrolAlice();
        $bucket = UnlockService::ipBucket(self::IP);
        $this->assertStringNotContainsString(self::IP, $bucket, 'the IP is hashed in the bucket key');
        $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP);
        $this->assertEqualsWithDelta(30.0, (float) $this->row('SELECT tokens FROM vault_rate WHERE bucket = ?', [$bucket])['tokens'], 1e-6);
        $this->assertVaultError('unlock_failed', fn () => $this->unlocker()->unlock($this->alice, 'wrong passphrase', self::IP));
        $this->assertEqualsWithDelta(29.0, (float) $this->row('SELECT tokens FROM vault_rate WHERE bucket = ?', [$bucket])['tokens'], 1e-6);

        // Drain the rest: the next attempt is refused before Argon2, from this IP only.
        $limiter = $this->limiter();
        while ($limiter->consume($bucket, UnlockService::IP_FAILURES, UnlockService::IP_FAILURES / UnlockService::IP_WINDOW)) {
        }
        $this->argonCalls = 0;
        $this->assertVaultError('rate_limited', fn () => $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP));
        $this->assertSame(0, $this->argonCalls);
        $this->assertSame(32, strlen($this->unlocker()->unlock($this->alice, $this->alicePassphrase, '198.51.100.7')));
    }

    // R15: the principal's slot is taken before anything else; busy maps to 'busy' (429) or 'busy_global' (503).
    public function testBusySlotsRefuseBeforeArgon2(): void
    {
        $this->enrolAlice();
        $this->argonCalls = 0;
        $this->held[] = $this->slots()->acquire($this->alice);
        $this->assertVaultError('busy', fn () => $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP));
        array_pop($this->held)->release();

        foreach ([101, 102, 103, 104] as $other) {
            $this->held[] = $this->slots()->acquire($other);
        }
        $this->assertVaultError('busy_global', fn () => $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP));
        $this->assertSame(0, $this->argonCalls);
        // A busy refusal is not a failed guess.
        $this->assertSame(0, $this->limiter()->backoffSeconds(UnlockService::userBucket($this->alice)));
        $this->assertNull($this->row('SELECT * FROM vault_rate WHERE bucket = ?', [UnlockService::userBucket($this->alice)]));

        foreach ($this->held as $slot) {
            $slot->release();
        }
        $this->held = [];
        $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP);
        // The slot was released after the unlock.
        $this->held[] = $again = $this->slots()->acquire($this->alice);
        $this->assertNotNull($again);
    }

    public function testUnlockNeedsHttpsExceptOnLocalhost(): void
    {
        $this->enrolAlice();
        $this->argonCalls = 0;
        $this->request(['HTTP_HOST' => 'kb.example']);
        $this->assertVaultError('https_required', fn () => $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP));
        // A Host header that merely starts with localhost is not localhost.
        $this->request(['HTTP_HOST' => 'localhost.evil.example']);
        $this->assertVaultError('https_required', fn () => $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP));
        $this->assertSame(0, $this->argonCalls);

        $this->request(['HTTP_HOST' => 'localhost:8081']);
        $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP);
        $cookie = $this->jar->last();
        $this->assertSame(VaultSession::DEV_COOKIE, $cookie['name']);
        $this->assertFalse($cookie['options']['secure']);
        $this->assertTrue($cookie['options']['httponly']);
        $this->assertSame('Strict', $cookie['options']['samesite']);
    }

    // The unlock stores enc_sk for this session and sends session_key only in the __Host- cookie.
    public function testUnlockSetsHostCookieAndSession(): void
    {
        $this->enrolAlice();
        $key = $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP);
        $cookie = $this->jar->last();
        $this->assertSame('__Host-kb_vault', $cookie['name']);
        $this->assertSame(['expires' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict'], $cookie['options']);
        $this->assertArrayNotHasKey('domain', $cookie['options']);
        $this->assertSame($key, sodium_base642bin($cookie['value'], SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING));

        $row = $this->row('SELECT * FROM vault_sessions');
        $this->assertSame($this->alice, (int) $row['user_id']);
        $this->assertSame(bin2hex(sodium_crypto_generichash($this->sid, '', 32)), $row['sid_hash']);
        $this->assertNull($row['enc_sk_next']);

        $this->sendCookieBack();
        $sk = $this->session()->secretKey();
        $pk = base64_decode($this->principals()->get($this->alice)['public_key'], true);
        $this->assertSame($pk, sodium_crypto_box_publickey_from_secretkey($sk));
    }

    // A wrap below the default KDF parameters is re-derived at the defaults on a successful unlock, in place
    // (same row id, new salt), and still opens afterwards.
    public function testKdfUpgradeOnUnlock(): void
    {
        $keypair = $this->principalWithWrap($this->alice, $this->alicePassphrase, 2, 16 * 1024 * 1024);
        $before = $this->row('SELECT * FROM vault_wraps WHERE user_id = ?', [$this->alice]);

        $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP);
        $this->assertSame([[2, 16 * 1024 * 1024], [Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM]], $this->argonParams);
        $after = $this->row('SELECT * FROM vault_wraps WHERE user_id = ?', [$this->alice]);
        $this->assertSame($before['id'], $after['id']);
        $this->assertSame(Kdf::DEFAULT_OPS, (int) $after['kdf_ops']);
        $this->assertSame(Kdf::DEFAULT_MEM, (int) $after['kdf_mem']);
        $this->assertNotSame($before['kdf_salt'], $after['kdf_salt']);
        $this->assertNotSame($before['wrapped_sk'], $after['wrapped_sk']);
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_wraps'));

        $kek = Kdf::kek(Kdf::argon2id($this->alicePassphrase, base64_decode($after['kdf_salt']), Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM), 'passphrase');
        $this->assertSame(sodium_crypto_box_secretkey($keypair), Wraps::unwrap($after, $kek, sodium_crypto_box_publickey($keypair)));

        // At the defaults now: the next unlock derives once, with the new parameters.
        $this->argonParams = [];
        $this->unlocker()->unlock($this->alice, $this->alicePassphrase, self::IP);
        $this->assertSame([[Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM]], $this->argonParams);
    }

    // A wrong passphrase never upgrades (or touches) the wrap.
    public function testFailedUnlockLeavesTheWrapAlone(): void
    {
        $this->principalWithWrap($this->alice, $this->alicePassphrase, 2, 16 * 1024 * 1024);
        $before = $this->row('SELECT * FROM vault_wraps WHERE user_id = ?', [$this->alice]);
        $this->assertVaultError('unlock_failed', fn () => $this->unlocker()->unlock($this->alice, 'wrong passphrase here', self::IP));
        $this->assertSame($before, $this->row('SELECT * FROM vault_wraps WHERE user_id = ?', [$this->alice]));
    }
}
