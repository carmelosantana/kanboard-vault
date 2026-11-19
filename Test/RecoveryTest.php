<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Plugin\Vault\Console\OrgKeygenCommand;
use Kanboard\Plugin\Vault\Console\OrgRecoverCommand;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\OrgSecret;
use Kanboard\Plugin\Vault\Crypto\RecoveryCode;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use KanboardTests\units\Base;
use Symfony\Component\Console\Tester\CommandTester;

// Spec: Recovery (the three policies, the recovery code, the org key, org recovery, lowering the policy), with
// Throttling (a recovery code is throttled like a passphrase, in its own buckets), Key rotation (recovery and org
// recovery remove hardware keys; the recovery code is replaced and the org wrap re-sealed) and Admin settings.
class RecoveryTest extends Base
{
    use VaultFixture;

    private const IP = '203.0.113.7';
    private const NEW_PASS = 'fresh copper lantern meadow';
    private const ADMIN = 1;
    private string $bobPassphrase = 'bob vault passphrase long';
    /** @var list<array{0:string,1:array}> */
    private array $audits = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->loginAs($this->alice);
        $this->principals()->enrolHuman($this->alice, $this->alicePassphrase);
        $this->principals()->enrolHuman($this->bob, $this->bobPassphrase);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    // A fast stand-in for Argon2id (keyed BLAKE2b of the secret by the salt); KEKs, wraps and AD are all real.
    protected function argon(): callable
    {
        return function (string $secret, string $salt, int $ops, int $mem): string {
            $this->argonCalls++;
            if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
                throw new CryptoException('kdf: bad salt length');
            }
            return sodium_crypto_generichash($secret, $salt, 32);
        };
    }

    private function audit(): callable
    {
        return function (string $action, array $cols): void {
            $this->audits[] = [$action, $cols];
        };
    }

    private function rotation(): RotationService
    {
        return new RotationService($this->container, $this->slots(), $this->argon(), fn () => $this->now, $this->session());
    }

    private function recovery(?RotationService $rotation = null): RecoveryService
    {
        return new RecoveryService($this->container, $this->slots(), $this->argon(), fn () => $this->now, $rotation ?? $this->rotation(), $this->audit());
    }

    private function settings(): VaultSettings
    {
        return new VaultSettings($this->container, $this->audit(), fn () => $this->now);
    }

    private function unlockService(): UnlockService
    {
        return new UnlockService($this->container, $this->slots(), $this->argon(), $this->session(), $this->limiter(), fn () => $this->now, $this->rotation(), $this->recovery());
    }

    private function store(): ObjectStore
    {
        return new ObjectStore($this->container, fn () => $this->now);
    }

    private function principal(int $userId): array
    {
        return $this->row('SELECT * FROM vault_principals WHERE user_id = ?', [$userId]);
    }

    // The principal's sk, opened from its active passphrase wrap at its current key_gen.
    private function skFor(int $userId, string $passphrase): string
    {
        $p = $this->principal($userId);
        $w = $this->row("SELECT * FROM vault_wraps WHERE user_id = ? AND method = 'passphrase' AND status = 'active' AND key_gen = ?", [$userId, $p['key_gen']]);
        $this->assertNotNull($w, 'an active passphrase wrap');
        $kek = Kdf::kek(($this->argon())($passphrase, base64_decode($w['kdf_salt']), (int) $w['kdf_ops'], (int) $w['kdf_mem']), 'passphrase');
        return Wraps::unwrap($w, $kek, base64_decode($p['public_key']));
    }

    // Unlocks in a fresh PHP session and returns the session's sk.
    private function unlock(int $userId, string $passphrase, string $sid, string $ip = self::IP): string
    {
        $this->sid = $sid;
        $this->loginAs($userId);
        $this->https();
        $this->unlockService()->unlock($userId, $passphrase, $ip);
        $this->sendCookieBack();
        $sk = $this->session()->secretKey();
        $this->assertNotNull($sk);
        return $sk;
    }

    private function policy(string $policy): void
    {
        $this->recovery()->setPolicy($policy, self::ADMIN);
    }

    private function wraps(int $userId, string $method): array
    {
        $s = $this->pdo()->prepare('SELECT * FROM vault_wraps WHERE user_id = ? AND method = ? ORDER BY id');
        $s->execute([$userId, $method]);
        return $s->fetchAll(\PDO::FETCH_ASSOC);
    }

    private function orgKeypair(string $display): string
    {
        $sk = OrgSecret::parse($display);
        return sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, sodium_crypto_box_publickey_from_secretkey($sk));
    }

    private function pk(string $sk): string
    {
        return sodium_crypto_box_publickey_from_secretkey($sk);
    }

    // A hardware key as T20 will leave it: a vault_webauthn row and a passphrase+prf wrap of the current sk.
    private function addHardwareKey(int $userId, string $sk): void
    {
        $p = $this->principal($userId);
        $this->pdo()->prepare("INSERT INTO vault_webauthn (user_id, credential_id, cose_public_key, sign_count, prf_salt, label, origin, rp_id, created_at) VALUES (?, 'Y3JlZDE', 'Y29zZQ==', 0, 'cHJm', 'YubiKey', 'https://kb.example', 'kb.example', ?)")
            ->execute([$userId, $this->now]);
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $this->pdo()->prepare("INSERT INTO vault_wraps (user_id, method, credential_id, kdf_salt, kdf_ops, kdf_mem, status, key_gen, nonce, wrapped_sk, crypto_v, created_at) VALUES (?, 'passphrase+prf', 'Y3JlZDE', ?, 3, 67108864, 'active', ?, '', '', 1, ?)")
            ->execute([$userId, base64_encode($salt), (int) $p['key_gen'], $this->now]);
        $id = (int) $this->pdo()->lastInsertId();
        $w = Wraps::wrap($sk, random_bytes(32), $userId, 'passphrase+prf', 'Y3JlZDE', $id);
        $this->pdo()->prepare('UPDATE vault_wraps SET nonce = ?, wrapped_sk = ? WHERE id = ?')->execute([$w['nonce'], $w['wrapped_sk'], $id]);
    }

    private function aliceEntry(): int
    {
        $s = $this->store();
        $g = $s->createGroup($this->alice, null, ['name' => 'alice group']);
        return $s->createEntry($this->alice, $g, ['title' => 'alice entry', 'password' => 'alice-secret-1']);
    }

    private function auditActions(): array
    {
        return array_column($this->audits, 0);
    }

    // Policy "None" (the default): no recovery or org wraps exist. A code can't be created, and an unlock adds no
    // org wrap even with an org key on file. Kills: a default other than none; createCode ignoring the policy;
    // the unlock adding an org wrap under a policy below code_org.
    public function testPolicyNoneHasNoRecoveryWraps(): void
    {
        $this->assertSame('none', $this->settings()->get('vault_recovery_policy'));
        $sk = $this->skFor($this->alice, $this->alicePassphrase);
        $this->assertVaultError('policy_forbids', fn () => $this->recovery()->createCode($this->alice, $sk));
        $this->assertSame([], $this->wraps($this->alice, 'recovery'));

        $this->recovery()->orgKeygen();
        $this->unlock($this->alice, $this->alicePassphrase, 'sid-none');
        $this->assertSame([], $this->wraps($this->alice, 'org'));
        $this->assertSame([], $this->recovery()->takeNotices($this->alice));

        // Control: the same calls under "code" do create a wrap, so the refusal above is the policy's.
        $this->policy('code');
        $display = $this->recovery()->createCode($this->alice, $sk);
        $this->assertMatchesRegularExpression('/^([0-9A-HJKMNP-TV-Z]{4}-){8}[0-9A-HJKMNP-TV-Z]{2}$/', $display);
        $this->assertCount(1, $this->wraps($this->alice, 'recovery'));
        $this->assertContains('recovery_code_create', $this->auditActions());
    }

    // "Using it is atomic: verify the code, create the new passphrase wrap, delete the recovery wrap, lock every
    // session, then run key rotation. A failed reset leaves the old code valid." A crash inside the transaction
    // (after start's own writes) changes nothing; then the real use rotates, removes the hardware keys, locks every
    // session, and consumes the code. Kills: committing before the rotation's writes; leaving the recovery wrap or
    // a session; not rotating; a reusable code.
    public function testCodeUseIsAtomicAndConsumes(): void
    {
        $this->policy('code');
        $entry = $this->aliceEntry();
        $sk1 = $this->unlock($this->alice, $this->alicePassphrase, 'sid-before');
        $code = $this->recovery()->createCode($this->alice, $sk1);
        $this->addHardwareKey($this->alice, $sk1);
        $before = $this->principal($this->alice);

        $crashing = new class($this->container, $this->slots(), $this->argon(), fn () => $this->now, $this->session()) extends RotationService {
            public function start(int $userId, #[\SensitiveParameter] string $sk1, #[\SensitiveParameter] array $survivingFactors): string
            {
                parent::start($userId, $sk1, $survivingFactors);
                throw new \RuntimeException('injected crash inside the recovery transaction');
            }
        };
        try {
            $this->recovery($crashing)->useCode($this->alice, $code, self::NEW_PASS, self::IP);
            $this->fail('the injected crash propagates');
        } catch (\RuntimeException $e) {
            $this->assertSame('injected crash inside the recovery transaction', $e->getMessage());
        }
        $this->assertSame($before, $this->principal($this->alice), 'nothing about the principal changed');
        $this->assertCount(1, $this->wraps($this->alice, 'recovery'), 'the old code is still valid');
        $this->assertCount(1, $this->wraps($this->alice, 'passphrase+prf'));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_webauthn WHERE user_id = ?', [$this->alice]));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->alice]));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rotations'));
        $this->assertSame($this->pk($sk1), $this->pk($this->skFor($this->alice, $this->alicePassphrase)), 'the old passphrase still opens sk1');

        // The new passphrase meets the enrolment rules; a refused one leaves the code valid too.
        $this->assertVaultError('passphrase_weak', fn () => $this->recovery()->useCode($this->alice, $code, 'too short', self::IP));
        $this->assertCount(1, $this->wraps($this->alice, 'recovery'));

        $this->assertSame(RotationService::ROTATED, $this->recovery()->useCode($this->alice, $code, self::NEW_PASS, self::IP));
        $after = $this->principal($this->alice);
        $this->assertSame((int) $before['key_gen'] + 1, (int) $after['key_gen']);
        $this->assertNotSame($before['public_key'], $after['public_key']);
        $this->assertSame([], $this->wraps($this->alice, 'recovery'), 'the code is consumed');
        $this->assertSame([], $this->wraps($this->alice, 'passphrase+prf'), 'hardware keys are removed');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_webauthn WHERE user_id = ?', [$this->alice]));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->alice]), 'every session is locked');
        $this->assertContains('recovery_used', $this->auditActions());

        $sk2 = $this->unlock($this->alice, self::NEW_PASS, 'sid-after');
        $this->assertSame('alice-secret-1', $this->store()->readEntry($this->alice, $entry, $sk2)['payload']['password']);
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, $this->alicePassphrase, self::IP));
        $this->assertVaultError('unlock_failed', fn () => $this->recovery()->useCode($this->alice, $code, 'another long passphrase here', self::IP));
    }

    // A new code replaces the old one: the old code opens nothing. Kills: keeping the old recovery wrap.
    public function testNewCodeReplacesOld(): void
    {
        $this->policy('code');
        $sk = $this->skFor($this->alice, $this->alicePassphrase);
        $first = $this->recovery()->createCode($this->alice, $sk);
        $second = $this->recovery()->createCode($this->alice, $sk);
        $this->assertNotSame($first, $second);
        $this->assertCount(1, $this->wraps($this->alice, 'recovery'));
        $this->assertVaultError('unlock_failed', fn () => $this->recovery()->useCode($this->alice, $first, self::NEW_PASS, self::IP));
        $this->assertSame(RotationService::ROTATED, $this->recovery()->useCode($this->alice, $second, self::NEW_PASS, self::IP));
    }

    // Spec Throttling: "Recovery code: the same buckets as the passphrase, kept separately". Five failures start
    // the per-principal back-off, which is checked before any work (no Argon2); the passphrase bucket is
    // untouched. Then the per-IP bucket: 30 failures per 10 min from one IP. Kills: no back-off check, the check
    // after the work, sharing the passphrase bucket, no IP bucket.
    public function testCodeRateLimitedLikePassphrase(): void
    {
        $this->policy('code');
        $code = $this->recovery()->createCode($this->alice, $this->skFor($this->alice, $this->alicePassphrase));
        for ($i = 0; $i < 5; $i++) {
            $this->assertVaultError('unlock_failed', fn () => $this->recovery()->useCode($this->alice, RecoveryCode::generate()['display'], self::NEW_PASS, self::IP));
        }
        $argon = $this->argonCalls;
        $this->assertVaultError('rate_limited', fn () => $this->recovery()->useCode($this->alice, $code, self::NEW_PASS, self::IP));
        $this->assertSame($argon, $this->argonCalls, 'throttling runs before any Argon2 work');
        $this->assertCount(1, $this->wraps($this->alice, 'recovery'));
        $this->unlock($this->alice, $this->alicePassphrase, 'sid-pass'); // the passphrase buckets are separate

        $this->now += 3600;
        // Thirty failures from one IP, spread over other principals so no principal back-off kicks in.
        for ($u = 0; $u < 30; $u++) {
            $this->assertVaultError('unlock_failed', fn () => $this->recovery()->useCode(5000 + $u, $code, self::NEW_PASS, '198.51.100.4'));
        }
        $this->assertVaultError('rate_limited', fn () => $this->recovery()->useCode($this->alice, $code, self::NEW_PASS, '198.51.100.4'));
        $this->unlock($this->alice, $this->alicePassphrase, 'sid-ip', '198.51.100.4'); // the passphrase IP bucket is separate
        $this->assertSame(RotationService::ROTATED, $this->recovery()->useCode($this->alice, $code, self::NEW_PASS, self::IP));
    }

    // Spec: "When the policy is turned on, each user gets an org wrap at their next unlock, and sees a one-time
    // banner explaining that the org key holder can now recover their vault." Kills: no wrap, a wrap that doesn't
    // open to the user's sk, a second wrap on the next unlock, no banner, a banner shown twice.
    public function testOrgWrapAddedAtNextUnlockWithBanner(): void
    {
        $display = $this->recovery()->orgKeygen();
        $this->policy('code_org');
        $this->assertSame([], $this->wraps($this->alice, 'org'));

        $sk = $this->unlock($this->alice, $this->alicePassphrase, 'sid-1');
        $wraps = $this->wraps($this->alice, 'org');
        $this->assertCount(1, $wraps);
        $this->assertSame('active', $wraps[0]['status']);
        $opened = Wraps::openOrg(base64_decode($wraps[0]['wrapped_sk']), $this->orgKeypair($display), $this->alice, $this->pk($sk));
        $this->assertSame($sk, $opened);
        $this->assertSame(['org_enabled'], $this->recovery()->takeNotices($this->alice));
        $this->assertSame([], $this->recovery()->takeNotices($this->alice), 'the banner shows once');

        $this->unlock($this->alice, $this->alicePassphrase, 'sid-2');
        $this->assertCount(1, $this->wraps($this->alice, 'org'));
        $this->assertSame([], $this->recovery()->takeNotices($this->alice));
        $this->assertSame([], $this->wraps($this->bob, 'org'), 'bob has not unlocked yet');
    }

    // Spec: "Lowering the policy deletes the affected wraps at once, then queues key rotation for every user who
    // had one. That rotation runs at each user's next unlock." code_org → code removes org wraps only; code → none
    // removes recovery wraps. Alice's next unlock rotates, so the org key holder's old copy of sk1 opens nothing
    // new. Kills: deleting the wrong methods, not queueing, queueing only some users, the unlock not rotating.
    public function testLoweringPolicyDeletesWraps(): void
    {
        $display = $this->recovery()->orgKeygen();
        $this->policy('code_org');
        $entry = $this->aliceEntry();
        $sk1 = $this->unlock($this->alice, $this->alicePassphrase, 'sid-a1');
        $this->recovery()->createCode($this->alice, $sk1);
        $this->unlock($this->bob, $this->bobPassphrase, 'sid-b1');
        $this->assertCount(1, $this->wraps($this->alice, 'org'));
        $this->assertCount(1, $this->wraps($this->bob, 'org'));
        $orgCopyOfSk1 = Wraps::openOrg(base64_decode($this->wraps($this->alice, 'org')[0]['wrapped_sk']), $this->orgKeypair($display), $this->alice, $this->pk($sk1));
        $this->audits = [];

        $this->policy('code');
        $this->assertSame([], $this->wraps($this->alice, 'org'));
        $this->assertSame([], $this->wraps($this->bob, 'org'));
        $this->assertCount(1, $this->wraps($this->alice, 'recovery'), 'code is still allowed');
        $this->assertSame('1', (string) $this->principal($this->alice)['rotate_requested']);
        $this->assertSame('1', (string) $this->principal($this->bob)['rotate_requested']);
        $this->assertSame([['policy_change', ['actor_user_id' => self::ADMIN]]], $this->audits);
        $this->assertSame('code', $this->settings()->get('vault_recovery_policy'));

        $this->policy('none');
        $this->assertSame([], $this->wraps($this->alice, 'recovery'));

        $gen = (int) $this->principal($this->alice)['key_gen'];
        $sk2 = $this->unlock($this->alice, $this->alicePassphrase, 'sid-a2');
        $p = $this->principal($this->alice);
        $this->assertSame($gen + 1, (int) $p['key_gen'], 'the queued rotation ran at the next unlock');
        $this->assertSame('0', (string) $p['rotate_requested']);
        $this->assertSame($this->pk($sk2), base64_decode($p['public_key']));
        $this->assertNotSame($this->pk($orgCopyOfSk1), $this->pk($sk2));
        $this->assertSame('alice-secret-1', $this->store()->readEntry($this->alice, $entry, $sk2)['payload']['password']);
        $this->assertVaultError('not_found', fn () => $this->store()->readEntry($this->alice, $entry, $orgCopyOfSk1));
        $this->assertSame('1', (string) $this->principal($this->bob)['rotate_requested'], 'bob rotates at his own next unlock');

        // R30: a hardware key can't be presented at a passphrase unlock, so bob's queued rotation waits for it.
        $bobSk = $this->skFor($this->bob, $this->bobPassphrase);
        $this->addHardwareKey($this->bob, $bobSk);
        $bobGen = (int) $this->principal($this->bob)['key_gen'];
        $this->unlock($this->bob, $this->bobPassphrase, 'sid-b2');
        $this->assertSame($bobGen, (int) $this->principal($this->bob)['key_gen']);
        $this->assertSame('1', (string) $this->principal($this->bob)['rotate_requested']);
        $this->assertCount(1, $this->wraps($this->bob, 'passphrase+prf'));
    }

    // Spec: org recovery "reads the org secret from stdin, sets a new passphrase and runs key rotation"; with no
    // hardware key present it removes them all. The org wrap is re-sealed to the new key. Kills: leaving hardware
    // keys or their wraps, not rotating, not re-sealing the org wrap, accepting the wrong org secret.
    public function testOrgRecoverRemovesHardwareKeysAndRotates(): void
    {
        $display = $this->recovery()->orgKeygen();
        $this->policy('code_org');
        $entry = $this->aliceEntry();
        $sk1 = $this->unlock($this->alice, $this->alicePassphrase, 'sid-a1');
        $this->addHardwareKey($this->alice, $sk1);
        $before = $this->principal($this->alice);

        $wrong = OrgSecret::format(sodium_crypto_box_secretkey(sodium_crypto_box_keypair()));
        $this->assertVaultError('recovery_failed', fn () => $this->recovery()->orgRecover('alice-the-auditor', $wrong, self::NEW_PASS));
        $this->assertVaultError('recovery_failed', fn () => $this->recovery()->orgRecover('nobody-here', $display, self::NEW_PASS));
        $this->assertVaultError('recovery_failed', fn () => $this->recovery()->orgRecover('bob', $display, self::NEW_PASS)); // no org wrap yet
        $this->assertSame($before, $this->principal($this->alice));
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_webauthn WHERE user_id = ?', [$this->alice]));

        $this->audits = [];
        $this->assertSame(RotationService::ROTATED, $this->recovery()->orgRecover('alice-the-auditor', $display, self::NEW_PASS));
        $after = $this->principal($this->alice);
        $this->assertSame((int) $before['key_gen'] + 1, (int) $after['key_gen']);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_webauthn WHERE user_id = ?', [$this->alice]));
        $this->assertSame([], $this->wraps($this->alice, 'passphrase+prf'));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rotations'));
        $this->assertSame([
            ['hw_key_remove', ['actor_user_id' => $this->alice, 'actor_kind' => 'cli', 'via' => 'cli']],
            ['org_recovery', ['target_user_id' => $this->alice, 'actor_kind' => 'cli', 'via' => 'cli']],
        ], $this->audits);

        $sk2 = $this->unlock($this->alice, self::NEW_PASS, 'sid-a2');
        $this->assertSame(base64_decode($after['public_key']), $this->pk($sk2));
        $org = $this->wraps($this->alice, 'org');
        $this->assertCount(1, $org);
        $this->assertSame(['active', (int) $after['key_gen']], [$org[0]['status'], (int) $org[0]['key_gen']]);
        $this->assertSame($sk2, Wraps::openOrg(base64_decode($org[0]['wrapped_sk']), $this->orgKeypair($display), $this->alice, $this->pk($sk2)), 'the org wrap is re-sealed to the new key');
        $this->assertContains('org_recovered', $this->recovery()->takeNotices($this->alice));
        $this->assertSame('alice-secret-1', $this->store()->readEntry($this->alice, $entry, $sk2)['payload']['password']);
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, $this->alicePassphrase, self::IP));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND principal_key_gen <> ?', [$this->alice, (int) $after['key_gen']]));
    }

    // Org recovery while a rotation is pending (its old wraps are gone, the org wrap pending for sk2): the org key
    // opens sk2, the pending rotation is finished, then the recovery rotation runs. Kills: refusing (the user would
    // be stuck), or using the pending wrap without finishing the rotation first.
    public function testOrgRecoverFinishesAPendingRotationFirst(): void
    {
        $display = $this->recovery()->orgKeygen();
        $this->policy('code_org');
        $entry = $this->aliceEntry();
        $sk1 = $this->unlock($this->alice, $this->alicePassphrase, 'sid-a1');
        $kek = Kdf::kek(($this->argon())('mid rotation passphrase', str_repeat('s', 16), 3, 67108864), 'passphrase');
        $sk2 = $this->rotation()->start($this->alice, $sk1, [['method' => 'passphrase', 'kek' => $kek, 'kdf_salt' => str_repeat('s', 16), 'kdf_ops' => 3, 'kdf_mem' => 67108864]]);
        $this->assertSame('pending', $this->wraps($this->alice, 'org')[0]['status'], 'start re-sealed the org wrap to sk2, pending');
        $gen = (int) $this->principal($this->alice)['key_gen'];

        $this->assertSame(RotationService::ROTATED, $this->recovery()->orgRecover('alice-the-auditor', $display, self::NEW_PASS));
        $this->assertSame($gen + 2, (int) $this->principal($this->alice)['key_gen'], 'the pending rotation finished, then the recovery rotated');
        $sk3 = $this->unlock($this->alice, self::NEW_PASS, 'sid-a3');
        $this->assertNotSame($this->pk($sk2), $this->pk($sk3));
        $this->assertSame('alice-secret-1', $this->store()->readEntry($this->alice, $entry, $sk3)['payload']['password']);
    }

    // Spec: "vault:org-keygen prints the org secret key once, as base32 with a checksum, and stores only the public
    // key." A second run refuses and prints nothing secret. Kills: storing the secret anywhere, printing it twice,
    // overwriting an existing org key without --replace.
    public function testOrgKeygenPrintsOnceStoresPublicOnly(): void
    {
        $tester = new CommandTester(new OrgKeygenCommand($this->container, fn () => $this->recovery()));
        $this->assertSame(0, $tester->execute([]));
        $out = $tester->getDisplay();
        $this->assertSame(1, preg_match_all('/(?:[0-9A-HJKMNP-TV-Z]{4}-){13}[0-9A-HJKMNP-TV-Z]{2}/', $out, $m));
        $display = $m[0][0];
        $sk = OrgSecret::parse($display);
        $pk = $this->pk($sk);
        $this->assertSame(base64_encode($pk), $this->row('SELECT org_pk FROM vault_meta WHERE id = 1')['org_pk']);

        $dump = '';
        $tables = $this->pdo()->query("SELECT name FROM sqlite_master WHERE type = 'table'")->fetchAll(\PDO::FETCH_COLUMN);
        foreach ($tables as $t) {
            $dump .= json_encode($this->pdo()->query('SELECT * FROM "'.$t.'"')->fetchAll(\PDO::FETCH_ASSOC));
        }
        foreach ([base64_encode($sk), bin2hex($sk), $display, str_replace('-', '', $display), base64_encode(sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, $pk))] as $needle) {
            $this->assertStringNotContainsString($needle, $dump);
        }

        $again = new CommandTester(new OrgKeygenCommand($this->container, fn () => $this->recovery()));
        $this->assertNotSame(0, $again->execute([]));
        $this->assertSame(0, preg_match('/[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-/', $again->getDisplay()));
        $this->assertSame(base64_encode($pk), $this->row('SELECT org_pk FROM vault_meta WHERE id = 1')['org_pk']);
    }

    // --replace: org wraps sealed to the old key are deleted and their users rotate at their next unlock, so the
    // old secret opens nothing written afterwards. Kills: replacing the key but keeping the old wraps.
    public function testOrgKeygenReplaceDropsOldOrgWraps(): void
    {
        $this->recovery()->orgKeygen();
        $this->policy('code_org');
        $this->unlock($this->alice, $this->alicePassphrase, 'sid-a1');
        $this->assertCount(1, $this->wraps($this->alice, 'org'));
        $old = $this->row('SELECT org_pk FROM vault_meta WHERE id = 1')['org_pk'];

        $tester = new CommandTester(new OrgKeygenCommand($this->container, fn () => $this->recovery()));
        $this->assertSame(0, $tester->execute(['--replace' => true]));
        $this->assertNotSame($old, $this->row('SELECT org_pk FROM vault_meta WHERE id = 1')['org_pk']);
        $this->assertSame([], $this->wraps($this->alice, 'org'));
        $this->assertSame('1', (string) $this->principal($this->alice)['rotate_requested']);
    }

    // The org secret and the new passphrase come from stdin only: the command takes no argument or option that
    // could carry them (argv shows up in ps and shell history), and echoes neither. Kills: a secret argument.
    public function testOrgRecoverCommandReadsSecretsFromStdinOnly(): void
    {
        $display = $this->recovery()->orgKeygen();
        $this->policy('code_org');
        $this->unlock($this->alice, $this->alicePassphrase, 'sid-a1');

        $command = new OrgRecoverCommand($this->container, fn () => $this->recovery());
        $this->assertSame(['username'], array_keys($command->getDefinition()->getArguments()));
        $this->assertSame([], array_keys($command->getDefinition()->getOptions()));

        $tester = new CommandTester($command);
        $tester->setInputs([$display, self::NEW_PASS]);
        $this->assertSame(0, $tester->execute(['username' => 'alice-the-auditor'], ['interactive' => false]));
        $out = $tester->getDisplay();
        $this->assertStringNotContainsString($display, $out);
        $this->assertStringNotContainsString(self::NEW_PASS, $out);
        $this->unlock($this->alice, self::NEW_PASS, 'sid-a2');

        $bad = new CommandTester(new OrgRecoverCommand($this->container, fn () => $this->recovery()));
        $bad->setInputs(['not a secret', self::NEW_PASS]);
        $this->assertNotSame(0, $bad->execute(['username' => 'alice-the-auditor'], ['interactive' => false]));
    }

    // Spec Key rotation: "The recovery code is always replaced … or the user may choose to have none" and "The org
    // wrap is re-sealed to the org public key", both without the user present. So a passphrase change no longer
    // refuses for them (R30 still refuses for hardware keys), re-seals the org wrap, drops the code and tells the
    // user once. Kills: refusing on org/recovery, leaving an org wrap of sk1, keeping the old code, no notice.
    public function testPassphraseChangeReSealsOrgWrapAndDropsRecoveryCode(): void
    {
        $display = $this->recovery()->orgKeygen();
        $this->policy('code_org');
        $sk1 = $this->unlock($this->alice, $this->alicePassphrase, 'sid-a1');
        $this->recovery()->takeNotices($this->alice);
        $this->recovery()->createCode($this->alice, $sk1);

        $principals = new PrincipalModel($this->container, $this->slots(), $this->argon(), fn () => $this->now, $this->rotation());
        $this->assertSame(RotationService::ROTATED, $principals->changePassphrase($this->alice, $this->alicePassphrase, self::NEW_PASS, $sk1));
        $sk2 = $this->skFor($this->alice, self::NEW_PASS);
        $org = $this->wraps($this->alice, 'org');
        $this->assertCount(1, $org);
        $this->assertSame($sk2, Wraps::openOrg(base64_decode($org[0]['wrapped_sk']), $this->orgKeypair($display), $this->alice, $this->pk($sk2)));
        $this->assertSame([], $this->wraps($this->alice, 'recovery'));
        $this->assertSame(['recovery_code_reset'], $this->recovery()->takeNotices($this->alice));

        $this->addHardwareKey($this->alice, $sk2);
        $this->assertVaultError('rotation_needs_factors', fn () => $principals->changePassphrase($this->alice, self::NEW_PASS, 'yet another long passphrase', $sk2));
    }

    // Admin settings: typed defaults, validation, and a policy_change audit row per change. The policy key goes
    // through setPolicy, so lowering it from the settings page deletes wraps too. Kills: unvalidated values, a
    // missing audit, a second path to the policy that skips the wrap deletion.
    public function testSettingsValidateAndAudit(): void
    {
        $s = $this->settings();
        $this->assertSame(365, $s->get('vault_audit_retention_days'));
        $this->assertSame('', $s->get('vault_trusted_proxy_cidrs'));
        $this->assertSame(0, $s->get('vault_hw_required'));
        $this->assertSame(15, $s->get('vault_idle_timeout'));

        $s->set('vault_idle_timeout', 30, self::ADMIN);
        $this->assertSame(30, $s->get('vault_idle_timeout'));
        $this->assertSame([['policy_change', ['actor_user_id' => self::ADMIN]]], $this->audits);
        $this->assertVaultError('payload_invalid', fn () => $s->set('vault_idle_timeout', 4, self::ADMIN));
        $this->assertVaultError('payload_invalid', fn () => $s->set('vault_recovery_policy', 'everyone', self::ADMIN));
        $this->assertVaultError('payload_invalid', fn () => $s->set('vault_trusted_proxy_cidrs', '10.0.0.0/8, not-a-cidr', self::ADMIN));
        $s->set('vault_trusted_proxy_cidrs', '127.0.0.1/32, 172.16.0.0/12', self::ADMIN);
        $this->assertSame('127.0.0.1/32,172.16.0.0/12', $s->get('vault_trusted_proxy_cidrs'));
        $this->expectException(\InvalidArgumentException::class);
        $s->get('vault_unknown');
    }

    // R12 / T5: secrets never reach a stack trace. Every secret parameter of the recovery API is marked. Kills:
    // dropping any one of the attributes.
    public function testSecretParametersAreMarkedSensitive(): void
    {
        $secret = [
            [RecoveryService::class, 'createCode', ['sk']],
            [RecoveryService::class, 'useCode', ['code', 'newPassphrase']],
            [RecoveryService::class, 'orgRecover', ['orgSecret', 'newPassphrase']],
            [RecoveryService::class, 'reconcileAtUnlock', ['sk', 'passphrase']],
            [RecoveryService::class, 'insertOrgWrap', ['sk']],
            [OrgSecret::class, 'format', ['sk']],
            [OrgSecret::class, 'parse', ['input']],
        ];
        foreach ($secret as [$class, $method, $names]) {
            foreach ((new \ReflectionMethod($class, $method))->getParameters() as $p) {
                $marked = $p->getAttributes(\SensitiveParameter::class) !== [];
                $this->assertSame(in_array($p->getName(), $names, true), $marked, "$class::$method \${$p->getName()}");
            }
        }
    }

    public function testPolicyKeyThroughSettingsDeletesWraps(): void
    {
        $this->settings()->set('vault_recovery_policy', 'code', self::ADMIN);
        $this->recovery()->createCode($this->alice, $this->skFor($this->alice, $this->alicePassphrase));
        $this->settings()->set('vault_recovery_policy', 'none', self::ADMIN);
        $this->assertSame([], $this->wraps($this->alice, 'recovery'));
        $this->assertSame('1', (string) $this->principal($this->alice)['rotate_requested']);
    }
}
