<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';
require_once __DIR__.'/Support/TestRoster.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Controller\EntryController;
use Kanboard\Plugin\Vault\Controller\HardwareKeyController;
use Kanboard\Plugin\Vault\Controller\SecurityController;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Model\HardwareKeys;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultFailure;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use Kanboard\Plugin\Vault\Test\Support\SoftAuthenticator;
use Kanboard\Plugin\Vault\Test\Support\WebAuthnVectors;
use Kanboard\Plugin\Vault\WebAuthn\CborBytes;
use KanboardTests\units\Base;

// T20 (spec: Hardware keys → Enrolment, two keys required; Removing a key; relying-party ID; Unlock; Key rotation;
// Recovery; Throttling; Audit). A software authenticator answers the server's own challenges, so every rule runs
// against real CBOR, real signatures and server-issued, single-use challenges. Carries: R10, R12, R20, R30, R33, R52,
// R54, T19 M3 (a bad Ed25519 key can't register), single-use 120 s challenges, credential ownership, prf_salt
// storage, origin/rp_id normalisation, the credential id from authData.
class HardwareKeysTest extends Base
{
    use ServiceFixture;

    private const ORIGIN = 'https://kb.example';
    private const RP = 'kb.example';
    private string $sk = '';

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpVault();
        $this->container['configModel']->save(['application_url' => 'https://kb.example/']);
        $this->container['memoryCache']->flush();
        $this->container['vaultUnlock'] = fn () => $this->unlockService();
        $this->container['vaultPrincipals'] = fn () => new PrincipalModel($this->container, $this->slots(), $this->argon(), $this->clock(), $this->rotation());
        $this->container['vaultRotation'] = fn () => $this->rotation();
        $this->container['vaultRecovery'] = fn () => $this->recovery();
        $this->container['vaultHousekeeping'] = fn () => new Housekeeping($this->container, $this->clock(), $this->rotation());
        $this->container['vaultHardwareKeys'] = fn () => $this->hw();
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->sk = $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-alice');
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function hw(?RotationService $rotation = null): HardwareKeys
    {
        return new HardwareKeys($this->container, $this->slots(), $this->argon(), $this->clock(), $rotation ?? $this->rotation());
    }

    // Registers $new for alice. $others: the keys she already has, each presenting a fresh assertion.
    private function register(SoftAuthenticator $new, array $others = [], string $passphrase = Fixtures::PASSPHRASE, ?HardwareKeys $hw = null, string $label = 'key'): void
    {
        $hw ??= $this->hw();
        $hw->registerKey($this->alice, $this->sk, $this->registration($new, $others, $label), $passphrase, self::IP);
        $this->refreshSk();
    }

    private function registration(SoftAuthenticator $new, array $others = [], string $label = 'key', int $userId = 0): array
    {
        $userId = $userId ?: $this->alice;
        $c = $this->hw()->challenge($userId, 'register');
        return [
            'label' => $label,
            'create' => $new->create($c, self::ORIGIN, self::RP),
            'assert' => $new->get($this->hw()->challenge($userId, 'ceremony'), self::ORIGIN, self::RP, HardwareKeys::prfSaltFor($c)),
            'others' => array_map(fn (SoftAuthenticator $k) => $this->assertion($k, 'ceremony', $userId), $others),
        ];
    }

    // A fresh assertion by $key for a challenge the server issued for $purpose, with the PRF output for its stored salt.
    private function assertion(SoftAuthenticator $key, string $purpose = 'unlock', int $userId = 0): array
    {
        $userId = $userId ?: $this->alice;
        return $key->get($this->hw()->challenge($userId, $purpose), self::ORIGIN, self::RP, $this->saltOf($key));
    }

    private function saltOf(SoftAuthenticator $key): string
    {
        $row = $this->row('SELECT prf_salt FROM vault_webauthn WHERE credential_id = ?', [$key->id()]);
        return $row === null ? random_bytes(32) : base64_decode($row['prf_salt']);
    }

    // The session's sk after a change (a rotation switches the session to sk2).
    private function refreshSk(): void
    {
        $sk = $this->session()->secretKey();
        if ($sk !== null) {
            $this->sk = $sk;
        }
    }

    private function unlockWithKey(SoftAuthenticator $key, string $passphrase = Fixtures::PASSPHRASE, ?array $assertion = null, string $sid = 'sid-key'): string
    {
        $this->sid = $sid;
        $this->https();
        $sessionKey = $this->unlockService()->unlock($this->alice, $passphrase, self::IP, $assertion ?? $this->assertion($key));
        $this->sendCookieBack();
        return $sessionKey;
    }

    private function keyRows(): int
    {
        return $this->countRows('SELECT COUNT(*) FROM vault_webauthn WHERE user_id = ?', [$this->alice]);
    }

    private function wraps(string $method): array
    {
        $s = $this->pdo()->prepare('SELECT * FROM vault_wraps WHERE user_id = ? AND method = ? ORDER BY id');
        $s->execute([$this->alice, $method]);
        return $s->fetchAll(\PDO::FETCH_ASSOC);
    }

    private function keyGen(): int
    {
        return (int) $this->row('SELECT key_gen FROM vault_principals WHERE user_id = ?', [$this->alice])['key_gen'];
    }

    private function twoKeys(): array
    {
        $a = new SoftAuthenticator(-8);
        $b = new SoftAuthenticator(-7);
        $this->register($a, [], Fixtures::PASSPHRASE, null, 'A');
        $this->register($b, [$a], Fixtures::PASSPHRASE, null, 'B');
        return [$a, $b];
    }

    private function token(): string
    {
        return $this->container['token']->getReusableCSRFToken();
    }

    // One controller request carrying the cookie the last response set (as SecurityControllerTest does).
    private function call(string $controller, string $action, string $method = 'POST', array $post = [], array $server = [], ?bool $ajax = null, array $get = []): VaultTestResponse
    {
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        if ($ajax ?? $method === 'POST') {
            $server += ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'];
        }
        $this->container['request'] = new Request($this->container, $server + [
            'REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => self::IP,
        ], $get, $post, [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new $controller($this->container))->$action();
        return $response;
    }

    private function post(string $controller, string $action, array $post = [], array $server = [], ?bool $ajax = null): VaultTestResponse
    {
        return $this->call($controller, $action, 'POST', $post + ['csrf_token' => $this->token()], $server, $ajax);
    }

    // The JSON the browser posts: every binary field base64url.
    private static function wire(array $a): string
    {
        $out = [];
        foreach ($a as $k => $v) {
            $out[$k] = is_string($v) && $k !== 'credential_id' ? WebAuthnVectors::b64u($v) : $v;
        }
        return json_encode($out);
    }

    private function dom(string $html): \DOMXPath
    {
        $doc = new \DOMDocument();
        @$doc->loadHTML('<?xml encoding="utf-8"?>'.$html);
        return new \DOMXPath($doc);
    }

    private function entry(string $title = 'kept'): int
    {
        $s = $this->store();
        $g = $s->createGroup($this->alice, null, ['name' => 'g']);
        return $s->createEntry($this->alice, $g, Fixtures::entry($title));
    }

    // Spec: "They register a second key. Its wrap is created, the bare passphrase wrap is deleted and key rotation
    // runs" (R30: with every surviving factor, each key's PRF KEK). The first key adds a passphrase+prf wrap and keeps
    // the passphrase wrap; the second deletes it and rotates, so afterwards both keys (each with the passphrase) open
    // the new key, the passphrase alone opens nothing, and the old sk opens no key row.
    // Kills: the second key keeping the passphrase wrap; no rotation (key_gen unchanged); a rotation that omits the
    // first key's factor (key A can't unlock); the first key rotating already.
    public function testSecondKeyDeletesPassphraseWrapAndRotates(): void
    {
        $e = $this->entry();
        $oldSk = $this->sk;
        $a = new SoftAuthenticator(-8);
        $this->register($a, [], Fixtures::PASSPHRASE, null, 'A');
        $this->assertSame(1, $this->keyRows());
        $this->assertCount(1, $this->wraps('passphrase'), 'the first key keeps the passphrase wrap');
        $this->assertCount(1, $this->wraps('passphrase+prf'));
        $this->assertSame(1, $this->keyGen(), 'no rotation for the first key');
        $this->assertSame(['hw_key_add'], array_values(array_intersect($this->auditActions(), ['hw_key_add', 'rotate'])));

        $b = new SoftAuthenticator(-7);
        // R30: the first key must take part in the rotation the second one starts.
        $this->assertVaultError('rotation_needs_factors', fn () => $this->register($b, [], Fixtures::PASSPHRASE, null, 'B'));
        $this->assertSame(1, $this->keyRows());
        $this->register($b, [$a], Fixtures::PASSPHRASE, null, 'B');
        $this->assertSame(2, $this->keyRows());
        $this->assertSame([], $this->wraps('passphrase'), 'the bare passphrase wrap is gone');
        $prf = $this->wraps('passphrase+prf');
        $this->assertCount(2, $prf);
        $this->assertSame([['active', 2], ['active', 2]], array_map(fn ($w) => [$w['status'], (int) $w['key_gen']], $prf));
        $this->assertSame(2, $this->keyGen(), 'rotated');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rotations'));
        $this->assertSame(['hw_key_add', 'hw_key_add', 'rotate'], array_values(array_filter($this->auditActions(), fn ($a) => in_array($a, ['hw_key_add', 'rotate'], true))));

        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, Fixtures::PASSPHRASE, self::IP));
        foreach ([$a, $b] as $i => $key) {
            $this->unlockWithKey($key, Fixtures::PASSPHRASE, null, "sid-$i");
            $sk = $this->session()->secretKey();
            $this->assertSame(Fixtures::ENTRY_PASSWORD, $this->store()->readField($this->alice, $e, 'password', $sk));
        }
        // A backup taken now is useless to the pre-rotation key.
        $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($oldSk, sodium_crypto_box_publickey_from_secretkey($oldSk));
        $s = $this->pdo()->query('SELECT * FROM vault_keys');
        foreach ($s->fetchAll(\PDO::FETCH_ASSOC) as $k) {
            try {
                Sealer::openDek(base64_decode($k['sealed_dek']), $keypair, $k['object_type'], (int) $k['object_id'], (int) $k['key_epoch'], (int) $k['principal_id']);
                $this->fail('the old sk opened a post-rotation key row');
            } catch (\Kanboard\Plugin\Vault\Crypto\CryptoException) {
            }
        }
        // A third key adds a wrap of the current key, no rotation.
        $c = new SoftAuthenticator(-8);
        $this->register($c, [$a, $b]);
        $this->assertSame([3, 2, []], [count($this->wraps('passphrase+prf')), $this->keyGen(), $this->wraps('passphrase')]);
        $this->unlockWithKey($c, Fixtures::PASSPHRASE, null, 'sid-c');
    }

    // Spec: "If an admin requires hardware keys, users who don't have two keys are sent straight to enrolment after a
    // passphrase unlock and can't view entries until they finish." Kills: the gate missing on entry endpoints or the
    // page; the gate blocking the enrolment page itself; the gate staying after the second key; the gate applied when
    // the policy is off.
    public function testRequiredPolicyForcesEnrolment(): void
    {
        $hw = $this->hw();
        $this->assertFalse($hw->enrolmentRequired($this->alice), 'policy off');
        $this->settings()->set('vault_hw_required', 1, self::ADMIN);
        $this->assertTrue($hw->enrolmentRequired($this->alice));
        $this->assertFalse($hw->enrolmentRequired($this->bob), 'not enrolled in the vault');

        $tree = $this->post(EntryController::class, 'tree');
        $this->assertSame([403, ['ok' => false, 'reason' => 'hw_enrolment_required']], [$tree->status, $tree->json_()]);
        $page = $this->call(VaultController::class, 'index', 'GET');
        $this->assertSame(303, $page->status);
        $this->assertStringContainsString('controller=HardwareKeyController', $page->headers['Location'] ?? '');
        $this->assertSame(200, $this->call(HardwareKeyController::class, 'index', 'GET')->status, 'the enrolment page itself is open');

        $a = new SoftAuthenticator();
        $this->register($a);
        $this->assertTrue($hw->enrolmentRequired($this->alice), 'one key is not enough');
        $this->assertSame(403, $this->post(EntryController::class, 'tree')->status);
        $this->register(new SoftAuthenticator(), [$a]);
        $this->assertFalse($hw->enrolmentRequired($this->alice));
        $this->assertSame(200, $this->post(EntryController::class, 'tree')->status);
        $this->assertSame(200, $this->call(VaultController::class, 'index', 'GET')->status);
    }

    // Spec: "While hardware keys are required, the count can't drop below two." Removal needs a fresh assertion from
    // another key. Kills: no count check; a check against the policy's absence; removal by the key's own assertion;
    // a removal that leaves its wrap behind.
    public function testCannotDropBelowTwoWhenRequired(): void
    {
        [$a, $b] = $this->twoKeys();
        $this->settings()->set('vault_hw_required', 1, self::ADMIN);
        $this->assertVaultError('hw_keys_required', fn () => $this->hw()->removeKey($this->alice, $b->id(), $this->assertion($a, 'ceremony'), $this->sk, Fixtures::PASSPHRASE, self::IP));
        $this->assertSame(2, $this->keyRows());

        $c = new SoftAuthenticator();
        $this->register($c, [$a, $b]);
        $this->assertVaultError('hw_key_invalid', fn () => $this->hw()->removeKey($this->alice, $b->id(), $this->assertion($b, 'ceremony')), 'not by its own assertion');
        // Nor by someone else's key: the assertion's credential must be one of alice's.
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->insertKeyFor($this->bob, $bobs = new SoftAuthenticator());
        $foreign = $bobs->get($this->hw()->challenge($this->alice, 'ceremony'), self::ORIGIN, self::RP, $this->saltOf($bobs));
        $this->assertVaultError('hw_key_invalid', fn () => $this->hw()->removeKey($this->alice, $b->id(), $foreign));
        $this->assertSame(3, $this->keyRows());
        $this->hw()->removeKey($this->alice, $b->id(), $this->assertion($a, 'ceremony'));
        $this->assertSame(2, $this->keyRows());
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_wraps WHERE credential_id = ?', [$b->id()]), 'its wrap goes with it');
        $this->assertSame(1, count($this->auditRows('hw_key_remove')));
        $this->assertVaultError('hw_keys_required', fn () => $this->hw()->removeKey($this->alice, $c->id(), $this->assertion($a, 'ceremony'), $this->sk, Fixtures::PASSPHRASE, self::IP));
        $this->unlockWithKey($c, Fixtures::PASSPHRASE, null, 'sid-c');
    }

    // Spec: "every unlock needs a fresh signed assertion, so a replayed PRF value doesn't work online." Challenges are
    // single-use, expire after 120 s and are bound to the user and the purpose. Kills: a challenge not consumed; no
    // expiry or the wrong TTL; the purpose or the user not checked; consumption rolled back with the failed attempt.
    public function testReplayedPrfWithoutFreshAssertionFails(): void
    {
        [$a] = $this->twoKeys();
        $assertion = $this->assertion($a);
        $this->unlockWithKey($a, Fixtures::PASSPHRASE, $assertion, 'sid-1');
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, $assertion, 'sid-2'));

        // The same PRF output under a stale assertion, with a fresh challenge issued but not used.
        $this->hw()->challenge($this->alice, 'unlock');
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, $assertion, 'sid-3'));

        $expiring = $this->assertion($a);
        $this->now += HardwareKeys::CHALLENGE_TTL;
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, $expiring, 'sid-4'));
        $justInTime = $this->assertion($a);
        $this->now += HardwareKeys::CHALLENGE_TTL - 1;
        $this->unlockWithKey($a, Fixtures::PASSPHRASE, $justInTime, 'sid-5');
        $this->assertSame(120, HardwareKeys::CHALLENGE_TTL);

        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, $this->assertion($a, 'ceremony'), 'sid-6'), 'another purpose');
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, $a->get($this->hw()->challenge($this->bob, 'unlock'), self::ORIGIN, self::RP, $this->saltOf($a)), 'sid-7'), "another user's challenge");
        // A failed attempt still burns its challenge: a corrupted signature, then the untouched original.
        $good = $this->assertion($a);
        $bad = $good;
        $bad['signature'] = $a->sign('something else');
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, $bad, 'sid-8'));
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, $good, 'sid-9'));
        $this->unlockWithKey($a, Fixtures::PASSPHRASE, null, 'sid-10');
    }

    // Spec: "Moving Kanboard to a new domain makes hardware-key wraps unusable … unlock reports a mismatch plainly."
    // A key pinned to kb.example under an Application URL on another host is rp_id_mismatch, a fixed reason with its
    // own message (not the generic unlock failure), and so is a request whose Host isn't the Application URL's.
    // Kills: the pin not checked; the mismatch reported as unlock_failed; the Host not compared.
    public function testRpIdMismatchMessage(): void
    {
        [$a] = $this->twoKeys();
        $assertion = $this->assertion($a);
        $this->container['configModel']->save(['application_url' => 'https://vault.example/']);
        $this->container['memoryCache']->flush();
        $this->sid = 'sid-moved';
        $this->request(['HTTPS' => 'on', 'HTTP_HOST' => 'vault.example']);
        $this->assertVaultError('rp_id_mismatch', fn () => $this->unlockService()->unlock($this->alice, Fixtures::PASSPHRASE, self::IP, $assertion));
        $this->assertSame([409, 'rp_id_mismatch'], VaultFailure::map(new \Kanboard\Plugin\Vault\Model\VaultException('rp_id_mismatch')));

        $r = $this->post(HardwareKeyController::class, 'unlock', ['passphrase' => Fixtures::PASSPHRASE, 'assertion' => self::wire($this->assertion($a))], ['HTTP_HOST' => 'vault.example']);
        $this->assertSame([409, ['ok' => false, 'reason' => 'rp_id_mismatch']], [$r->status, $r->json_()]);
        $page = $this->call(VaultController::class, 'index', 'GET', [], ['HTTP_HOST' => 'vault.example']);
        $messages = json_decode((string) $this->dom($page->body)->query('//*[@id="vault-app"]/@data-messages')->item(0)?->nodeValue, true);
        $this->assertStringContainsString('different web address', $messages['rp_id_mismatch'] ?? '');

        // The Host the browser used isn't the Application URL's host.
        $this->request(['HTTPS' => 'on', 'HTTP_HOST' => 'kb.example']);
        $this->assertVaultError('rp_id_mismatch', fn () => $this->hw()->rpBinding());
        $this->request(['HTTPS' => 'on', 'HTTP_HOST' => 'Vault.Example:443']);
        $this->assertSame(['origin' => 'https://vault.example', 'rp_id' => 'vault.example'], $this->hw()->rpBinding());
    }

    // Spec: the Application URL "must be a non-empty https:// URL, or http://localhost on the dev stack. Otherwise
    // hardware-key enrolment is refused." R20: http://localhost needs VAULT_DEV_INSECURE_LOCALHOST=1 and a localhost
    // Host. The binding is normalised (scheme and host lower-cased, the default port dropped, the path ignored).
    // Kills: an empty URL accepted; http accepted off localhost; localhost accepted without the opt-in or with
    // another Host; no normalisation; the settings page still showing a localhost binding without the opt-in.
    public function testApplicationUrlRequired(): void
    {
        $url = function (string $u): void {
            $this->container['configModel']->save(['application_url' => $u]);
            $this->container['memoryCache']->flush();
        };
        foreach (['', 'http://kb.example/', 'ftp://kb.example/', 'https://user:pw@kb.example/'] as $bad) {
            $url($bad);
            $this->assertVaultError('application_url_required', fn () => $this->hw()->rpBinding());
        }
        $this->assertVaultError('application_url_required', fn () => $this->hw()->challenge($this->alice, 'register'));
        $r = $this->post(HardwareKeyController::class, 'challenge', ['purpose' => 'register']);
        $this->assertSame([409, ['ok' => false, 'reason' => 'application_url_required']], [$r->status, $r->json_()]);

        $url('HTTPS://KB.Example:443/kanboard/');
        $this->request(['HTTPS' => 'on', 'HTTP_HOST' => 'KB.example']);
        $this->assertSame(['origin' => 'https://kb.example', 'rp_id' => 'kb.example'], $this->hw()->rpBinding());
        $url('https://kb.example:8443/');
        $this->assertSame(['origin' => 'https://kb.example:8443', 'rp_id' => 'kb.example'], $this->hw()->rpBinding());

        $url('http://localhost:8081/');
        $this->request(['HTTP_HOST' => 'localhost:8081']);
        $this->assertVaultError('application_url_required', fn () => $this->hw()->rpBinding());
        $this->assertNull(VaultSettings::relyingParty('http://localhost:8081/'), 'R20: the settings page too');
        putenv('VAULT_DEV_INSECURE_LOCALHOST=1');
        $this->assertSame(['origin' => 'http://localhost:8081', 'rp_id' => 'localhost'], $this->hw()->rpBinding());
        $this->assertSame(['origin' => 'http://localhost:8081', 'rp_id' => 'localhost'], VaultSettings::relyingParty('http://localhost:8081/', true));
        $this->request(['HTTP_HOST' => 'kb.example']);
        $this->assertVaultError('application_url_required', fn () => $this->hw()->rpBinding());
    }

    // Spec: "A recovery code bypasses hardware keys": the locked page's "use recovery code" flow (R52) removes every key
    // and its wraps (each audited hw_key_remove), sets the new passphrase and rotates. Kills: keys kept after a code
    // use; their wraps kept; the removals not audited; the flow not reachable from the locked page.
    public function testRecoveryRemovesKeys(): void
    {
        [$a, $b] = $this->twoKeys();
        $this->recovery()->setPolicy('code', self::ADMIN);
        $code = $this->recovery()->createCode($this->alice, $this->sk);
        $this->session()->lock($this->alice);
        $this->jar->sets = [];

        $locked = $this->dom($this->call(VaultController::class, 'index', 'GET')->body);
        $this->assertSame(1, $locked->query('//a[@data-vault-link="recover"]')->length, 'Forgot passphrase? on the locked page');

        $r = $this->post(VaultController::class, 'recover', ['code' => $code, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE]);
        $this->assertSame([200, ['ok' => true, 'rotation' => 'done']], [$r->status, $r->json_()]);
        $this->assertSame(0, $this->keyRows());
        $this->assertSame([], $this->wraps('passphrase+prf'));
        $this->assertCount(2, $this->auditRows('hw_key_remove'));
        $this->assertCount(1, $this->auditRows('recovery_used'));
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, $this->assertion($a), 'sid-old-key'));
        $this->unlockAs($this->alice, Fixtures::NEW_PASSPHRASE, 'sid-new');
    }

    // The PRF unlock needs the passphrase AND that key's PRF output: a wrong passphrase, another key's PRF, or another
    // user's credential all fail as the one generic unlock_failed, each counted as a failed guess (spec: Throttling,
    // "Vault passphrase (and PRF unlock)"). The KEK is exactly BLAKE2b(Argon2id(passphrase), enc("kek","prf",id,prf)).
    // Kills: the passphrase ignored; the PRF ignored; the credential looked up without the user; failures uncounted.
    public function testUnlockNeedsPassphraseAndThatKeysPrf(): void
    {
        [$a, $b] = $this->twoKeys();
        $streak = fn (): int => \Kanboard\Plugin\Vault\Model\FailedGuess::streak(new \Kanboard\Plugin\Vault\Model\VaultDb($this->container), $this->alice);
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::WRONG_PASSPHRASE));
        $this->assertSame(1, $streak());
        $swapped = $this->assertion($a);
        $swapped['prf'] = $b->prf($this->saltOf($b));
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, $swapped));
        $this->assertSame(2, $streak());

        // Bob's credential presented by alice.
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->insertKeyFor($this->bob, $c = new SoftAuthenticator());
        $foreign = $c->get($this->hw()->challenge($this->alice, 'unlock'), self::ORIGIN, self::RP, $this->saltOf($c));
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($c, Fixtures::PASSPHRASE, $foreign));

        // The wrap's KEK is the spec's.
        $w = $this->row('SELECT * FROM vault_wraps WHERE credential_id = ?', [$a->id()]);
        $ikm = ($this->argon())(Fixtures::PASSPHRASE, base64_decode($w['kdf_salt']), (int) $w['kdf_ops'], (int) $w['kdf_mem']);
        $kek = \Kanboard\Plugin\Vault\Crypto\Kdf::kek($ikm, 'prf', $a->rawId, $a->prf($this->saltOf($a)));
        $pk = base64_decode($this->row('SELECT public_key FROM vault_principals WHERE user_id = ?', [$this->alice])['public_key']);
        $this->assertSame($pk, sodium_crypto_box_publickey_from_secretkey(\Kanboard\Plugin\Vault\Crypto\Wraps::unwrap($w, $kek, $pk)));
        $this->unlockWithKey($a);
        $this->assertSame(0, $streak(), 'a success resets the streak');
    }

    // A credential row for another user, as registration would leave it (no wrap needed for the ownership check).
    private function insertKeyFor(int $userId, SoftAuthenticator $key): void
    {
        $c = $this->hw()->challenge($userId, 'register');
        $reg = $key->create($c, self::ORIGIN, self::RP);
        $att = \Kanboard\Plugin\Vault\WebAuthn\Cbor::decode($reg['attestationObject']);
        $auth = \Kanboard\Plugin\Vault\WebAuthn\AuthData::parse($att['authData']->bytes, true);
        $this->pdo()->prepare('INSERT INTO vault_webauthn (user_id, credential_id, cose_public_key, sign_count, prf_salt, label, origin, rp_id, created_at) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?)')
            ->execute([$userId, $key->id(), base64_encode($auth->coseKeyCbor), base64_encode(random_bytes(32)), 'bob key', self::ORIGIN, self::RP, $this->now]);
    }

    // Spec: "The server stores the credential id, the COSE key, signCount, prf_salt, the origin and the rp_id." The id
    // is the one in authData (T19 contract), prf_salt is the server's (derived from its own registration challenge),
    // and a credential id can be registered once. Kills: the client's id stored; a client-chosen or missing salt; no
    // binding stored; a duplicate credential accepted.
    public function testRegistrationStoresWhatTheSpecLists(): void
    {
        $a = new SoftAuthenticator(-7);
        $c = $this->hw()->challenge($this->alice, 'register');
        $reg = [
            'label' => 'Desk key',
            'create' => $a->create($c, self::ORIGIN, self::RP),
            'assert' => $a->get($this->hw()->challenge($this->alice, 'ceremony'), self::ORIGIN, self::RP, HardwareKeys::prfSaltFor($c)),
            'others' => [],
            'rawId' => WebAuthnVectors::b64u('client says something else'),
        ];
        $this->hw()->registerKey($this->alice, $this->sk, $reg, Fixtures::PASSPHRASE, self::IP);
        $row = $this->row('SELECT * FROM vault_webauthn WHERE user_id = ?', [$this->alice]);
        $this->assertSame($a->id(), $row['credential_id']);
        $this->assertSame(HardwareKeys::prfSaltFor($c), base64_decode($row['prf_salt']));
        $this->assertSame(32, strlen(HardwareKeys::prfSaltFor($c)));
        $this->assertNotSame(HardwareKeys::prfSaltFor($c), HardwareKeys::prfSaltFor(random_bytes(32)));
        $this->assertSame([self::ORIGIN, self::RP, 'Desk key', 1], [$row['origin'], $row['rp_id'], $row['label'], (int) $row['sign_count']]);
        $this->assertNotSame('', $row['cose_public_key']);
        $w = $this->row("SELECT * FROM vault_wraps WHERE method = 'passphrase+prf'");
        $this->assertSame($a->id(), $w['credential_id']);
        $this->assertSame($this->alice, (int) $this->auditRows('hw_key_add')[0]['actor_user_id']);

        // The new key's assertion must name the id from authData (the client's claim is checked, never stored).
        $this->refreshSk();
        $other = new SoftAuthenticator();
        $claim = $this->registration($other);
        $claim['assert']['credential_id'] = WebAuthnVectors::b64u('client says something else');
        $this->assertVaultError('hw_key_invalid', fn () => $this->hw()->registerKey($this->alice, $this->sk, $claim, Fixtures::PASSPHRASE, self::IP));

        // The same credential again (a second registration of one key) is refused, and so is any reuse of the challenge.
        $this->refreshSk();
        $this->assertVaultError('hw_key_invalid', fn () => $this->hw()->registerKey($this->alice, $this->sk, $this->registration($a, [$a]), Fixtures::PASSPHRASE, self::IP));
        $this->assertVaultError('hw_key_invalid', fn () => $this->hw()->registerKey($this->alice, $this->sk, $reg, Fixtures::PASSPHRASE, self::IP));
        $this->assertSame(1, $this->keyRows());
    }

    // Spec: "The client must report prf.enabled", and the JS refuses such a key too. T19 M3: an Ed25519 public key that
    // isn't a valid point of the main subgroup can't register. A wrong passphrase registers nothing and is a failed
    // guess. Kills: prf.enabled unchecked; the Ed25519 point unchecked; the passphrase unchecked.
    public function testRegistrationRefusals(): void
    {
        $noPrf = new SoftAuthenticator();
        $c = $this->hw()->challenge($this->alice, 'register');
        $reg = ['label' => 'x', 'create' => $noPrf->create($c, self::ORIGIN, self::RP, false),
            'assert' => $noPrf->get($this->hw()->challenge($this->alice, 'ceremony'), self::ORIGIN, self::RP, HardwareKeys::prfSaltFor($c)), 'others' => []];
        $this->assertVaultError('hw_key_invalid', fn () => $this->hw()->registerKey($this->alice, $this->sk, $reg, Fixtures::PASSPHRASE, self::IP));

        // A small-order point (the identity, y = 1) as the Ed25519 key: refused when the COSE key is read, so at
        // registration, before any signature could tell.
        $identity = [1 => 1, 3 => -8, -1 => 6, -2 => new CborBytes("\x01".str_repeat("\0", 31))];
        try {
            \Kanboard\Plugin\Vault\WebAuthn\CoseKey::fromCbor($identity);
            $this->fail('a small-order Ed25519 key was accepted');
        } catch (\Kanboard\Plugin\Vault\WebAuthn\WebAuthnException $e) {
            $this->assertSame('cose_invalid', $e->getMessage());
        }
        $bad = (new SoftAuthenticator(-8))->withCose($identity);
        $this->assertVaultError('hw_key_invalid', fn () => $this->hw()->registerKey($this->alice, $this->sk, $this->registration($bad), Fixtures::PASSPHRASE, self::IP));

        $this->assertVaultError('unlock_failed', fn () => $this->hw()->registerKey($this->alice, $this->sk, $this->registration(new SoftAuthenticator()), Fixtures::WRONG_PASSPHRASE, self::IP));
        $this->assertCount(1, $this->auditRows('unlock_failed'));
        $this->assertSame(0, $this->keyRows());
        $this->assertSame([], $this->wraps('passphrase+prf'));
    }

    // Spec: "signCount: … the server rejects it and audits hw_signcount" (R60: either value non-zero means the new one
    // must be greater). The audit commits although the unlock fails. Kills: the regression unaudited; the audit rolled
    // back with the failure; the stored count not advanced on success.
    public function testSignCountRegressionIsAudited(): void
    {
        [$a] = $this->twoKeys();
        $this->unlockWithKey($a);
        $stored = (int) $this->row('SELECT sign_count FROM vault_webauthn WHERE credential_id = ?', [$a->id()])['sign_count'];
        $this->assertSame($a->signCount, $stored);
        $a->signCount = 0; // a cloned key: its counter starts again
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, null, 'sid-clone'));
        $rows = $this->auditRows('hw_signcount');
        $this->assertCount(1, $rows);
        $this->assertSame((string) $this->alice, (string) $rows[0]['actor_user_id']);
        $this->assertSame($stored, (int) $this->row('SELECT sign_count FROM vault_webauthn WHERE credential_id = ?', [$a->id()])['sign_count']);
    }

    // Carry (T16): the PRF unlock refuses roster agents and kind=agent principals. Kills: the PRF path skipping the
    // roster check that the passphrase path has.
    public function testPrfUnlockRefusesAgents(): void
    {
        [$a] = $this->twoKeys();
        $this->container['vaultAgentRoster'] = new VaultTestRoster($this->container, [$this->alice => $this->bob]);
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a));
        unset($this->container['vaultAgentRoster']);
        $this->pdo()->exec("UPDATE vault_principals SET kind = 'agent' WHERE user_id = ".$this->alice);
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, null, 'sid-agent'));
    }

    // Spec: "When they're optional, dropping to one key restores a passphrase wrap, after a passphrase-plus-key
    // unlock." The remaining key and the passphrase both still unlock; the last key goes with the passphrase alone.
    // Kills: no passphrase wrap restored; the passphrase not checked before restoring it.
    public function testDroppingToOneKeyRestoresPassphraseWrap(): void
    {
        [$a, $b] = $this->twoKeys();
        $this->assertVaultError('unlock_failed', fn () => $this->hw()->removeKey($this->alice, $b->id(), $this->assertion($a, 'ceremony'), $this->sk, Fixtures::WRONG_PASSPHRASE, self::IP));
        $this->assertSame(2, $this->keyRows());
        $this->hw()->removeKey($this->alice, $b->id(), $this->assertion($a, 'ceremony'), $this->sk, Fixtures::PASSPHRASE, self::IP);
        $this->assertSame(1, $this->keyRows());
        $this->assertCount(1, $this->wraps('passphrase'));
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-pass');
        $this->unlockWithKey($a, Fixtures::PASSPHRASE, null, 'sid-a');
        $this->refreshSk();
        $this->hw()->removeKey($this->alice, $a->id(), [], $this->sk, Fixtures::PASSPHRASE, self::IP);
        $this->assertSame([0, []], [$this->keyRows(), $this->wraps('passphrase+prf')]);
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-pass-2');
    }

    // R30 / T9 carry: a rotation queued for a hardware-key user (a lowered policy) runs in the ceremony with every key
    // (Rotate my keys for key users, optionally with a new passphrase). Every registered key must be presented, or it's
    // rotation_needs_factors. Kills: a rotation that drops a key not presented; the queue flag left set; a new
    // passphrase ignored.
    public function testQueuedRotationRunsWithEveryKey(): void
    {
        [$a, $b] = $this->twoKeys();
        $this->recovery()->setPolicy('code', self::ADMIN);
        $this->recovery()->createCode($this->alice, $this->sk);
        $this->recovery()->setPolicy('none', self::ADMIN);
        $this->assertSame(1, (int) $this->row('SELECT rotate_requested FROM vault_principals WHERE user_id = ?', [$this->alice])['rotate_requested']);
        $this->unlockWithKey($a);
        $this->refreshSk();
        $this->assertSame(1, (int) $this->row('SELECT rotate_requested FROM vault_principals WHERE user_id = ?', [$this->alice])['rotate_requested'], 'a key unlock alone cannot rotate');

        $this->assertVaultError('rotation_needs_factors', fn () => $this->hw()->rotate($this->alice, $this->sk, Fixtures::PASSPHRASE, '', [$this->assertion($a, 'ceremony')], self::IP));
        $gen = $this->keyGen();
        $this->assertSame(RotationService::ROTATED, $this->hw()->rotate($this->alice, $this->sk, Fixtures::PASSPHRASE, Fixtures::NEW_PASSPHRASE, [$this->assertion($a, 'ceremony'), $this->assertion($b, 'ceremony')], self::IP));
        $this->assertSame([$gen + 1, 0], [$this->keyGen(), (int) $this->row('SELECT rotate_requested FROM vault_principals WHERE user_id = ?', [$this->alice])['rotate_requested']]);
        $this->assertVaultError('unlock_failed', fn () => $this->unlockWithKey($a, Fixtures::PASSPHRASE, null, 'sid-old'));
        $this->unlockWithKey($a, Fixtures::NEW_PASSPHRASE, null, 'sid-a');
        $this->unlockWithKey($b, Fixtures::NEW_PASSPHRASE, null, 'sid-b');
    }

    // R54: a user with hardware keys gives a fresh assertion (with the passphrase) to create a recovery code; without
    // one it's refused, and the assertion must open that key's wrap with the passphrase. Kills: the hook left empty; an
    // assertion accepted without the passphrase check.
    public function testRecoveryCodeNeedsAFreshAssertion(): void
    {
        [$a] = $this->twoKeys();
        $this->recovery()->setPolicy('code', self::ADMIN);
        $r = $this->post(SecurityController::class, 'recoveryCode', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([403, ['ok' => false, 'reason' => 'hw_assertion_required']], [$r->status, $r->json_()]);
        $r = $this->post(SecurityController::class, 'recoveryCode', ['passphrase' => Fixtures::WRONG_PASSPHRASE, 'assertion' => self::wire($this->assertion($a, 'ceremony'))]);
        $this->assertSame([401, ['ok' => false, 'reason' => 'unlock_failed']], [$r->status, $r->json_()]);
        $this->assertSame([], $this->wraps('recovery'));
        $r = $this->post(SecurityController::class, 'recoveryCode', ['passphrase' => Fixtures::PASSPHRASE, 'assertion' => self::wire($this->assertion($a, 'ceremony'))]);
        $this->assertTrue($r->json_()['ok'] ?? false);
        $this->assertCount(1, $this->wraps('recovery'));
    }

    // R52: the locked page's recovery-code flow has unlock's hardening: POST with CSRF, the transport check before any
    // work, the client IP from ClientIp, generic failures, a native POST that redirects with a code only (never the
    // secret), ROTATED and PENDING both success, roster agents refused. Kills: GET or no token accepted; a secret in
    // the redirect; PENDING shown as failure; an agent recovering a vault; the forged X-Forwarded-For bucketed.
    public function testLockedPageRecoveryFlowIsHardened(): void
    {
        $this->recovery()->setPolicy('code', self::ADMIN);
        $code = $this->recovery()->createCode($this->alice, $this->sk);
        $this->session()->lock($this->alice);
        $this->jar->sets = [];

        $form = $this->dom($this->call(VaultController::class, 'index', 'GET', [], [], null, ['recover' => '1'])->body);
        $f = $form->query('//form[@data-vault-form="recover"]')->item(0);
        $this->assertNotNull($f, 'the recovery form');
        $this->assertSame('post', $f->getAttribute('method'));
        $this->assertStringContainsString('action=recover', $f->getAttribute('action'));
        $names = array_map(fn ($n) => $n->nodeValue, iterator_to_array($form->query('.//input/@name', $f)));
        sort($names);
        $this->assertSame(['code', 'confirm', 'csrf_token', 'passphrase'], $names);
        $this->assertSame('password', $form->query('.//input[@name="passphrase"]/@type', $f)->item(0)?->nodeValue);

        $this->assertSame(403, $this->call(VaultController::class, 'recover', 'POST', ['code' => $code, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE])->status, 'no token');
        $this->assertSame(403, $this->call(VaultController::class, 'recover', 'GET', ['code' => $code, 'csrf_token' => $this->token()])->status, 'not a GET');
        $argon = $this->argonCalls;
        $plain = $this->call(VaultController::class, 'recover', 'POST', ['code' => $code, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE, 'csrf_token' => $this->token()], ['HTTPS' => '', 'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest']);
        $this->assertSame([403, 'https_required', $argon], [$plain->status, $plain->json_()['reason'] ?? null, $this->argonCalls]);
        $wrong = $this->post(VaultController::class, 'recover', ['code' => 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA', 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE], ['HTTP_X_FORWARDED_FOR' => '198.51.100.77']);
        $this->assertSame([401, ['ok' => false, 'reason' => 'unlock_failed']], [$wrong->status, $wrong->json_()]);
        $this->assertNotNull($this->row('SELECT bucket FROM vault_rate WHERE bucket = ?', [RecoveryService::ipBucket(self::IP)]), 'the real IP paid');
        $this->assertNull($this->row('SELECT bucket FROM vault_rate WHERE bucket = ?', [RecoveryService::ipBucket('198.51.100.77')]));
        $mismatch = $this->post(VaultController::class, 'recover', ['code' => $code, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => 'not the same at all']);
        $this->assertSame('passphrase_mismatch', $mismatch->json_()['reason'] ?? null);
        // A failed native POST goes back to the recovery form with the reason code only.
        $nativeWrong = $this->post(VaultController::class, 'recover', ['code' => 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA', 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE], [], false);
        $this->assertSame(303, $nativeWrong->status);
        $this->assertSame('/?controller=VaultController&action=index&plugin=Vault&vault_error=unlock_failed&recover=1', $nativeWrong->headers['Location'] ?? null);

        // A roster agent is refused like a wrong code.
        $this->container['vaultAgentRoster'] = new VaultTestRoster($this->container, [$this->alice => $this->bob]);
        $agent = $this->post(VaultController::class, 'recover', ['code' => $code, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE]);
        $this->assertSame([401, 'unlock_failed'], [$agent->status, $agent->json_()['reason'] ?? null]);
        unset($this->container['vaultAgentRoster']);

        // Native POST, and a rotation left PENDING: a success, redirected with a code only.
        unset($this->container['vaultRecovery']);
        $this->container['vaultRecovery'] = fn () => new RecoveryService($this->container, $this->slots(), $this->argon(), $this->clock(), new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session(), null, 1));
        $s = $this->store();
        $g = $s->createGroup($this->alice, null, ['name' => 'bulk']);
        for ($i = 0; $i < RotationService::CEREMONY_BATCHES + 2; $i++) {
            $s->createEntry($this->alice, $g, ['title' => "e$i"]);
        }
        $native = $this->post(VaultController::class, 'recover', ['code' => $code, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE], [], false);
        $this->assertSame(303, $native->status);
        $location = $native->headers['Location'] ?? '';
        $this->assertStringContainsString('vault_notice=recovered_pending', $location);
        foreach ([Fixtures::NEW_PASSPHRASE, str_replace('-', '', $code), $code] as $secret) {
            $this->assertStringNotContainsString($secret, $location.$native->body);
        }
        $this->assertNotNull($this->row('SELECT user_id FROM vault_rotations WHERE user_id = ?', [$this->alice]));
        $this->unlockAs($this->alice, Fixtures::NEW_PASSPHRASE, 'sid-after');
    }
}
