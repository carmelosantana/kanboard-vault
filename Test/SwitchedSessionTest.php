<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Controller\EntryController;
use Kanboard\Plugin\Vault\Controller\HardwareKeyController;
use Kanboard\Plugin\Vault\Controller\SecurityController;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Model\HardwareKeys;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\SwitchedSessionGuard;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use Kanboard\Plugin\Vault\Test\Support\SoftAuthenticator;
use Kanboard\Plugin\Vault\Test\Support\WebAuthnVectors;
use KanboardTests\units\Base;

// A stand-in for Steward's stewardSwitching service: only isSwitched() is read.
final class VaultTestStewardSwitching
{
    public bool $switched = false;
    public bool $throws = false;

    public function isSwitched(): bool
    {
        if ($this->throws) {
            throw new \RuntimeException('steward is broken');
        }
        return $this->switched;
    }
}

// T24b, R72: while Steward's admin "switch user" session is active, no unlock path opens the vault, and an
// unlocked vault session locks on the next Vault request. Defence in depth behind Steward's own SwitchGuard, so it
// holds even if Vault's actions were added to Steward's allow list. Steward absent: unchanged; isSwitched() throwing:
// refused (fail closed). A refusal is reason 'switched', audited as unlock_refused (actor, ip_trunc, ua_family only),
// and costs no Argon2 run, no throttle token and no failure streak.
// Kills: the check dropped from UnlockService (passphrase and PRF paths), from RecoveryService::useCode, from the
// session guard or from requireUnlocked; fail-open on a throwing service; the refusal counted as a failed guess.
class SwitchedSessionTest extends Base
{
    use ServiceFixture;

    private const ORIGIN = 'https://kb.example';
    private const RP = 'kb.example';
    private VaultTestStewardSwitching $steward;

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
        $this->steward = new VaultTestStewardSwitching();
        $this->container[SwitchedSessionGuard::SERVICE] = $this->steward;
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-alice');
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function hw(): HardwareKeys
    {
        return new HardwareKeys($this->container, $this->slots(), $this->argon(), $this->clock(), $this->rotation());
    }

    private function token(): string
    {
        return $this->container['token']->getReusableCSRFToken();
    }

    // One vault.js request carrying the cookie the last response set.
    private function post(string $controller, string $action, array $post = []): VaultTestResponse
    {
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        $this->container['request'] = new Request($this->container, [
            'REQUEST_METHOD' => 'POST', 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php',
            'REMOTE_ADDR' => self::IP, 'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
        ], [], $post + ['csrf_token' => $this->token()], [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new $controller($this->container))->$action();
        return $response;
    }

    private function sessions(): int
    {
        return $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->alice]);
    }

    // Everything a refusal must leave alone: Argon2 runs, throttle buckets and the streak, failure audits, sessions.
    private function untouched(): array
    {
        return [
            'argon' => $this->argonCalls,
            'rate' => $this->pdo()->query('SELECT bucket, tokens FROM vault_rate ORDER BY bucket')->fetchAll(\PDO::FETCH_ASSOC),
            'unlock_failed' => count($this->auditRows('unlock_failed')),
            'rate_limited' => count($this->auditRows('rate_limited')),
            'sessions' => $this->sessions(),
        ];
    }

    private function assertRefused(VaultTestResponse $r, array $before, string $what): void
    {
        $this->assertSame([403, ['ok' => false, 'reason' => 'switched']], [$r->status, $r->json_()], $what);
        $this->assertSame($before, $this->untouched(), "$what: no Argon2, no throttle, no streak, no session");
    }

    private function lockAlice(): void
    {
        $this->session()->lock($this->alice);
        $this->jar->sets = [];
    }

    // The refusal's audit row: the actor, the truncated IP and the UA family, nothing else.
    private function assertRefusalAudited(int $n): void
    {
        $rows = $this->auditRows('unlock_refused');
        $this->assertCount($n, $rows);
        foreach ($rows as $row) {
            $this->assertSame([$this->alice, '203.0.113.0/24'], [(int) $row['actor_user_id'], $row['ip_trunc']]);
            foreach (['object_type', 'object_id', 'share_hash', 'target_user_id', 'count'] as $col) {
                $this->assertNull($row[$col], $col);
            }
        }
    }

    public function testPassphraseUnlockRefusedWhileSwitched(): void
    {
        $this->lockAlice();
        $this->steward->switched = true;
        $before = $this->untouched();
        $this->assertRefused($this->post(VaultController::class, 'unlock', ['passphrase' => Fixtures::PASSPHRASE]), $before, 'right passphrase');
        $this->assertRefused($this->post(VaultController::class, 'unlock', ['passphrase' => Fixtures::WRONG_PASSPHRASE]), $before, 'wrong passphrase');
        $this->assertRefusalAudited(2);
        $this->assertStringNotContainsString(Fixtures::PASSPHRASE, json_encode($this->auditRows()));

        $this->steward->switched = false;
        $ok = $this->post(VaultController::class, 'unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([200, true], [$ok->status, $ok->json_()['ok'] ?? null], 'not switched: unchanged');
        $this->assertSame(1, $this->sessions());
    }

    public function testStewardAbsentIsUnchangedAndAThrowingStewardRefuses(): void
    {
        $this->lockAlice();
        unset($this->container[SwitchedSessionGuard::SERVICE]);
        $this->assertFalse((new SwitchedSessionGuard($this->container))->isSwitched());
        $ok = $this->post(VaultController::class, 'unlock', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([200, true], [$ok->status, $ok->json_()['ok'] ?? null], 'no Steward: unchanged');

        $this->lockAlice();
        $this->container[SwitchedSessionGuard::SERVICE] = $this->steward;
        $this->steward->throws = true;
        $this->assertTrue((new SwitchedSessionGuard($this->container))->isSwitched(), 'fail closed');
        $this->assertRefused($this->post(VaultController::class, 'unlock', ['passphrase' => Fixtures::PASSPHRASE]), $this->untouched(), 'isSwitched() throws');

        // A service that isn't Steward's (no isSwitched()) fails closed too.
        $this->container[SwitchedSessionGuard::SERVICE] = new \stdClass();
        $this->assertTrue((new SwitchedSessionGuard($this->container))->isSwitched());
    }

    public function testHardwareKeyUnlockRefusedWhileSwitched(): void
    {
        $sk = $this->session()->secretKey();
        $key = new SoftAuthenticator(-8);
        $c = $this->hw()->challenge($this->alice, 'register');
        $this->hw()->registerKey($this->alice, $sk, [
            'label' => 'A',
            'create' => $key->create($c, self::ORIGIN, self::RP),
            'assert' => $key->get($this->hw()->challenge($this->alice, 'ceremony'), self::ORIGIN, self::RP, HardwareKeys::prfSaltFor($c)),
            'others' => [],
        ], Fixtures::PASSPHRASE, self::IP);
        sodium_memzero($sk);
        $this->lockAlice();
        $salt = base64_decode($this->row('SELECT prf_salt FROM vault_webauthn WHERE credential_id = ?', [$key->id()])['prf_salt']);
        $assertion = fn (): string => self::wire($key->get($this->hw()->challenge($this->alice, 'unlock'), self::ORIGIN, self::RP, $salt));

        $this->steward->switched = true;
        $wire = $assertion();
        $before = $this->untouched();
        $this->assertRefused($this->post(HardwareKeyController::class, 'unlock', ['passphrase' => Fixtures::PASSPHRASE, 'assertion' => $wire]), $before, 'hardware key');
        $this->assertRefusalAudited(1);

        $this->steward->switched = false;
        $ok = $this->post(HardwareKeyController::class, 'unlock', ['passphrase' => Fixtures::PASSPHRASE, 'assertion' => $assertion()]);
        $this->assertSame([200, true], [$ok->status, $ok->json_()['ok'] ?? null], 'not switched: unchanged');
        $this->assertSame(1, $this->sessions());
    }

    public function testRecoveryCodeUseRefusedWhileSwitched(): void
    {
        $this->recovery()->setPolicy('code', self::ADMIN);
        $sk = $this->session()->secretKey();
        $code = $this->recovery()->createCode($this->alice, $sk);
        sodium_memzero($sk);
        $this->lockAlice();
        $wraps = $this->pdo()->query('SELECT * FROM vault_wraps ORDER BY id')->fetchAll(\PDO::FETCH_ASSOC);

        $this->steward->switched = true;
        $before = $this->untouched();
        $form = ['code' => $code, 'passphrase' => Fixtures::NEW_PASSPHRASE, 'confirm' => Fixtures::NEW_PASSPHRASE];
        $this->assertRefused($this->post(VaultController::class, 'recover', $form), $before, 'recovery code');
        $this->assertSame($wraps, $this->pdo()->query('SELECT * FROM vault_wraps ORDER BY id')->fetchAll(\PDO::FETCH_ASSOC), 'no passphrase reset');
        $this->assertRefusalAudited(1);
        $this->assertSame([], $this->auditRows('recovery_used'));

        $this->steward->switched = false;
        $ok = $this->post(VaultController::class, 'recover', $form);
        $this->assertSame([200, true], [$ok->status, $ok->json_()['ok'] ?? null], 'not switched: unchanged');
        $this->assertCount(1, $this->auditRows('recovery_used'));
    }

    // Minting a recovery code needs an unlocked session; while switched the session locks and the answer says why.
    public function testRecoveryCodeCreationRefusedWhileSwitched(): void
    {
        $this->recovery()->setPolicy('code', self::ADMIN);
        $this->steward->switched = true;
        $argon = $this->argonCalls;
        $r = $this->post(SecurityController::class, 'recoveryCode', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([403, ['ok' => false, 'reason' => 'switched']], [$r->status, $r->json_()]);
        $this->assertSame([$argon, 0, 0], [$this->argonCalls, $this->sessions(), $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE method = 'recovery'")]);
    }

    // I1: enrolment creates a keypair and a passphrase wrap; while switched an admin must not set the target's
    // passphrase. Refused in PrincipalModel::enrolHuman before the passphrase checks and any Argon2.
    public function testEnrolmentRefusedWhileSwitched(): void
    {
        $this->loginAs($this->bob);
        $this->jar->sets = [];
        $this->steward->switched = true;
        $argon = $this->argonCalls;
        $form = ['passphrase' => Fixtures::BOB_PASSPHRASE, 'confirm' => Fixtures::BOB_PASSPHRASE];
        $r = $this->post(VaultController::class, 'enrol', $form);
        $this->assertSame([403, ['ok' => false, 'reason' => 'switched']], [$r->status, $r->json_()]);
        $rows = fn (): array => [
            $this->countRows('SELECT COUNT(*) FROM vault_principals WHERE user_id = ?', [$this->bob]),
            $this->countRows('SELECT COUNT(*) FROM vault_wraps WHERE user_id = ?', [$this->bob]),
        ];
        $this->assertSame([[0, 0], $argon], [$rows(), $this->argonCalls], 'no principal, no wrap, no Argon2');
        $this->assertVaultError('switched', fn () => $this->principals()->enrolHuman($this->bob, 'x'));
        $this->assertSame($argon, $this->argonCalls, 'refused before the passphrase checks too');

        $this->steward->switched = false;
        $ok = $this->post(VaultController::class, 'enrol', $form);
        $this->assertSame([200, true], [$ok->status, $ok->json_()['ok'] ?? null], 'not switched: unchanged');
        $this->assertSame([1, 1], $rows());
    }

    public function testUnlockedSessionLocksOnTheNextRequestWhileSwitched(): void
    {
        $this->assertSame(1, $this->sessions());
        $this->steward->switched = true;
        $r = $this->post(EntryController::class, 'tree');
        $this->assertSame([403, 'switched'], [$r->status, $r->json_()['reason'] ?? null]);
        $this->assertSame(0, $this->sessions(), 'the vault session is gone');
        $this->assertNull($this->session()->secretKey());

        // Switching back doesn't bring it back: the user unlocks again.
        $this->steward->switched = false;
        $this->assertSame([401, 'locked'], [($r = $this->post(EntryController::class, 'tree'))->status, $r->json_()['reason'] ?? null]);
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
}
