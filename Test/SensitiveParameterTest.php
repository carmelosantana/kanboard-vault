<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\RecoveryCode;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\UnlockService;
use KanboardTests\units\Base;
use PHPUnit\Framework\Attributes\DataProvider;

// Secrets must never reach logs through exception stack-trace arguments. With zend.exception_ignore_args=Off
// (the engine default; the official Kanboard images ship no php.ini) every frame records its arguments, and
// a logged exception prints them. Each secret parameter carries #[\SensitiveParameter].
class SensitiveParameterTest extends Base
{
    use VaultFixture;

    private string|false $ignoreArgs;
    private string|false $maxLen;

    protected function setUp(): void
    {
        parent::setUp();
        $this->ignoreArgs = ini_get('zend.exception_ignore_args');
        ini_set('zend.exception_ignore_args', '0');
        // The engine default; this host's php.ini sets 0, which would hide string arguments from printed traces.
        $this->maxLen = ini_get('zend.exception_string_param_max_len');
        ini_set('zend.exception_string_param_max_len', '15');
        $this->setUpVault();
        $this->loginAs($this->alice);
    }

    protected function tearDown(): void
    {
        ini_set('zend.exception_ignore_args', (string) $this->ignoreArgs);
        ini_set('zend.exception_string_param_max_len', (string) $this->maxLen);
        $this->tearDownVault();
        parent::tearDown();
    }

    // Fails if $secret shows in the exception text, the printed trace (which cuts strings at 15 characters)
    // or any raw argument of a Vault frame. The test's own frames hold the secret on purpose.
    private function assertRedacted(string $secret, \Throwable $e): void
    {
        $this->assertSame('0', ini_get('zend.exception_ignore_args'), 'trace arguments are being recorded');
        // Lines of the printed exception and trace that belong to Vault code (the test's own frames are skipped).
        $lines = array_filter(
            explode("\n", (string) $e."\n".$e->getTraceAsString()),
            static fn (string $l): bool => ! str_contains($l, 'SensitiveParameterTest') && ! str_contains($l, 'PHPUnit\\')
        );
        $printed = implode("\n", $lines);
        $this->assertStringNotContainsString(substr($secret, 0, 15), $printed);
        $vaultFrames = 0;
        foreach ($e->getTrace() as $frame) {
            if (! str_starts_with($frame['class'] ?? '', 'Kanboard\\Plugin\\Vault\\')) {
                continue;
            }
            $vaultFrames++;
            $this->assertArrayHasKey('args', $frame, 'trace arguments are recorded');
            foreach ($frame['args'] ?? [] as $arg) {
                $this->assertFalse(is_string($arg) && str_contains($arg, substr($secret, 0, 15)), 'raw trace argument in '.($frame['function'] ?? '?'));
            }
        }
        $this->assertGreaterThan(0, $vaultFrames, 'the trace has Vault frames to check');
    }

    private function thrown(callable $fn): \Throwable
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            return $e;
        }
        $this->fail('expected an exception');
    }

    // Sanity: without the attribute, the same setup does leak (so the assertions can fail).
    public function testAnUnmarkedParameterWouldLeak(): void
    {
        $leaky = static function (string $value): void {
            throw new \RuntimeException('boom');
        };
        $e = $this->thrown(fn () => $leaky('LEAKY-SENTINEL-0123456789'));
        $this->assertStringContainsString('LEAKY-SENTINEL-', $e->getTraceAsString());
    }

    public function testUnlockPassphraseIsAbsentWhenArgon2Throws(): void
    {
        $this->principals()->enrolHuman($this->alice, $this->alicePassphrase);
        $secret = 'PASSPHRASE-SENTINEL-unlock-0123';
        $boom = function (string $s, string $salt, int $ops, int $mem): string {
            throw new \RuntimeException('argon2 exploded');
        };
        $u = new UnlockService($this->container, $this->slots(), $boom, $this->session(), $this->limiter(), fn () => $this->now);
        $e = $this->thrown(fn () => $u->unlock($this->alice, $secret, '203.0.113.9'));
        $this->assertSame('argon2 exploded', $e->getMessage());
        $this->assertRedacted($secret, $e);
    }

    public function testEnrolPassphraseIsAbsentWhenArgon2Throws(): void
    {
        $secret = 'PASSPHRASE-SENTINEL-enrol-0123';
        $boom = function (string $s, string $salt, int $ops, int $mem): string {
            throw new \RuntimeException('argon2 exploded');
        };
        $p = new PrincipalModel($this->container, $this->slots(), $boom, fn () => $this->now);
        $this->assertRedacted($secret, $this->thrown(fn () => $p->enrolHuman($this->alice, $secret)));
    }

    // The KDF upgrade re-derives with the passphrase and seals sk: an exception there carries both.
    public function testUpgradeSecretsAreAbsentWhenItThrows(): void
    {
        $this->principalWithWrap($this->alice, $this->alicePassphrase, 2, 16 * 1024 * 1024);
        $calls = 0;
        $argon = function (string $s, string $salt, int $ops, int $mem) use (&$calls): string {
            if (++$calls === 2) {
                throw new \RuntimeException('upgrade exploded');
            }
            return Kdf::argon2id($s, $salt, $ops, $mem);
        };
        $u = new UnlockService($this->container, $this->slots(), $argon, $this->session(), $this->limiter(), fn () => $this->now);
        $e = $this->thrown(fn () => $u->unlock($this->alice, $this->alicePassphrase, '203.0.113.9'));
        $this->assertSame('upgrade exploded', $e->getMessage());
        $this->assertRedacted($this->alicePassphrase, $e);
    }

    public function testSessionCreateSkIsAbsent(): void
    {
        $sk = str_pad('SK-SENTINEL-create', 32, 'x');
        $this->request(['HTTP_HOST' => 'kb.example']); // plain HTTP: create throws https_required
        $this->assertRedacted($sk, $this->thrown(fn () => $this->session()->create($this->alice, $sk)));
        $this->https();
        $this->assertRedacted($sk, $this->thrown(fn () => $this->session()->create(0, $sk)));
    }

    public static function cryptoCalls(): array
    {
        $k = str_pad('KEY-SENTINEL-crypto', 32, 'k');
        $s = str_pad('SECRET-SENTINEL-crypto', 32, 's');
        return [
            'Kdf::argon2id secret' => [$s, fn () => Kdf::argon2id($s, 'short salt', 3, Kdf::DEFAULT_MEM)],
            'Kdf::kek ikm' => [$s, fn () => Kdf::kek(substr($s, 0, 15), 'passphrase')],
            'Aead::seal plaintext and key' => [$s, fn () => Aead::seal($s, 'short key', 'ad')],
            'Aead::seal key' => [$k, fn () => Aead::seal('x', $k.'too long', 'ad')],
            'Aead::open key' => [$k, fn () => Aead::open('bad nonce', 'ct', $k, 'ad')],
            'Wraps::wrap sk' => [$s, fn () => Wraps::wrap($s, $k, 1, 'nonsense', '', 1)],
            'Wraps::wrap kek' => [$k, fn () => Wraps::wrap($s, $k, 1, 'nonsense', '', 1)],
            'Wraps::unwrap kek' => [$k, fn () => Wraps::unwrap(['crypto_v' => 1, 'method' => 'passphrase', 'nonce' => base64_encode(random_bytes(24)), 'wrapped_sk' => base64_encode(random_bytes(48)), 'user_id' => 1, 'id' => 1], $k, 'pk')],
            'Wraps::sealOrg sk' => [$s, fn () => Wraps::sealOrg($s.'x', 1, 'pk')],
            'Wraps::openOrg keypair' => [$k, fn () => Wraps::openOrg('sealed', $k.$k, 1, 'pk')],
            'Wraps::field plain' => [$s, fn () => Wraps::field($s, 'prefix', 3, 'x')],
            'Sealer::sealDek dek' => [$s, fn () => Sealer::sealDek($s.'x', 'entry', 1, 1, 1, 'pk')],
            'Sealer::openDek keypair' => [$k, fn () => Sealer::openDek('sealed', $k.$k, 'entry', 1, 1, 1)],
            'RecoveryCode::parse input' => ['RECOVERY-SENTINEL-INPUT', fn () => RecoveryCode::parse('RECOVERY-SENTINEL-INPUT')],
            'Encoding::enc fields' => [$s, fn () => Encoding::enc('dek', $s, new \stdClass())],
        ];
    }

    /** @dataProvider cryptoCalls */
    #[DataProvider('cryptoCalls')]
    public function testCryptoHelpersRedactSecrets(string $secret, callable $call): void
    {
        $this->assertRedacted($secret, $this->thrown($call));
    }
}
