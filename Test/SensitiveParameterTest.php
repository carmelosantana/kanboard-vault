<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\RecoveryCode;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\DekContext;
use Kanboard\Plugin\Vault\Model\FileKeyProvider;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\ServerKeyFile;
use Kanboard\Plugin\Vault\Model\ServerKeyUnavailable;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Model\VaultDb;
use Kanboard\Plugin\Vault\Model\ServerGrant;
use Kanboard\Plugin\Vault\Model\UnlockService;
use KanboardTests\units\Base;

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

    // The Server sk handed to FileKeyProvider::wrapNew, when the key file can't be read (the failure is raised under
    // wrapNew's frame); and the file key and Server sk behind openSealedDek / openFieldMacKey, whose refusal is a bare
    // ServerKeyUnavailable with nothing chained.
    public function testServerKeySecretsAreAbsent(): void
    {
        $dir = realpath(sys_get_temp_dir()).'/vault-sp-'.bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        $file = new ServerKeyFile($dir.'/vault-server/server.key');
        try {
            $sk = str_pad('SK-SENTINEL-server', 32, 'x');
            $e = $this->thrown(fn () => (new FileKeyProvider($this->container, $file))->wrapNew(new VaultDb($this->container), $sk));
            $this->assertInstanceOf(ServerKeyUnavailable::class, $e);
            $this->assertRedacted($sk, $e);

            $file->create();
            $fileKey = $file->read();
            $provider = new FileKeyProvider($this->container, $file);
            foreach (['openSealedDek' => fn () => $provider->openSealedDek('sealed', new DekContext('entry', 1, 1, -1)), 'openFieldMacKey' => fn () => $provider->openFieldMacKey()] as $what => $call) {
                $e = $this->thrown($call);
                $this->assertInstanceOf(ServerKeyUnavailable::class, $e, $what);
                $this->assertNull($e->getPrevious(), "$what: nothing chained");
                $this->assertRedacted($fileKey, $e);
            }
            $this->assertStringNotContainsString($fileKey, print_r($provider, true), 'print_r of the provider');
        } finally {
            @unlink($dir.'/vault-server/server.key');
            @unlink($dir.'/vault-server/.lock');
            @rmdir($dir.'/vault-server');
            @rmdir($dir);
        }
    }

    // Review fix 1: with Server on, a non-crypto failure inside the provider's keypair callback (here a database error
    // while the keypair is held) propagates; neither the Server keypair nor its sk may be in its trace.
    // Kills: an unannotated $keypair on a withKeypair callback.
    public function testServerKeypairIsAbsentWhenTheCallbackFails(): void
    {
        $dir = realpath(sys_get_temp_dir()).'/vault-sp-'.bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        $file = new ServerKeyFile($dir.'/vault-server/server.key');
        try {
            (new ServerPrincipal($this->container, $file, null, fn () => $this->now))->enable(1);
            $meta = $this->row('SELECT server_wrap_id, server_wrap_nonce, server_wrapped_sk FROM vault_meta WHERE id = 1');
            $pk = base64_decode($this->row('SELECT public_key FROM vault_principals WHERE user_id = -1')['public_key']);
            $sk = Wraps::unwrap(['id' => (int) $meta['server_wrap_id'], 'user_id' => -1, 'method' => 'server', 'credential_id' => null,
                'nonce' => $meta['server_wrap_nonce'], 'wrapped_sk' => $meta['server_wrapped_sk'], 'crypto_v' => 1], Kdf::kek($file->read(), 'server', -1), $pk);
            $this->assertSame(32, strlen((new FileKeyProvider($this->container, $file))->openFieldMacKey()), 'opens while the column is there');

            $this->pdo()->exec('ALTER TABLE vault_meta RENAME COLUMN server_field_mac_sealed TO server_field_mac_gone');
            $e = $this->thrown(fn () => (new FileKeyProvider($this->container, $file))->openFieldMacKey());
            $this->assertNotInstanceOf(ServerKeyUnavailable::class, $e, 'a database error, not a key failure');
            $this->assertNotInstanceOf(CryptoException::class, $e);
            $printed = (string) $e."\n".$e->getTraceAsString();
            $frames = 0;
            foreach ($e->getTrace() as $frame) {
                foreach ($frame['args'] ?? [] as $arg) {
                    $frames++;
                    foreach (['keypair' => $sk.$pk, 'sk' => $sk] as $what => $secret) {
                        $this->assertFalse(is_string($arg) && str_contains($arg, $secret), "the Server $what in a raw trace argument of ".($frame['function'] ?? '?'));
                    }
                }
            }
            $this->assertGreaterThan(0, $frames, 'trace arguments are recorded');
            $this->assertMatchesRegularExpression('/openFieldMacKey\(\):\d+\}|\{closure\}/', $printed, 'the callback frame is in the trace');
            $this->assertStringNotContainsString(substr($sk, 0, 15), $printed);
            $this->assertRedacted($sk.$pk, $e);
        } finally {
            @unlink($dir.'/vault-server/server.key');
            @unlink($dir.'/vault-server/.lock');
            @rmdir($dir.'/vault-server');
            @rmdir($dir);
        }
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
            // R1: the field-MAC key sealed to Server, and the keypair that opens it.
            'Sealer::sealFieldMacKey key' => [$s, fn () => Sealer::sealFieldMacKey($s.'x', -1, 'pk')],
            'Sealer::openFieldMacKey keypair' => [$k, fn () => Sealer::openFieldMacKey('sealed', $k.$k, -1)],
            'RecoveryCode::parse input' => ['RECOVERY-SENTINEL-INPUT', fn () => RecoveryCode::parse('RECOVERY-SENTINEL-INPUT')],
            'Encoding::enc fields' => [$s, fn () => Encoding::enc('dek', $s, new \stdClass())],
            // R1: the field-MAC key, and a custom field name (secret: only its MAC is ever stored).
            'ServerGrant::macField key' => [$k, fn () => ServerGrant::macField($k.'too long', 'api_token')],
            'ServerGrant::macField name' => [$s, fn () => ServerGrant::macField(str_repeat('k', 32), $s."\x01")],
        ];
    }

    /** @dataProvider cryptoCalls */
    public function testCryptoHelpersRedactSecrets(string $secret, callable $call): void
    {
        $this->assertRedacted($secret, $this->thrown($call));
    }
}
