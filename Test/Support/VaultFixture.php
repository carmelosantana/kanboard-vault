<?php

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\ArgonSlots;
use Kanboard\Plugin\Vault\Model\CookieJar;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RateLimiter;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultSession;

// Captures cookies instead of sending headers.
class VaultRecordingCookieJar extends CookieJar
{
    public array $sets = [];

    public function set(string $name, #[\SensitiveParameter] string $value, array $options): void
    {
        $this->sets[] = ['name' => $name, 'value' => $value, 'options' => $options];
    }

    public function last(): ?array
    {
        return $this->sets === [] ? null : $this->sets[count($this->sets) - 1];
    }
}

// Shared set-up for the enrolment, unlock and vault-session tests: a migrated DB, two users, a fixed clock,
// an injectable PHP session id, an HTTPS request, a temp Argon2 slot dir and an Argon2 spy.
trait VaultFixture
{
    protected int $now = 1_800_000_000;
    protected string $sid = 'php-session-A';
    protected VaultRecordingCookieJar $jar;
    protected string $slotDir;
    protected int $argonCalls = 0;
    protected array $argonParams = [];
    protected int $alice;
    protected int $bob;
    protected string $alicePassword = 'alice login password 1';
    protected string $alicePassphrase = 'purple otter galaxy ladder';

    protected function setUpVault(): void
    {
        putenv('VAULT_DEV_INSECURE_LOCALHOST'); // the localhost dev exception is off unless a test opts in
        // Kanboard 1.2.47's test mail client on every version: the real one with only send() mocked. 1.2.5x's test
        // Base stubs every method, so setTransport() would register nothing and getAvailableTransports() would lie.
        unset($this->container['emailClient']);
        $this->container['emailClient'] = $this->getMockBuilder(\Kanboard\Core\Mail\Client::class)
            ->setConstructorArgs([$this->container])
            ->onlyMethods(['send'])
            ->getMock();
        require_once __DIR__.'/Migrate.php';
        vault_test_migrate($this->container['db']->getConnection());
        $this->jar = new VaultRecordingCookieJar();
        $this->slotDir = sys_get_temp_dir().'/vault-t5-'.bin2hex(random_bytes(6)).'/vault';
        $this->alice = (int) $this->container['userModel']->create(['username' => 'alice-the-auditor', 'password' => $this->alicePassword]);
        $this->bob = (int) $this->container['userModel']->create(['username' => 'bob', 'password' => 'bob login password 1']);
        $this->https();
        $this->container['vaultSession'] = fn ($c) => $this->session();
    }

    protected function tearDownVault(): void
    {
        putenv('VAULT_DEV_INSECURE_LOCALHOST');
        foreach (glob($this->slotDir.'/*.lock') ?: [] as $f) {
            unlink($f);
        }
        @rmdir($this->slotDir);
        @rmdir(dirname($this->slotDir));
    }

    protected function request(array $server, array $cookies = []): void
    {
        $this->container['request'] = new Request($this->container, $server + ['REQUEST_METHOD' => 'POST', 'SCRIPT_NAME' => '/index.php'], [], [], [], $cookies);
    }

    protected function https(array $cookies = []): void
    {
        $this->request(['HTTPS' => 'on', 'HTTP_HOST' => 'kb.example'], $cookies);
    }

    // The next request carries the cookie the last response set.
    protected function sendCookieBack(): void
    {
        $last = $this->jar->last();
        $this->assertNotNull($last, 'a cookie was set');
        $this->container['request'] = new Request($this->container, $this->serverOf(), [], [], [], [$last['name'] => $last['value']]);
    }

    private function serverOf(): array
    {
        $r = $this->container['request'];
        $server = [];
        foreach (['HTTPS', 'HTTP_HOST', 'REQUEST_METHOD', 'SCRIPT_NAME'] as $k) {
            $v = $r->getServerVariable($k);
            if ($v !== '') {
                $server[$k] = $v;
            }
        }
        return $server;
    }

    protected function loginAs(int $userId): void
    {
        $this->container['userSession']->initialize($this->container['userModel']->getById($userId));
    }

    protected function session(): VaultSession
    {
        return new VaultSession($this->container, $this->jar, fn () => $this->sid, fn () => $this->now);
    }

    protected function argon(): callable
    {
        return function (string $secret, string $salt, int $ops, int $mem): string {
            $this->argonCalls++;
            $this->argonParams[] = [$ops, $mem];
            return Kdf::argon2id($secret, $salt, $ops, $mem);
        };
    }

    protected function slots(): ArgonSlots
    {
        return new ArgonSlots($this->container, $this->slotDir);
    }

    protected function principals(): PrincipalModel
    {
        return new PrincipalModel($this->container, $this->slots(), $this->argon(), fn () => $this->now);
    }

    protected function limiter(): RateLimiter
    {
        return new RateLimiter($this->container, null, fn () => $this->now);
    }

    protected function unlocker(): UnlockService
    {
        return new UnlockService($this->container, $this->slots(), $this->argon(), $this->session(), $this->limiter(), fn () => $this->now);
    }

    protected function pdo(): \PDO
    {
        return $this->container['db']->getConnection();
    }

    protected function countRows(string $sql, array $params = []): int
    {
        $s = $this->pdo()->prepare($sql);
        $s->execute($params);
        return (int) $s->fetchColumn();
    }

    protected function row(string $sql, array $params = []): ?array
    {
        $s = $this->pdo()->prepare($sql);
        $s->execute($params);
        $r = $s->fetch(\PDO::FETCH_ASSOC);
        return $r === false ? null : $r;
    }

    // A principal with a passphrase wrap at chosen KDF parameters, built by hand. Returns the keypair.
    protected function principalWithWrap(int $userId, string $passphrase, int $ops, int $mem): string
    {
        $keypair = sodium_crypto_box_keypair();
        $sk = sodium_crypto_box_secretkey($keypair);
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $pdo = $this->pdo();
        $pdo->prepare('INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at, live_user_id) VALUES (?, ?, ?, 1, ?, ?, ?)')
            ->execute([$userId, 'human', base64_encode(sodium_crypto_box_publickey($keypair)), 'active', $this->now, $userId]);
        $pdo->prepare("INSERT INTO vault_wraps (user_id, method, kdf_salt, kdf_ops, kdf_mem, status, key_gen, nonce, wrapped_sk, crypto_v, created_at) VALUES (?, 'passphrase', ?, ?, ?, 'active', 1, '', '', 1, ?)")
            ->execute([$userId, base64_encode($salt), $ops, $mem, $this->now]);
        $wrapId = (int) $pdo->lastInsertId();
        $kek = Kdf::kek(Kdf::argon2id($passphrase, $salt, $ops, $mem), 'passphrase');
        $w = Wraps::wrap($sk, $kek, $userId, 'passphrase', '', $wrapId);
        $pdo->prepare('UPDATE vault_wraps SET nonce = ?, wrapped_sk = ? WHERE id = ?')->execute([$w['nonce'], $w['wrapped_sk'], $wrapId]);
        return $keypair;
    }

    // Asserts $fn throws a VaultException with exactly this code and message.
    protected function assertVaultError(string $code, callable $fn): \Throwable
    {
        try {
            $fn();
        } catch (\Kanboard\Plugin\Vault\Model\VaultException $e) {
            $this->assertSame($code, $e->getMessage());
            $this->assertSame($code, $e->errorCode());
            return $e;
        }
        $this->fail("expected VaultException($code)");
    }
}
