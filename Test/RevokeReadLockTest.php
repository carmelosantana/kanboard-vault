<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultLock;
use Kanboard\ServiceProvider\DatabaseProvider;
use KanboardTests\units\Base;

// T24 fix round 1, I2: revoke against read on two real connections to MariaDB or Postgres, where VaultLock is a
// row lock on the vault_meta singleton (FOR UPDATE for writers, LOCK IN SHARE MODE / FOR SHARE for readers) rather
// than SQLite's database lock. Alice's revoke of Bob runs on the test's connection; Bob reads on a second one with a
// one-second lock timeout. While the revoke holds the lock, Bob's read waits and times out instead of reading the
// committed pre-revoke grant (MVCC would hand it over); once it commits Bob gets not_found. The other way round,
// a revoke waits out Bob's read and changes nothing. Kills: VaultLock not locking the singleton on these drivers,
// a shared lock that doesn't conflict with the exclusive one, a read that checks grants before taking the lock.
// SQLite runs the same races in GrantConcurrencyTest (forked processes on a file DB; the test DB here is in memory).
class RevokeReadLockTest extends Base
{
    use VaultFixture;

    private const LOCK_TIMEOUT_S = 1;

    private string $aliceSk;
    private string $bobSk;
    private \PicoDb\Database $db2;

    protected function setUp(): void
    {
        parent::setUp(); // first: PHPUnit 10+ runs tearDown() after a skip in setUp(), and Kanboard's needs the container
        if (DB_DRIVER === 'sqlite') {
            $this->markTestSkipped('needs a second connection to the same database; SQLite: GrantConcurrencyTest');
        }
        $this->setUpVault();
        $this->aliceSk = $this->enrol($this->alice);
        $this->bobSk = $this->enrol($this->bob);
        $this->db2 = (new DatabaseProvider())->getInstance();
    }

    protected function tearDown(): void
    {
        if (isset($this->db2)) {
            $this->tearDownVault();
            $this->db2->closeConnection();
        }
        parent::tearDown();
    }

    private function enrol(int $userId): string
    {
        $keypair = sodium_crypto_box_keypair();
        $this->pdo()->prepare("INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at, live_user_id) VALUES (?, 'human', ?, 1, 'active', ?, ?)")
            ->execute([$userId, base64_encode(sodium_crypto_box_publickey($keypair)), $this->now, $userId]);
        return sodium_crypto_box_secretkey($keypair);
    }

    private function second(): \Pimple\Container
    {
        $c = new \Pimple\Container();
        $c['db'] = $this->db2;
        return $c;
    }

    private static function lockTimeout(\PDO $pdo, ?int $seconds): void
    {
        if ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql') {
            $pdo->exec('SET SESSION innodb_lock_wait_timeout = '.($seconds ?? 50));
        } else {
            $pdo->exec($seconds === null ? 'SET lock_timeout = DEFAULT' : "SET lock_timeout = '".$seconds."s'");
        }
    }

    // A lock wait that ran out: MariaDB error 1205, Postgres SQLSTATE 55P03 (lock_not_available).
    private function assertLockWaitTimedOut(?\Throwable $e, float $waited, string $what): void
    {
        $this->assertInstanceOf(\PDOException::class, $e, "$what: blocked on the vault lock");
        $info = $e->errorInfo ?? [];
        $this->assertTrue(($info[1] ?? null) === 1205 || ($info[0] ?? null) === '55P03', "$what: a lock-wait timeout, not ".$e->getMessage());
        $this->assertGreaterThanOrEqual(self::LOCK_TIMEOUT_S * 0.9, $waited, "$what: it waited for the lock");
    }

    private function bobReads(int $entry): mixed
    {
        return (new ObjectStore($this->second(), fn () => $this->now))->readEntry($this->bob, $entry, $this->bobSk)['payload']['title'];
    }

    public function testReadWaitsForRevokeThenIsDenied(): void
    {
        $store = new ObjectStore($this->container, fn () => $this->now);
        $entry = $store->createEntry($this->alice, $store->createGroup($this->alice, null, ['name' => 'g']), ['title' => 'shared-title', 'password' => 'p1']);
        $grants = new GrantModel($this->container, fn () => $this->now);
        $grants->grant($this->alice, 'entry', $entry, $this->bob, 'read', null, $this->aliceSk);
        $this->assertSame('shared-title', $this->bobReads($entry), 'Bob reads before the revoke');

        self::lockTimeout($this->db2->getConnection(), self::LOCK_TIMEOUT_S);
        [$seen, $error, $waited] = (new VaultLock($this->container))->exclusive(function () use ($grants, $entry): array {
            $grants->revoke($this->alice, 'entry', $entry, $this->bob, $this->aliceSk);
            $t0 = microtime(true);
            try {
                return [$this->bobReads($entry), null, microtime(true) - $t0];
            } catch (\Throwable $e) {
                return [null, $e, microtime(true) - $t0];
            }
        });
        $this->assertNull($seen, 'no read completed while the revoke held the lock');
        $this->assertLockWaitTimedOut($error, $waited, 'Bob\'s read during the revoke');

        try {
            $this->bobReads($entry);
            $this->fail('Bob was revoked');
        } catch (VaultException $e) {
            $this->assertSame('not_found', $e->getMessage());
        }
    }

    public function testRevokeWaitsForReadInProgress(): void
    {
        $store = new ObjectStore($this->container, fn () => $this->now);
        $entry = $store->createEntry($this->alice, $store->createGroup($this->alice, null, ['name' => 'g']), ['title' => 'shared-title', 'password' => 'p1']);
        $grants = new GrantModel($this->container, fn () => $this->now);
        $grants->grant($this->alice, 'entry', $entry, $this->bob, 'read', null, $this->aliceSk);

        self::lockTimeout($this->pdo(), self::LOCK_TIMEOUT_S);
        [$seen, $error, $waited] = (new VaultLock($this->second()))->shared(function () use ($grants, $entry): array {
            $seen = $this->bobReads($entry);
            $t0 = microtime(true);
            try {
                $grants->revoke($this->alice, 'entry', $entry, $this->bob, $this->aliceSk);
                return [$seen, null, microtime(true) - $t0];
            } catch (\Throwable $e) {
                return [$seen, $e, microtime(true) - $t0];
            }
        });
        self::lockTimeout($this->pdo(), null);
        $this->assertSame('shared-title', $seen, 'Bob read under his shared lock');
        $this->assertLockWaitTimedOut($error, $waited, 'Alice\'s revoke during Bob\'s read');
        $this->assertSame('shared-title', $this->bobReads($entry), 'the timed-out revoke changed nothing');

        $grants->revoke($this->alice, 'entry', $entry, $this->bob, $this->aliceSk);
        $this->assertVaultError('not_found', fn () => $this->bobReads($entry));
    }
}
