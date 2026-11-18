<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/FileDb.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultLock;
use KanboardTests\units\Base;

// Two independent connections (one per process) on a file-backed SQLite DB, raced through the vault lock.
// One side holds the exclusive lock mid-operation while the other starts, so the interleaving is fixed:
// any check or crypto prepared outside the lock would be done against a stale snapshot and show up here.
class GrantConcurrencyTest extends Base
{
    private const NOW = 1_800_000_000;
    private const HOLD_US = 600_000;

    private string $path;
    private string $dir;
    private array $sk = [];
    private int $alice = 1;
    private int $bob = 2;
    private int $carol = 3;

    protected function setUp(): void
    {
        parent::setUp();
        if (! function_exists('pcntl_fork') || ! function_exists('posix_kill')) {
            $this->markTestSkipped('pcntl and posix are needed for the concurrency tests');
        }
        $this->path = VaultTestFileDb::create();
        $this->dir = sys_get_temp_dir().'/vault-t7-'.bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
        $pdo = VaultTestFileDb::connect($this->path);
        foreach ([$this->alice, $this->bob, $this->carol] as $id) {
            $kp = sodium_crypto_box_keypair();
            $pdo->prepare("INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at) VALUES (?, 'human', ?, 1, 'active', ?)")
                ->execute([$id, base64_encode(sodium_crypto_box_publickey($kp)), self::NOW]);
            $this->sk[$id] = sodium_crypto_box_secretkey($kp);
        }
    }

    protected function tearDown(): void
    {
        if (isset($this->path)) {
            VaultTestFileDb::remove($this->path);
            foreach (glob($this->dir.'/*') ?: [] as $f) {
                unlink($f);
            }
            @rmdir($this->dir);
        }
        parent::tearDown();
    }

    private function container(): \Pimple\Container
    {
        return VaultTestFileDb::container(VaultTestFileDb::connect($this->path, 20));
    }

    private function store(\Pimple\Container $c): ObjectStore
    {
        return new ObjectStore($c, fn () => self::NOW);
    }

    private function grants(\Pimple\Container $c): GrantModel
    {
        return new GrantModel($c, fn () => self::NOW);
    }

    // Runs $fn in a child on its own connection; its string result lands in a file. The child dies without
    // running PHPUnit's shutdown handlers.
    private function fork(string $name, callable $fn): int
    {
        $pid = pcntl_fork();
        $this->assertNotSame(-1, $pid, 'fork failed');
        if ($pid === 0) {
            try {
                $out = (string) $fn($this->container());
            } catch (\Throwable $e) {
                $out = 'E:'.get_class($e).':'.$e->getMessage();
            }
            file_put_contents("$this->dir/$name", $out);
            posix_kill(getmypid(), SIGKILL);
        }
        return $pid;
    }

    private function join(int $pid, string $name): string
    {
        pcntl_waitpid($pid, $status);
        return (string) @file_get_contents("$this->dir/$name");
    }

    private function signal(string $name): void
    {
        touch("$this->dir/$name");
    }

    private function await(string $name): void
    {
        $until = microtime(true) + 10;
        while (! file_exists("$this->dir/$name")) {
            if (microtime(true) > $until) {
                throw new RuntimeException("timed out waiting for $name");
            }
            usleep(1000);
        }
    }

    private function row(\Pimple\Container $c, string $sql, array $params = []): array
    {
        $s = $c['db']->getConnection()->prepare($sql);
        $s->execute($params);
        return $s->fetch(\PDO::FETCH_ASSOC);
    }

    private function dekOf(\Pimple\Container $c, int $entry, int $principal): string
    {
        $r = $this->row($c, "SELECT key_epoch, sealed_dek FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND principal_id = ?", [$entry, $principal]);
        $sk = $this->sk[$principal];
        $kp = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, sodium_crypto_box_publickey_from_secretkey($sk));
        return Sealer::openDek(base64_decode($r['sealed_dek']), $kp, 'entry', $entry, (int) $r['key_epoch'], $principal);
    }

    private function opens(\Pimple\Container $c, int $entry, string $dek): bool
    {
        $r = $this->row($c, 'SELECT * FROM vault_entries WHERE id = ?', [$entry]);
        for ($epoch = 1; $epoch <= (int) $r['key_epoch']; $epoch++) {
            try {
                Aead::open(base64_decode($r['nonce']), base64_decode($r['ciphertext']), $dek, ObjectStore::ad('entry', $entry, $this->alice, $epoch));
                return true;
            } catch (CryptoException) {
            }
        }
        return false;
    }

    // An edit by Bob (edit grantee) races Alice revoking Carol, in both orders. Neither write is lost, and the
    // edit never ends up under the DEK Carol held. Kills: a revoke that reads the payload or epoch before
    // taking the lock (Bob's edit is overwritten by the stale payload), and an edit that opens the DEK or
    // reads the row before the lock (the edit lands under Carol's old DEK).
    public function testEditVsRevoke(): void
    {
        $a = $this->container();
        $g1 = $this->store($a)->createGroup($this->alice, null, ['name' => 'one']);
        $e1 = $this->store($a)->createEntry($this->alice, $g1, ['title' => 'v1', 'password' => 'p1']);
        $g2 = $this->store($a)->createGroup($this->alice, null, ['name' => 'two']);
        $e2 = $this->store($a)->createEntry($this->alice, $g2, ['title' => 'v1', 'password' => 'p1']);
        foreach ([$g1, $g2] as $g) {
            $this->grants($a)->grant($this->alice, 'group', $g, $this->bob, 'edit', null, $this->sk[$this->alice]);
            $this->grants($a)->grant($this->alice, 'group', $g, $this->carol, 'read', null, $this->sk[$this->alice]);
        }
        $old1 = $this->dekOf($a, $e1, $this->carol);
        $old2 = $this->dekOf($a, $e2, $this->carol);
        unset($a);

        // 1. The edit holds the lock; the revoke starts while it does and must wait.
        $pid = $this->fork('revoke1', function ($c) use ($g1): string {
            $this->await('edit-locked');
            $this->grants($c)->revoke($this->alice, 'group', $g1, $this->carol, $this->sk[$this->alice]);
            return 'ok';
        });
        $a = $this->container();
        (new VaultLock($a))->exclusive(function () use ($a, $e1): void {
            $this->store($a)->updateEntry($this->bob, $e1, 1, ['title' => 'bob-edit-1', 'password' => 'p2'], $this->sk[$this->bob]);
            $this->signal('edit-locked');
            usleep(self::HOLD_US);
        });
        $this->assertSame('ok', $this->join($pid, 'revoke1'));

        // 2. The revoke holds the lock; the edit starts while it does and must wait.
        $pid = $this->fork('revoke2', function ($c) use ($g2): string {
            (new VaultLock($c))->exclusive(function () use ($c, $g2): void {
                $this->grants($c)->revoke($this->alice, 'group', $g2, $this->carol, $this->sk[$this->alice]);
                $this->signal('revoke-locked');
                usleep(self::HOLD_US);
            });
            return 'ok';
        });
        $this->await('revoke-locked');
        $this->assertSame(2, $this->store($a)->updateEntry($this->bob, $e2, 1, ['title' => 'bob-edit-2', 'password' => 'p2'], $this->sk[$this->bob]));
        $this->assertSame('ok', $this->join($pid, 'revoke2'));

        foreach ([[$e1, $old1, 'bob-edit-1'], [$e2, $old2, 'bob-edit-2']] as [$e, $old, $title]) {
            $read = $this->store($a)->readEntry($this->alice, $e, $this->sk[$this->alice]);
            $this->assertSame($title, $read['payload']['title'], "entry $e kept Bob's edit");
            $this->assertSame('p2', $read['payload']['password']);
            $this->assertSame(2, $read['version']);
            $this->assertSame(2, $read['key_epoch']);
            $this->assertFalse($this->opens($a, $e, $old), "entry $e is out of reach of Carol's old DEK");
            $this->assertSame($title, $this->store($a)->readEntry($this->bob, $e, $this->sk[$this->bob])['payload']['title']);
            try {
                $this->store($a)->readEntry($this->carol, $e, $this->sk[$this->carol]);
                $this->fail('Carol was revoked');
            } catch (VaultException $ex) {
                $this->assertSame('not_found', $ex->getMessage());
            }
        }
    }

    // Carol reads in a loop on her own connection while Alice moves the entry out of the shared group and then
    // edits it. Carol sees the pre-move title or not_found, never post-move data, and her old DEK can't open
    // what was written after the move. Kills: a write that skips the move's barrier, and a move that leaves
    // Carol's key row in place while the read path trusts key rows.
    public function testMoveVsRead(): void
    {
        $a = $this->container();
        $shared = $this->store($a)->createGroup($this->alice, null, ['name' => 'shared']);
        $private = $this->store($a)->createGroup($this->alice, null, ['name' => 'private']);
        $e = $this->store($a)->createEntry($this->alice, $shared, ['title' => 'pre-move']);
        $this->grants($a)->grant($this->alice, 'group', $shared, $this->carol, 'read', null, $this->sk[$this->alice]);
        $carolCopy = $this->dekOf($a, $e, $this->carol);
        unset($a);

        $pid = $this->fork('reads', function ($c) use ($e): string {
            $seen = [];
            $read = function () use ($c, $e, &$seen): void {
                try {
                    $seen[] = $this->store($c)->readEntry($this->carol, $e, $this->sk[$this->carol])['payload']['title'];
                } catch (VaultException $ex) {
                    $seen[] = $ex->getMessage();
                }
            };
            $read();
            $this->signal('reading');
            $until = microtime(true) + 10;
            while (! file_exists("$this->dir/done") && microtime(true) < $until) {
                $read();
                usleep(2000);
            }
            $read();
            return implode(',', array_unique($seen)).'|'.$seen[array_key_last($seen)];
        });
        $this->await('reading');
        $a = $this->container();
        (new VaultLock($a))->exclusive(function () use ($a, $e, $private): void {
            $this->grants($a)->move($this->alice, 'entry', $e, $private, $this->sk[$this->alice]);
            $this->store($a)->updateEntry($this->alice, $e, 1, ['title' => 'post-move'], $this->sk[$this->alice]);
            usleep(self::HOLD_US / 2); // Carol keeps reading the committed (pre-move) snapshot meanwhile.
        });
        usleep(self::HOLD_US / 2);
        $this->signal('done');
        [$seen, $last] = explode('|', $this->join($pid, 'reads'));

        $this->assertStringContainsString('pre-move', $seen, 'Carol read before the move');
        $this->assertStringNotContainsString('post-move', $seen);
        $this->assertSame('not_found', $last);
        $this->assertFalse($this->opens($a, $e, $carolCopy), "post-move data is out of reach of Carol's old DEK");
        $this->assertSame('post-move', $this->store($a)->readEntry($this->alice, $e, $this->sk[$this->alice])['payload']['title']);
    }
}
