<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/FileDb.php';

use Kanboard\Plugin\Vault\Model\Notifier;
use Kanboard\Plugin\Vault\Model\ShareModel;
use Kanboard\Plugin\Vault\Model\VaultLock;
use KanboardTests\units\Base;

// Spec: "Of two concurrent reveals, exactly one wins." Two worker processes, each on its own connection to a
// file-backed SQLite DB, reveal the same link with the right b. Exactly one gets the ciphertext; the other gets the
// generic null; the row is gone and one share_reveal is audited.
class ShareConcurrencyTest extends Base
{
    private const NOW = 1_800_000_000;
    private const HOLD_US = 400_000;
    private const CREATOR = 1;

    private string $path;
    private string $dir;

    protected function setUp(): void
    {
        parent::setUp();
        if (! function_exists('pcntl_fork') || ! function_exists('posix_kill')) {
            $this->markTestSkipped('pcntl and posix are needed for the concurrency tests');
        }
        $this->path = VaultTestFileDb::create();
        $this->dir = sys_get_temp_dir().'/vault-t17-'.bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
        $pdo = VaultTestFileDb::connect($this->path);
        // The settings table VaultSettings reads (the reveal limit); the users row the share's FK names.
        $pdo->exec('CREATE TABLE settings ("option" TEXT PRIMARY KEY, value TEXT, changed_by INTEGER, changed_on INTEGER)');
        $pdo->prepare("INSERT INTO users (id, username, is_active) VALUES (?, 'alice', 1)")->execute([self::CREATOR]);
        $kp = sodium_crypto_box_keypair();
        $pdo->prepare("INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at, live_user_id) VALUES (?, 'human', ?, 1, 'active', ?, ?)")
            ->execute([self::CREATOR, base64_encode(sodium_crypto_box_publickey($kp)), self::NOW, self::CREATOR]);
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
        $c = VaultTestFileDb::container(VaultTestFileDb::connect($this->path, 20));
        $c['logger'] = new \Psr\Log\NullLogger();
        $c['vaultNotifier'] = fn ($c) => new class($c) extends Notifier {
            public function shareRevealed(int $creatorId): bool { return true; }
        };
        return $c;
    }

    private function shares(\Pimple\Container $c, ?callable $hook = null): ShareModel
    {
        return new ShareModel($c, fn () => self::NOW, $hook);
    }

    /** @return array{0:string,1:string} [share_id, b] */
    private function share(): array
    {
        $c = $this->container();
        $sid = str_repeat('ab', 32);
        $burn = bin2hex(random_bytes(16));
        $r = $this->shares($c)->reserve(self::CREATOR, $sid, '1d');
        $this->shares($c)->finalize(self::CREATOR, $sid, [
            'share_id' => $r['share_id'], 'ciphertext' => base64_encode('the one secret'), 'iv' => base64_encode(random_bytes(12)),
            'salt' => '', 'has_passphrase' => '0', 'burn_hash' => ShareModel::burnHash($burn), 'label' => '',
        ]);
        return [$r['share_id'], $burn];
    }

    // A reveal in a child on its own connection; its answer lands in a file ('null', the ciphertext, or the error).
    private function fork(string $name, callable $fn): int
    {
        $pid = pcntl_fork();
        $this->assertNotSame(-1, $pid, 'fork failed');
        if ($pid === 0) {
            try {
                $out = $fn($this->container());
                $out = $out === null ? 'null' : 'won:'.$out['ciphertext'];
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

    // Three rounds, each a fresh link revealed with its right b by two workers at once.
    //   pinned  A reads the row inside its transaction and pauses there; B, already past its throttle, starts its
    //           read during the pause. B must wait for A's transaction and then find nothing. A reveal that reads the
    //           row outside the transaction, or runs without the lock, lets B see the row too, and if the DELETE's row
    //           count is ignored, both win.
    //   held    the parent holds the vault lock while both workers enter reveal(); they queue on it.
    //   free    both start on one signal.
    // Kills: the SELECT moved before VaultLock::exclusive with the DELETE's row count ignored (M25); no lock at all
    // with the row count ignored (M26).
    public function testExactlyOneOfTwoReveals(): void
    {
        foreach (['pinned', 'held', 'free'] as $round) {
            [$id, $burn] = $this->share();
            $go = "go-$round";
            $hooks = ['a' => null, 'b' => null];
            if ($round === 'pinned') {
                $hooks['a'] = function (string $point): void {
                    if ($point === 'throttled') {
                        $this->signal('a-throttled');
                        $this->await('b-throttled');
                    } elseif ($point === 'read') {
                        $this->signal('a-read');
                        usleep(self::HOLD_US);
                    }
                };
                $hooks['b'] = function (string $point): void {
                    if ($point === 'throttled') {
                        $this->signal('b-throttled');
                        $this->await('a-read');
                    }
                };
            }
            $pids = [];
            foreach (['a', 'b'] as $w) {
                $pids[$w] = $this->fork("$round-$w", function ($c) use ($id, $burn, $go, $round, $w, $hooks) {
                    $this->signal("$round-$w-ready");
                    $this->await($go);
                    return $this->shares($c, $hooks[$w])->reveal($id, $burn, '203.0.113.'.($w === 'a' ? 1 : 2));
                });
            }
            $this->await("$round-a-ready");
            $this->await("$round-b-ready");
            $parent = $this->container();
            if ($round === 'held') {
                (new VaultLock($parent))->exclusive(function () use ($go): void {
                    $this->signal($go);
                    usleep(self::HOLD_US);
                });
            } else {
                $this->signal($go);
            }
            $results = [$this->join($pids['a'], "$round-a"), $this->join($pids['b'], "$round-b")];
            if ($round === 'pinned') {
                $this->assertSame('won:'.base64_encode('the one secret'), $results[0], 'pinned: A, which read first, wins');
            }
            sort($results);
            $this->assertSame(['null', 'won:'.base64_encode('the one secret')], $results, "$round: exactly one reveal wins");
            $pdo = $parent['db']->getConnection();
            $this->assertSame(0, (int) $pdo->query('SELECT COUNT(*) FROM vault_shares')->fetchColumn(), "$round: the row is gone");
        }
        $this->assertSame(3, (int) $pdo->query("SELECT COUNT(*) FROM vault_audit WHERE action = 'share_reveal'")->fetchColumn(), 'one reveal audited per link');
    }
}
