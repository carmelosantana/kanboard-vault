<?php
require_once 'tests/units/Base.php';

use Kanboard\Plugin\Vault\Model\ServerKeyFile;
use Kanboard\Plugin\Vault\Model\ServerKeyUnavailable;
use PHPUnit\Framework\TestCase;

// Spec amendment: Server key file (SEC-12). Ports Matinee's KeyStoreTest file cases and adds the stricter ones:
// no-follow on every path component, fstat of the open descriptor (regular, owner, mode exactly 0600, nlink 1,
// 32 bytes), no chmod repair, never created by a read, never replaced.
class ServerKeyFileTest extends TestCase
{
    private string $base;
    private string $dir;
    private string $path;
    private int $umask;

    protected function setUp(): void
    {
        $this->umask = umask(0022);
        // realpath: the base itself has no symlink in it (e.g. a /tmp that is a link).
        $this->base = realpath(sys_get_temp_dir()).'/vault-skf-'.bin2hex(random_bytes(8));
        mkdir($this->base, 0700);
        $this->dir = $this->base.'/vault-server';
        $this->path = $this->dir.'/server.key';
    }

    protected function tearDown(): void
    {
        umask($this->umask);
        $this->rmTree($this->base);
    }

    private function rmTree(string $path): void
    {
        if (is_link($path)) {
            unlink($path);
            return;
        }
        if (!file_exists($path)) {
            return;
        }
        if (is_dir($path)) {
            chmod($path, 0700);
            foreach (scandir($path) as $entry) {
                if ($entry !== '.' && $entry !== '..') {
                    $this->rmTree($path.'/'.$entry);
                }
            }
            rmdir($path);
            return;
        }
        unlink($path);
    }

    private function writeKey(string $path, string $bytes, int $mode = 0600): void
    {
        if (!is_dir(dirname($path))) {
            mkdir(dirname($path), 0700, true);
        }
        file_put_contents($path, $bytes);
        chmod($path, $mode);
    }

    private function mode(string $path): int
    {
        clearstatcache();
        return fileperms($path) & 07777;
    }

    private function assertUnavailable(callable $call): ServerKeyUnavailable
    {
        try {
            $call();
        } catch (ServerKeyUnavailable $e) {
            $this->assertSame('server_key_unavailable', $e->getMessage());
            return $e;
        }
        $this->fail('expected ServerKeyUnavailable');
    }

    // Kills a mode taken from the umask (022 would leave 0644 / 0755) and a key regenerated per read.
    public function testCreateThenRead(): void
    {
        $file = new ServerKeyFile($this->path);
        $file->create();
        $first = $file->read();
        $this->assertSame(ServerKeyFile::KEY_BYTES, strlen($first));
        $this->assertSame($first, $file->read());
        $this->assertSame($first, (new ServerKeyFile($this->path))->read());
        $this->assertSame(0600, $this->mode($this->path));
        $this->assertSame(0700, $this->mode($this->dir));
        $this->assertSame(1, stat($this->path)['nlink']);
        $this->assertSame('ok', $file->status());
        $this->assertSame($this->path, $file->path());

        // A second create keeps the valid file.
        $file->create();
        $this->assertSame($first, $file->read());
    }

    // Kills read() falling back to create().
    public function testReadNeverCreates(): void
    {
        $file = new ServerKeyFile($this->path);
        $this->assertUnavailable(fn () => $file->read());
        $this->assertFalse(file_exists($this->path));
        $this->assertFalse(file_exists($this->dir));
        $this->assertSame('missing', $file->status());

        mkdir($this->dir, 0700);
        $this->assertUnavailable(fn () => $file->read());
        $this->assertFalse(file_exists($this->path));
        $this->assertFalse(file_exists($this->dir.'/.lock'));
        $this->assertSame('missing', $file->status());
    }

    // Kills an fopen that follows the link (no lstat / ino check) and an 'x' open that isn't checked.
    public function testSymlinkedFileFailsClosed(): void
    {
        $target = $this->base.'/elsewhere/server.key';
        $bytes = random_bytes(32);
        $this->writeKey($target, $bytes);
        mkdir($this->dir, 0700);
        symlink($target, $this->path);

        $file = new ServerKeyFile($this->path);
        $this->assertUnavailable(fn () => $file->read());
        $this->assertUnavailable(fn () => $file->create());
        $this->assertSame('unsafe', $file->status());
        $this->assertSame($bytes, file_get_contents($target));
        $this->assertTrue(is_link($this->path));

        // A dangling link: create must not write through it.
        unlink($this->path);
        $dangling = $this->base.'/elsewhere/new.key';
        symlink($dangling, $this->path);
        $this->assertUnavailable(fn () => $file->create());
        $this->assertFalse(file_exists($dangling));
    }

    // Kills checking only the last component.
    public function testSymlinkInAPathComponentFailsClosed(): void
    {
        $real = $this->base.'/real/vault-server/server.key';
        $bytes = random_bytes(32);
        $this->writeKey($real, $bytes);
        chmod($this->base.'/real', 0700);
        symlink($this->base.'/real', $this->base.'/link');

        $file = new ServerKeyFile($this->base.'/link/vault-server/server.key');
        $this->assertUnavailable(fn () => $file->read());
        $this->assertUnavailable(fn () => $file->create());
        $this->assertSame('unsafe', $file->status());
        $this->assertSame($bytes, file_get_contents($real));

        // A symlinked last directory, which create() would otherwise mkdir into.
        $file = new ServerKeyFile($this->base.'/link2/server.key');
        symlink($this->base.'/real/vault-server', $this->base.'/link2');
        $this->assertUnavailable(fn () => $file->read());
        $this->assertUnavailable(fn () => $file->create());
    }

    // Kills replace-on-bad-size.
    public function testWrongSizeFailsClosedAndIsKept(): void
    {
        foreach ([31, 33, 0] as $n) {
            $bytes = random_bytes(max($n, 1));
            $bytes = substr($bytes, 0, $n);
            $this->writeKey($this->path, $bytes);
            $file = new ServerKeyFile($this->path);
            $this->assertUnavailable(fn () => $file->read());
            $this->assertUnavailable(fn () => $file->create());
            $this->assertSame('unsafe', $file->status());
            $this->assertSame($bytes, file_get_contents($this->path));
            $this->assertSame(0600, $this->mode($this->path));
        }
    }

    public static function looseModes(): array
    {
        return ['0640' => [0640], '0644' => [0644], '0604' => [0604], '0660' => [0660], '0400' => [0400], '0700' => [0700]];
    }

    /**
     * Kills KeyStore's chmod repair and a `& 0077` check (0400 and 0700 would pass it).
     *
     * @dataProvider looseModes
     */
    public function testLooseModeFailsClosedNeverRepaired(int $mode): void
    {
        $bytes = random_bytes(32);
        $this->writeKey($this->path, $bytes, $mode);
        $file = new ServerKeyFile($this->path);
        $this->assertUnavailable(fn () => $file->read());
        $this->assertSame($mode, $this->mode($this->path));
        $this->assertUnavailable(fn () => $file->create());
        $this->assertSame($mode, $this->mode($this->path));
        $this->assertSame('unsafe', $file->status());
        chmod($this->path, 0600);
        $this->assertSame($bytes, file_get_contents($this->path));
    }

    // Kills a missing uid check (on the file and on the directory).
    public function testWrongOwnerFailsClosed(): void
    {
        (new ServerKeyFile($this->path))->create();
        $file = new ServerKeyFile($this->path, posix_geteuid() + 1);
        $this->assertUnavailable(fn () => $file->read());
        $this->assertUnavailable(fn () => $file->create());
        $this->assertSame('unsafe', $file->status());
    }

    // Kills a missing nlink check.
    public function testHardLinkFailsClosed(): void
    {
        $file = new ServerKeyFile($this->path);
        $file->create();
        link($this->path, $this->path.'.2');
        $this->assertUnavailable(fn () => $file->read());
        $this->assertUnavailable(fn () => $file->create());
        $this->assertSame('unsafe', $file->status());
    }

    // Kills a missing dir check, or a dir chmod.
    public function testGroupWritableDirFailsClosed(): void
    {
        $file = new ServerKeyFile($this->path);
        $file->create();
        foreach ([0770, 0702, 0777] as $mode) {
            chmod($this->dir, $mode);
            $this->assertUnavailable(fn () => $file->read());
            $this->assertUnavailable(fn () => $file->create());
            $this->assertSame('unsafe', $file->status());
            $this->assertSame($mode, $this->mode($this->dir));
        }
    }

    // A missing grandparent is not created (only the last directory is), and a relative path never works.
    public function testOnlyTheLastDirectoryIsCreatedAndPathsAreAbsolute(): void
    {
        $file = new ServerKeyFile($this->base.'/missing/vault-server/server.key');
        $this->assertUnavailable(fn () => $file->create());
        $this->assertFalse(file_exists($this->base.'/missing'));

        $file = new ServerKeyFile('vault-server/server.key');
        $this->assertUnavailable(fn () => $file->create());
        $this->assertUnavailable(fn () => $file->read());
        $this->assertSame('unsafe', $file->status());
    }

    // A symlinked or foreign lock file fails closed too.
    public function testSymlinkedLockFailsClosed(): void
    {
        $file = new ServerKeyFile($this->path);
        $file->create();
        unlink($this->dir.'/.lock');
        touch($this->base.'/other-lock');
        symlink($this->base.'/other-lock', $this->dir.'/.lock');
        $this->assertUnavailable(fn () => $file->read());
        $this->assertUnavailable(fn () => $file->create());
    }

    // Kills create without O_EXCL + flock (two keys, or a reader seeing a partial file).
    public function testConcurrentCreateKeepsOneKey(): void
    {
        $child = __DIR__.'/fixtures/server-key-race.php';
        for ($round = 0; $round < 3; $round++) {
            $this->rmTree($this->dir);
            $procs = [];
            for ($i = 0; $i < 4; $i++) {
                $pipes = [];
                $proc = proc_open([PHP_BINARY, $child, $this->path], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
                $this->assertIsResource($proc);
                $procs[] = [$proc, $pipes];
            }
            $lines = [];
            foreach ($procs as [$proc, $pipes]) {
                $out = stream_get_contents($pipes[1]);
                $err = stream_get_contents($pipes[2]);
                fclose($pipes[1]);
                fclose($pipes[2]);
                $this->assertSame(0, proc_close($proc), $err);
                $lines[] = trim($out);
            }
            $this->assertCount(1, array_unique($lines));
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $lines[0]);
            $this->assertSame($lines[0], bin2hex((new ServerKeyFile($this->path))->read()));
        }
    }

    /**
     * print_r of the trace frames inside Vault code (with their arguments). The full trace drags in PHPUnit's and
     * this test's own objects, which hold the fixture paths.
     */
    private static function vaultFrames(\Throwable $e): string
    {
        $frames = array_filter($e->getTrace(), fn (array $f) => str_starts_with($f['class'] ?? '', 'Kanboard\\Plugin\\Vault\\'));
        return print_r(array_values($frames), true);
    }

    // Kills a message (or a trace argument) carrying the path or the key bytes.
    public function testFailureNamesNoPathOrBytes(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');
        try {
            $bytes = random_bytes(32);
            $hex = bin2hex($bytes);
            $cases = [
                'missing' => function () {
                },
                'loose mode' => fn () => $this->writeKey($this->path, $bytes, 0644),
                'hard link' => function () use ($bytes) {
                    $this->writeKey($this->path, $bytes);
                    link($this->path, $this->path.'.2');
                },
                'wrong size' => fn () => $this->writeKey($this->path, substr($bytes, 0, 31)),
                'loose dir' => function () use ($bytes) {
                    $this->writeKey($this->path, $bytes);
                    chmod($this->dir, 0770);
                },
                'symlink' => function () use ($bytes) {
                    $this->writeKey($this->base.'/elsewhere/k', $bytes);
                    mkdir($this->dir, 0700);
                    symlink($this->base.'/elsewhere/k', $this->path);
                },
            ];
            foreach ($cases as $name => $arrange) {
                $this->rmTree($this->base);
                mkdir($this->base, 0700);
                $arrange();
                foreach ([[$this->path, null], [$this->path, posix_geteuid() + 1]] as [$p, $uid]) {
                    $file = new ServerKeyFile($p, $uid);
                    // A missing file is a valid create(); only read() fails for it with the right uid.
                    $methods = $name === 'missing' && $uid === null ? ['read'] : ['read', 'create'];
                    foreach ($methods as $method) {
                        $e = $this->assertUnavailable(fn () => $file->$method());
                        foreach ([$e->getMessage(), (string) $e, self::vaultFrames($e)] as $text) {
                            $this->assertStringNotContainsString($this->base, $text, "$name/$method");
                            $this->assertStringNotContainsString('server.key', $text, "$name/$method");
                            $this->assertStringNotContainsString($hex, $text, "$name/$method");
                            $this->assertStringNotContainsString($bytes, $text, "$name/$method");
                        }
                    }
                }
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous === false ? '1' : $previous);
        }
    }

    // Kills a string-prefix check fooled by data2/.
    public function testIsUnder(): void
    {
        mkdir($this->base.'/data', 0700);
        mkdir($this->base.'/data2', 0700);
        mkdir($this->base.'/other', 0700);

        $this->assertTrue((new ServerKeyFile($this->base.'/data/vault-server/server.key'))->isUnder($this->base.'/data'));
        $this->assertTrue((new ServerKeyFile($this->base.'/data/server.key'))->isUnder($this->base.'/data'));
        $this->assertTrue((new ServerKeyFile($this->base.'/data/server.key'))->isUnder($this->base.'/data/'));
        $this->assertFalse((new ServerKeyFile($this->base.'/other/vault-server/server.key'))->isUnder($this->base.'/data'));
        $this->assertFalse((new ServerKeyFile($this->base.'/data2/vault-server/server.key'))->isUnder($this->base.'/data'));
        $this->assertFalse((new ServerKeyFile($this->base.'/server.key'))->isUnder($this->base.'/data'));
        // `..` is resolved, in the key path and in the dir.
        $this->assertFalse((new ServerKeyFile($this->base.'/data/../other/server.key'))->isUnder($this->base.'/data'));
        $this->assertTrue((new ServerKeyFile($this->base.'/other/../data/x/server.key'))->isUnder($this->base.'/data'));
        $this->assertTrue((new ServerKeyFile($this->base.'/data/server.key'))->isUnder($this->base.'/other/../data'));
        // A symlinked DATA_DIR still matches the real path it names.
        symlink($this->base.'/data', $this->base.'/data-link');
        $this->assertTrue((new ServerKeyFile($this->base.'/data/vault-server/server.key'))->isUnder($this->base.'/data-link'));
    }

    // Minor 9: a DATA_DIR (or key path) that can't be normalised (relative, empty, a NUL) counts as under, so the
    // deployment check shows red rather than failing open. Kills: null treated as "not under".
    public function testIsUnderFailsClosed(): void
    {
        $key = new ServerKeyFile($this->base.'/elsewhere/server.key');
        foreach (['data', '', "/data\0x", './data'] as $dir) {
            $this->assertTrue($key->isUnder($dir), var_export($dir, true));
        }
        $this->assertTrue((new ServerKeyFile('relative/server.key'))->isUnder($this->base.'/data'));
    }

    // Kills a umask(0077) left in place by create(), on success and on failure.
    public function testCreateRestoresTheUmask(): void
    {
        umask(0022);
        (new ServerKeyFile($this->path))->create();
        $this->assertSame(0022, umask());

        umask(0027);
        chmod($this->dir, 0770);
        unlink($this->path);
        $this->assertUnavailable(fn () => (new ServerKeyFile($this->path))->create());
        $this->assertSame(0027, umask());
    }

    // `.` and `..` components are refused, not normalised: `link/..` would name a different directory to the OS
    // (the link's target's parent) than to a lexical resolver.
    public function testDotComponentsFailClosed(): void
    {
        mkdir($this->base.'/a/b', 0700, true);
        mkdir($this->base.'/a/real', 0700);
        symlink($this->base.'/a/real', $this->base.'/a/link');
        $this->writeKey($this->base.'/a/b/server.key', random_bytes(32));
        foreach (['/a/link/../b/server.key', '/a/./b/server.key', '/a/b/../b/server.key'] as $suffix) {
            $file = new ServerKeyFile($this->base.$suffix);
            $this->assertUnavailable(fn () => $file->read());
            $this->assertUnavailable(fn () => $file->create());
            $this->assertSame('unsafe', $file->status(), $suffix);
        }
        $this->assertFalse(file_exists($this->base.'/a/real/server.key'));
    }

    // Kills taking the lock before the directory walk: with the directory unsafe, read() must fail without touching
    // .lock (here held LOCK_EX, so a LOCK_SH would block; a planted FIFO would hang the open the same way).
    public function testReadWalksBeforeTheLock(): void
    {
        (new ServerKeyFile($this->path))->create();
        chmod($this->dir, 0770);
        $held = fopen($this->dir.'/.lock', 'r');
        $this->assertTrue(flock($held, LOCK_EX));
        try {
            $pipes = [];
            $proc = proc_open([PHP_BINARY, __DIR__.'/fixtures/server-key-race.php', $this->path, 'read'],
                [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $deadline = microtime(true) + 10;
            while (proc_get_status($proc)['running'] && microtime(true) < $deadline) {
                usleep(20000);
            }
            $running = proc_get_status($proc)['running'];
            if ($running) {
                proc_terminate($proc, 9);
            }
            $out = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
            $this->assertFalse($running, 'read() blocked on the lock');
            $this->assertSame('server_key_unavailable', trim($out));
        } finally {
            flock($held, LOCK_UN);
            fclose($held);
        }
    }

    public function testConfiguredPathDefaultsUnderDataDir(): void
    {
        if (defined('VAULT_SERVER_KEY_FILE')) {
            $this->assertSame((string) constant('VAULT_SERVER_KEY_FILE'), ServerKeyFile::configuredPath());
        } else {
            $this->assertSame(DATA_DIR.'/vault-server/server.key', ServerKeyFile::configuredPath());
        }
    }
}
