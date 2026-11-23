<?php
namespace Kanboard\Plugin\Vault\Model;

/**
 * The Server key file: 32 random bytes that only the Kanboard process user can read (spec amendment, Server key file).
 *
 * Stricter than Matinee's KeyStore (SEC-12). KeyStore follows path components, repairs a loose mode with chmod and
 * reads by path; dropping its chmod repair is a follow-up in Matinee. Here every deviation fails closed with
 * ServerKeyUnavailable, whose message is always `server_key_unavailable`:
 *
 * - The path must be absolute with no `.` or `..` component (refused, not normalised), and every component
 *   from `/` down to the file's directory is lstat'ed: a symlink anywhere, or a component that isn't a directory,
 *   fails. The directory must be owned by the expected uid with no group or other write bit (`mode & 0022 === 0`).
 * - read() never creates and never chmods. It lstats the file (a regular file, so a planted FIFO or device is never
 *   opened), opens it once, and checks the open descriptor with fstat: a regular file owned by the expected uid,
 *   mode exactly 0600, nlink 1, size 32. It then re-walks the directories and lstats the path again, which must
 *   report the same dev/ino as the descriptor (a swap or a link fails), and reads the 32 bytes and EOF from that
 *   same descriptor. When `<dir>/.lock` exists it is held LOCK_SH meanwhile (checked the same way as a regular file
 *   owned by the uid, opened read-only so a read never creates anything).
 * - create() runs under umask 0077. It makes only the last directory (0700) when missing, takes LOCK_EX on
 *   `<dir>/.lock` (created with O_EXCL, so a planted link is refused), keeps a valid existing key (an invalid one
 *   throws, never replaced), and otherwise creates the key with fopen 'xb' (O_CREAT|O_EXCL, which also refuses a
 *   planted symlink), fstat-checks it, writes, fflushes and fsyncs it, then fsyncs the directory (best effort: PHP
 *   can open a directory read-only on Linux). On failure it unlinks only the inode it created.
 *
 * Residual races. PHP has no openat() or O_NOFOLLOW, so a path component can't be pinned between the walk and the
 * open. The walk before the open, the fstat of the open descriptor and the second walk plus dev/ino compare after it
 * catch any swap that is still in place when the check runs; a component swapped to a symlink and back again within
 * that window is not caught. The key's directory is writable only by the expected uid, so only that uid (or root)
 * can swap the key or lock file itself; an ancestor directory is a window only if someone else can rename entries
 * in it (not a sticky /tmp, not DATA_DIR on a sane host). umask() is process-wide, which matters only under a
 * threaded (ZTS) SAPI. The dev/ino compare and nlink 1 still refuse what such a race would leave behind in the
 * common cases.
 *
 * Depends only on PHP, posix and ServerKeyUnavailable (the race test's child process requires it directly). Without
 * posix_geteuid every call fails closed.
 */
final class ServerKeyFile
{
    public const KEY_BYTES = 32;

    private const LOCK = '.lock';
    private const S_IFMT = 0170000;
    private const S_IFDIR = 0040000;
    private const S_IFREG = 0100000;

    /** The configured path with repeated slashes dropped, or null when it isn't absolute or has `.` or `..`. */
    private ?string $file;
    private ?int $uid;

    public function __construct(private string $path, ?int $expectedUid = null)
    {
        $this->file = self::strict($path);
        $this->uid = $expectedUid ?? (function_exists('posix_geteuid') ? posix_geteuid() : null);
    }

    /** var_dump and print_r (a trace argument, a closure's $this) never show the path. */
    public function __debugInfo(): array
    {
        return ['path' => '[redacted]'];
    }

    /** VAULT_SERVER_KEY_FILE when defined (a path, not a secret), else DATA_DIR/vault-server/server.key. */
    public static function configuredPath(): string
    {
        return defined('VAULT_SERVER_KEY_FILE') ? (string) constant('VAULT_SERVER_KEY_FILE') : DATA_DIR.'/vault-server/server.key';
    }

    public function path(): string
    {
        return $this->path;
    }

    /** The 32 key bytes. Never creates and never chmods. */
    public function read(): string
    {
        return $this->guard(function () {
            // The walk comes first, as in create(): under an unsafe directory .lock is never opened or locked.
            if ($this->walk(dirname($this->file)) !== 'ok') {
                throw new ServerKeyUnavailable();
            }
            $lock = $this->openLock(false);
            try {
                return $this->readUnlocked();
            } finally {
                $this->closeLock($lock);
            }
        });
    }

    /** Creates the key once. A valid existing key is kept; an invalid one throws and is left as it is. */
    public function create(): void
    {
        $this->guard(function () {
            if ($this->uid !== posix_geteuid()) {
                throw new ServerKeyUnavailable(); // a file we create can't be owned by another uid
            }
            $umask = umask(0077);
            try {
                $this->createUnderUmask();
            } finally {
                umask($umask);
            }
        });
    }

    /** 'ok', 'missing' (nothing at the path, every existing directory sound) or 'unsafe'. No path, no bytes. */
    public function status(): string
    {
        try {
            $key = $this->read();
            sodium_memzero($key);
            return 'ok';
        } catch (ServerKeyUnavailable) {
        }
        if ($this->file === null || $this->uid === null || !function_exists('posix_geteuid')) {
            return 'unsafe';
        }
        $walk = $this->walk(dirname($this->file));
        if ($walk === 'ok') {
            return self::lst($this->file) === false ? 'missing' : 'unsafe';
        }
        return $walk;
    }

    /** Whether the key's resolved directory is $dir or below it (component-wise, so `data2/` isn't under `data`). */
    public function isUnder(string $dir): bool
    {
        $parent = self::resolve(dirname($this->path));
        $root = self::resolve($dir);
        if ($parent === null || $root === null) {
            return false;
        }
        return $parent === $root || str_starts_with($parent, rtrim($root, '/').'/');
    }

    /**
     * Runs $op and turns every failure into a bare ServerKeyUnavailable: nothing is chained, since a PHP error or
     * warning text could name the path.
     *
     * @template T
     * @param callable(): T $op
     * @return T
     */
    private function guard(callable $op): mixed
    {
        if ($this->file === null || $this->uid === null || !function_exists('posix_geteuid')) {
            throw new ServerKeyUnavailable();
        }
        try {
            return $op();
        } catch (\Throwable) {
            throw new ServerKeyUnavailable();
        }
    }

    private function createUnderUmask(): void
    {
        $dir = dirname($this->file);
        $madeDir = false;
        if (self::lst($dir) === false) {
            // Only the last directory is made; its parent chain must already be sound.
            if ($this->walk(dirname($dir), false) !== 'ok') {
                throw new ServerKeyUnavailable();
            }
            $madeDir = @mkdir($dir, 0700); // a sibling may win the race; the walk below decides either way
        }
        if ($this->walk($dir) !== 'ok') {
            throw new ServerKeyUnavailable();
        }
        if ($madeDir) {
            self::fsyncDir(dirname($dir));
        }

        $lock = $this->openLock(true);
        try {
            if (self::lst($this->file) !== false) {
                $key = $this->readUnlocked();
                sodium_memzero($key);
                return;
            }
            $this->createKey($dir);
        } finally {
            $this->closeLock($lock);
        }
    }

    /** Runs under LOCK_EX with nothing at the path, so the inode this call creates is its own to remove. */
    private function createKey(string $dir): void
    {
        $fh = @fopen($this->file, 'xb');
        if ($fh === false) {
            throw new ServerKeyUnavailable();
        }
        $created = fstat($fh);
        $ok = false;
        try {
            if (is_array($created) && $this->soundKeyStat($created, 0) && $this->samePathInode($created)) {
                $key = random_bytes(self::KEY_BYTES);
                $ok = fwrite($fh, $key) === self::KEY_BYTES && fflush($fh) && fsync($fh);
                sodium_memzero($key);
            }
        } finally {
            $ok = fclose($fh) && $ok;
            if (!$ok) {
                if (is_array($created) && $this->samePathInode($created)) {
                    @unlink($this->file);
                }
                throw new ServerKeyUnavailable();
            }
        }
        self::fsyncDir($dir);
    }

    private function readUnlocked(): string
    {
        $dir = dirname($this->file);
        $before = self::lst($this->file);
        if ($this->walk($dir) !== 'ok' || $before === false || !self::isType($before, self::S_IFREG)) {
            throw new ServerKeyUnavailable();
        }
        $fh = @fopen($this->file, 'rb');
        if ($fh === false) {
            throw new ServerKeyUnavailable();
        }
        try {
            $st = fstat($fh);
            if (!is_array($st) || !$this->soundKeyStat($st, self::KEY_BYTES)
                || $st['dev'] !== $before['dev'] || $st['ino'] !== $before['ino']
                || $this->walk($dir) !== 'ok' || !$this->samePathInode($st)) {
                throw new ServerKeyUnavailable();
            }
            $key = stream_get_contents($fh, self::KEY_BYTES + 1);
            if (!is_string($key) || strlen($key) !== self::KEY_BYTES || !feof($fh)) {
                if (is_string($key)) {
                    sodium_memzero($key);
                }
                throw new ServerKeyUnavailable();
            }
            return $key;
        } finally {
            fclose($fh);
        }
    }

    /** A regular file owned by the uid, mode exactly 0600, one link, $size bytes. */
    private function soundKeyStat(array $st, int $size): bool
    {
        return self::isType($st, self::S_IFREG) && $st['uid'] === $this->uid && ($st['mode'] & 07777) === 0600
            && $st['nlink'] === 1 && $st['size'] === $size;
    }

    /** The path, looked up again without following a final link, still names the inode in $st. */
    private function samePathInode(array $st): bool
    {
        $now = self::lst($this->file);
        return $now !== false && $now['dev'] === $st['dev'] && $now['ino'] === $st['ino'];
    }

    /**
     * Opens and locks `<dir>/.lock`: LOCK_EX when $create (made with O_EXCL if absent), LOCK_SH otherwise (none
     * when absent). The lock must be a regular file owned by the uid, and the descriptor must be the path's inode.
     *
     * @return resource|null
     */
    private function openLock(bool $create)
    {
        $path = dirname($this->file).'/'.self::LOCK;
        $fh = false;
        $st = self::lst($path);
        if ($st === false) {
            if (!$create) {
                return null;
            }
            $fh = @fopen($path, 'x'); // O_EXCL: a planted link is refused, not followed
            $st = $fh === false ? self::lst($path) : fstat($fh);
            if ($st === false) {
                throw new ServerKeyUnavailable();
            }
        }
        if (!self::isType($st, self::S_IFREG)) {
            throw new ServerKeyUnavailable();
        }
        if ($fh === false) {
            $fh = @fopen($path, 'r'); // flock needs no write access; 'r' never creates
            if ($fh === false) {
                throw new ServerKeyUnavailable();
            }
        }
        $open = fstat($fh);
        $now = self::lst($path);
        if (!is_array($open) || $now === false || !self::isType($open, self::S_IFREG) || $open['uid'] !== $this->uid
            || $open['dev'] !== $now['dev'] || $open['ino'] !== $now['ino'] || !flock($fh, $create ? LOCK_EX : LOCK_SH)) {
            fclose($fh);
            throw new ServerKeyUnavailable();
        }
        return $fh;
    }

    /** @param resource|null $lock */
    private function closeLock($lock): void
    {
        if ($lock !== null) {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * lstat every component from `/` down to $dir: 'missing' at the first absent one, 'unsafe' at a symlink or
     * a non-directory. With $ownerRules, $dir itself must be owned by the uid with `mode & 0022 === 0`.
     */
    private function walk(string $dir, bool $ownerRules = true): string
    {
        $st = self::lst('/');
        if ($st === false || !self::isType($st, self::S_IFDIR)) {
            return 'unsafe';
        }
        $current = '';
        foreach ($dir === '/' ? [] : explode('/', substr($dir, 1)) as $part) {
            $current .= '/'.$part;
            $st = self::lst($current);
            if ($st === false) {
                return 'missing';
            }
            if (!self::isType($st, self::S_IFDIR)) {
                return 'unsafe';
            }
        }
        if ($ownerRules && ($st['uid'] !== $this->uid || ($st['mode'] & 0022) !== 0)) {
            return 'unsafe';
        }
        return 'ok';
    }

    /** fsync a directory so a new entry in it survives a crash. Best effort: PHP may not open a directory. */
    private static function fsyncDir(string $dir): void
    {
        $fh = @fopen($dir, 'r');
        if ($fh !== false) {
            @fsync($fh);
            fclose($fh);
        }
    }

    /** An uncached lstat (PHP caches the last lstat, and a re-check must see the disk). */
    private static function lst(string $path): array|false
    {
        clearstatcache(true);
        return @lstat($path);
    }

    private static function isType(array $st, int $type): bool
    {
        return ($st['mode'] & self::S_IFMT) === $type;
    }

    /**
     * The path the key file uses: absolute, with no `.` or `..` component (refused, not normalised: `link/..` names
     * a different directory to the OS than to a lexical resolver). Repeated and trailing slashes are dropped.
     */
    private static function strict(string $path): ?string
    {
        if ($path === '' || $path[0] !== '/' || str_contains($path, "\0")) {
            return null;
        }
        $parts = array_values(array_filter(explode('/', $path), fn (string $part) => $part !== ''));
        if ($parts === [] || array_intersect($parts, ['.', '..']) !== []) {
            return null;
        }
        return '/'.implode('/', $parts);
    }

    /** For isUnder() only: absolute path with `.`, `..` and repeated slashes resolved lexically; null when relative or not a file path. */
    private static function normalize(string $path): ?string
    {
        if ($path === '' || $path[0] !== '/' || str_contains($path, "\0")) {
            return null;
        }
        $parts = [];
        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                array_pop($parts);
                continue;
            }
            $parts[] = $part;
        }
        return $parts === [] ? null : '/'.implode('/', $parts);
    }

    /** realpath of the deepest existing ancestor, plus the lexically normalised rest. */
    private static function resolve(string $path): ?string
    {
        if ($path === '/') {
            return '/';
        }
        $current = self::normalize($path);
        if ($current === null) {
            return null;
        }
        clearstatcache(true);
        $rest = '';
        while (($real = realpath($current)) === false) {
            if ($current === '/') {
                return self::normalize($path);
            }
            $rest = '/'.basename($current).$rest;
            $current = dirname($current);
        }
        $resolved = rtrim($real, '/').$rest;
        return $resolved === '' ? '/' : $resolved;
    }
}
