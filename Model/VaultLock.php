<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Core\Base;
use LogicException;
use PDO;
use RuntimeException;
use Throwable;
use WeakMap;

// The install-wide vault lock: one serialisation domain for every authorisation or ciphertext change.
// SQLite: raw BEGIN IMMEDIATE (exclusive) or deferred BEGIN (shared), never PicoDb's beginTransaction().
// MySQL/Postgres: a transaction that row-locks the vault_meta singleton FOR UPDATE, or for sharing
// (FOR SHARE on Postgres, LOCK IN SHARE MODE on MySQL/MariaDB).
// Nesting is tracked per PDO connection, so separate VaultLock instances on one connection share it.
// afterCommit queues work (events, notices) for after the outermost COMMIT; a rollback drops it.
class VaultLock extends Base
{
    public const EXCLUSIVE = 'exclusive';
    public const SHARED = 'shared';

    /** @var WeakMap<PDO, array{mode: string, depth: int, rollbackOnly: bool, after: list<callable>}>|null */
    private static ?WeakMap $held = null;

    public function exclusive(callable $fn): mixed
    {
        return $this->run(self::EXCLUSIVE, $fn);
    }

    public function shared(callable $fn): mixed
    {
        return $this->run(self::SHARED, $fn);
    }

    // Inside a lock: $fn runs once after the outermost COMMIT, in the order queued, and never on a rollback. With no
    // lock held it runs at once. A callback's exception is caught and logged by class only (its message could carry
    // data); the change is already committed and the next callback still runs.
    public function afterCommit(callable $fn): void
    {
        $pdo = $this->db->getConnection();
        if (self::$held !== null && isset(self::$held[$pdo])) {
            $state = self::$held[$pdo];
            $state['after'][] = $fn;
            self::$held[$pdo] = $state;
            return;
        }
        $this->runAfter([$fn]);
    }

    private function run(string $mode, callable $fn): mixed
    {
        $pdo = $this->db->getConnection();
        self::$held ??= new WeakMap();

        if (isset(self::$held[$pdo])) {
            $state = self::$held[$pdo];
            if ($mode === self::EXCLUSIVE && $state['mode'] === self::SHARED) {
                self::markRollbackOnly($pdo);
                throw new LogicException('Vault lock: cannot take the exclusive lock inside a shared one');
            }
            // Re-use the outer transaction. A failure marks it rollback-only, so the outermost call rolls back
            // even when a caller in between catches the exception and carries on.
            self::$held[$pdo] = ['depth' => $state['depth'] + 1] + $state;
            try {
                return $fn();
            } catch (Throwable $e) {
                self::markRollbackOnly($pdo);
                throw $e;
            } finally {
                $now = self::$held[$pdo];
                self::$held[$pdo] = ['depth' => $state['depth'], 'rollbackOnly' => $now['rollbackOnly'], 'after' => $now['after']] + $state;
            }
        }

        $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $this->begin($pdo, $driver, $mode);
        self::$held[$pdo] = ['mode' => $mode, 'depth' => 1, 'rollbackOnly' => false, 'after' => []];
        try {
            $this->lockMetaRow($pdo, $driver, $mode);
            $result = $fn();
        } catch (Throwable $e) {
            unset(self::$held[$pdo]);
            $this->rollback($pdo, $driver);
            throw $e;
        }
        ['rollbackOnly' => $rollbackOnly, 'after' => $after] = self::$held[$pdo];
        unset(self::$held[$pdo]);
        if ($rollbackOnly) {
            // A nested operation failed and its exception was swallowed; its partial writes must not commit.
            $this->rollback($pdo, $driver);
            throw new RuntimeException('Vault lock: a nested operation failed, so the transaction was rollback-only and has been rolled back');
        }
        if (! $pdo->inTransaction()) {
            // Something (e.g. PicoDb's error handler) ended the transaction, so later work ran outside the lock.
            throw new RuntimeException('Vault lock: the transaction was ended inside the lock');
        }
        try {
            $this->commit($pdo, $driver);
        } catch (Throwable $e) {
            // A failed COMMIT (e.g. SQLITE_BUSY) can leave the transaction open; never leave it dangling.
            $this->rollback($pdo, $driver);
            throw $e;
        }
        $this->runAfter($after);
        return $result;
    }

    /** @param list<callable> $callbacks */
    private function runAfter(array $callbacks): void
    {
        foreach ($callbacks as $fn) {
            try {
                $fn();
            } catch (Throwable $e) {
                $this->logger->warning('Vault: an after-commit callback failed ('.get_class($e).')');
            }
        }
    }

    private function begin(PDO $pdo, string $driver, string $mode): void
    {
        switch ($driver) {
            case 'sqlite':
                $this->exec($pdo, $mode === self::EXCLUSIVE ? 'BEGIN IMMEDIATE' : 'BEGIN');
                return;
            case 'mysql':
            case 'pgsql':
                if (! $pdo->beginTransaction()) {
                    throw new RuntimeException('Vault lock: could not begin a transaction');
                }
                return;
        }
        throw new RuntimeException('Vault lock: unsupported database driver');
    }

    private function lockMetaRow(PDO $pdo, string $driver, string $mode): void
    {
        if ($driver === 'sqlite') {
            return;
        }
        // MariaDB has no FOR SHARE; LOCK IN SHARE MODE works on MariaDB and MySQL 8.
        $share = $driver === 'mysql' ? 'LOCK IN SHARE MODE' : 'FOR SHARE';
        $sql = 'SELECT id FROM vault_meta WHERE id = 1 '.($mode === self::EXCLUSIVE ? 'FOR UPDATE' : $share);
        $stmt = $pdo->query($sql);
        // Without the singleton row nothing is locked, so nothing may run.
        if ($stmt === false || (int) $stmt->fetchColumn() !== 1) {
            throw new RuntimeException('Vault lock: the vault_meta lock row is missing');
        }
    }

    private function commit(PDO $pdo, string $driver): void
    {
        if ($driver === 'sqlite') {
            $this->exec($pdo, 'COMMIT');
        } elseif (! $pdo->commit()) {
            throw new RuntimeException('Vault lock: commit failed');
        }
    }

    // Best effort: the original error is what the caller needs to see.
    private function rollback(PDO $pdo, string $driver): void
    {
        try {
            if ($driver === 'sqlite') {
                $pdo->exec('ROLLBACK');
            } else {
                $pdo->rollBack();
            }
        } catch (Throwable $ignored) {
        }
    }

    private static function markRollbackOnly(PDO $pdo): void
    {
        self::$held[$pdo] = ['rollbackOnly' => true] + self::$held[$pdo];
    }

    private function exec(PDO $pdo, string $sql): void
    {
        if ($pdo->exec($sql) === false) {
            throw new RuntimeException('Vault lock: '.$sql.' failed');
        }
    }
}
