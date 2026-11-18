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
// MySQL/Postgres: a transaction that row-locks the vault_meta singleton FOR UPDATE or FOR SHARE.
// Nesting is tracked per PDO connection, so separate VaultLock instances on one connection share it.
class VaultLock extends Base
{
    public const EXCLUSIVE = 'exclusive';
    public const SHARED = 'shared';

    /** @var WeakMap<PDO, array{mode: string, depth: int}>|null */
    private static ?WeakMap $held = null;

    public function exclusive(callable $fn): mixed
    {
        return $this->run(self::EXCLUSIVE, $fn);
    }

    public function shared(callable $fn): mixed
    {
        return $this->run(self::SHARED, $fn);
    }

    private function run(string $mode, callable $fn): mixed
    {
        $pdo = $this->db->getConnection();
        self::$held ??= new WeakMap();

        if (isset(self::$held[$pdo])) {
            $state = self::$held[$pdo];
            if ($mode === self::EXCLUSIVE && $state['mode'] === self::SHARED) {
                throw new LogicException('Vault lock: cannot take the exclusive lock inside a shared one');
            }
            // Re-use the outer transaction; an exception propagates to the outermost call, which rolls back.
            self::$held[$pdo] = ['mode' => $state['mode'], 'depth' => $state['depth'] + 1];
            try {
                return $fn();
            } finally {
                self::$held[$pdo] = $state;
            }
        }

        $driver = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
        $this->begin($pdo, $driver, $mode);
        self::$held[$pdo] = ['mode' => $mode, 'depth' => 1];
        try {
            $this->lockMetaRow($pdo, $driver, $mode);
            $result = $fn();
        } catch (Throwable $e) {
            unset(self::$held[$pdo]);
            $this->rollback($pdo, $driver);
            throw $e;
        }
        unset(self::$held[$pdo]);
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
        return $result;
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
        $sql = 'SELECT id FROM vault_meta WHERE id = 1 '.($mode === self::EXCLUSIVE ? 'FOR UPDATE' : 'FOR SHARE');
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

    private function exec(PDO $pdo, string $sql): void
    {
        if ($pdo->exec($sql) === false) {
            throw new RuntimeException('Vault lock: '.$sql.' failed');
        }
    }
}
