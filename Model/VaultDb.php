<?php
namespace Kanboard\Plugin\Vault\Model;

use InvalidArgumentException;
use Kanboard\Core\Base;
use PDO;
use PDOStatement;

// Raw-PDO statements for model code inside the vault lock. PicoDb's statement handler rolls back the
// connection's transaction on any SQL error and hides a duplicate key as `false`, which would let work
// carry on outside the lock. Here every error throws a PDOException and PicoDb is never involved.
// The connection's error mode is forced to ERRMODE_EXCEPTION for each call and restored afterwards.
class VaultDb extends Base
{
    private const IDENTIFIER = '/^[a-z_][a-z0-9_]*$/D';

    // Rows affected.
    public function execute(string $sql, array $params = []): int
    {
        return $this->run($sql, $params, static fn (PDOStatement $s): int => $s->rowCount());
    }

    // The new row's id, or 0 when $idColumn is null (tables keyed by something else).
    public function insert(string $table, array $row, ?string $idColumn = 'id'): int
    {
        $this->checkIdentifier($table);
        if ($row === []) {
            throw new InvalidArgumentException('VaultDb: empty row');
        }
        foreach (array_keys($row) as $column) {
            $this->checkIdentifier((string) $column);
        }
        if ($idColumn !== null) {
            $this->checkIdentifier($idColumn);
        }
        $sql = 'INSERT INTO '.$table.' ('.implode(', ', array_keys($row)).') VALUES ('.implode(', ', array_fill(0, count($row), '?')).')';
        $pdo = $this->pdo();
        $returning = $idColumn !== null && $pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql';
        if ($returning) {
            $sql .= ' RETURNING '.$idColumn;
        }
        return $this->run($sql, array_values($row), static function (PDOStatement $s) use ($pdo, $idColumn, $returning): int {
            if ($idColumn === null) {
                return 0;
            }
            return (int) ($returning ? $s->fetchColumn() : $pdo->lastInsertId());
        });
    }

    public function fetchOne(string $sql, array $params = []): ?array
    {
        return $this->run($sql, $params, static function (PDOStatement $s): ?array {
            $row = $s->fetch(PDO::FETCH_ASSOC);
            return $row === false ? null : $row;
        });
    }

    public function fetchAll(string $sql, array $params = []): array
    {
        return $this->run($sql, $params, static fn (PDOStatement $s): array => $s->fetchAll(PDO::FETCH_ASSOC));
    }

    private function pdo(): PDO
    {
        return $this->db->getConnection();
    }

    private function checkIdentifier(string $name): void
    {
        if (! preg_match(self::IDENTIFIER, $name)) {
            throw new InvalidArgumentException('VaultDb: invalid identifier');
        }
    }

    private function run(string $sql, array $params, callable $read): mixed
    {
        $pdo = $this->pdo();
        $mode = $pdo->getAttribute(PDO::ATTR_ERRMODE);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        try {
            $stmt = $pdo->prepare($sql);
            $stmt->execute($params);
            try {
                return $read($stmt);
            } finally {
                $stmt->closeCursor();
            }
        } finally {
            $pdo->setAttribute(PDO::ATTR_ERRMODE, $mode);
        }
    }
}
