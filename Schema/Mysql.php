<?php
namespace Kanboard\Plugin\Vault\Schema;

const VERSION = 4;

// Binary values are base64 TEXT (entry and group ciphertext LONGTEXT); timestamps are Unix seconds.
// Ownership references to users(id) cascade; provenance columns (created_by, granted_by, audit actor/target) are SET NULL.
// Surrogate ids must never be reused (grants and key rows name objects by type and id): AUTO_INCREMENT
// keeps a persistent InnoDB counter only on MySQL 8.0+ / MariaDB 10.2.4+.
function version_1($pdo)
{
    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_meta (
        id INT NOT NULL PRIMARY KEY CHECK (id = 1),
        schema_note TEXT
    ) ENGINE=InnoDB CHARSET=utf8mb4');
    $pdo->exec("INSERT INTO vault_meta (id, schema_note) SELECT 1, 'Vault schema v1' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM vault_meta WHERE id = 1)");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_principals (
        user_id INT NOT NULL PRIMARY KEY,
        kind VARCHAR(16) NOT NULL CHECK (kind IN ('human', 'agent')),
        public_key TEXT NOT NULL,
        key_gen INT NOT NULL DEFAULT 1,
        state VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'rotating')),
        created_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_rotations (
        user_id INT NOT NULL PRIMARY KEY,
        old_pk TEXT NOT NULL,
        new_pk TEXT NOT NULL,
        bridge_nonce TEXT NOT NULL,
        bridge TEXT NOT NULL,
        phase VARCHAR(16) NOT NULL CHECK (phase IN ('start', 'sweep', 'finish')),
        started_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_wraps (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        method VARCHAR(32) NOT NULL,
        credential_id TEXT,
        kdf_salt TEXT,
        kdf_ops INT,
        kdf_mem BIGINT,
        status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending')),
        key_gen INT NOT NULL,
        nonce TEXT NOT NULL,
        wrapped_sk TEXT NOT NULL,
        crypto_v INT NOT NULL,
        created_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4");

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_webauthn (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        credential_id TEXT NOT NULL,
        cose_public_key TEXT NOT NULL,
        sign_count BIGINT NOT NULL DEFAULT 0,
        prf_salt TEXT NOT NULL,
        label VARCHAR(255) NOT NULL,
        origin VARCHAR(255) NOT NULL,
        rp_id VARCHAR(255) NOT NULL,
        created_at BIGINT NOT NULL,
        last_used_at BIGINT,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_challenges (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        purpose VARCHAR(32) NOT NULL,
        challenge_hash VARCHAR(128) NOT NULL,
        expires_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_groups (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        owner_id INT NOT NULL,
        parent_id INT,
        kind VARCHAR(16) NOT NULL DEFAULT 'normal' CHECK (kind IN ('normal', 'agent_created', 'import')),
        key_epoch INT NOT NULL DEFAULT 1,
        nonce TEXT NOT NULL,
        ciphertext LONGTEXT NOT NULL,
        crypto_v INT NOT NULL,
        position INT NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(parent_id) REFERENCES vault_groups(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4");

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_entries (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        group_id INT NOT NULL,
        owner_id INT NOT NULL,
        created_by INT,
        version INT NOT NULL DEFAULT 1,
        key_epoch INT NOT NULL DEFAULT 1,
        nonce TEXT NOT NULL,
        ciphertext LONGTEXT NOT NULL,
        crypto_v INT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        FOREIGN KEY(group_id) REFERENCES vault_groups(id) ON DELETE CASCADE,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_grants (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        subject_type VARCHAR(16) NOT NULL,
        subject_id INT NOT NULL,
        grantee_id INT NOT NULL,
        permission VARCHAR(16) NOT NULL,
        granted_by INT,
        expires_at BIGINT,
        created_at BIGINT NOT NULL,
        UNIQUE(subject_type, subject_id, grantee_id),
        FOREIGN KEY(grantee_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(granted_by) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_keys (
        object_type VARCHAR(16) NOT NULL,
        object_id INT NOT NULL,
        principal_id INT NOT NULL,
        principal_key_gen INT NOT NULL,
        key_epoch INT NOT NULL,
        sealed_dek TEXT NOT NULL,
        PRIMARY KEY(object_type, object_id, principal_id, principal_key_gen),
        FOREIGN KEY(principal_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_rekey_queue (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        object_type VARCHAR(16) NOT NULL,
        object_id INT NOT NULL,
        expected_key_epoch INT NOT NULL,
        created_at BIGINT NOT NULL,
        UNIQUE(object_type, object_id)
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_sessions (
        sid_hash VARCHAR(128) NOT NULL PRIMARY KEY,
        user_id INT NOT NULL,
        nonce TEXT NOT NULL,
        enc_sk TEXT NOT NULL,
        nonce_next TEXT,
        enc_sk_next TEXT,
        created_at BIGINT NOT NULL,
        last_used_at BIGINT NOT NULL,
        idle_expires_at BIGINT NOT NULL,
        abs_expires_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_share_reservations (
        id_hash VARCHAR(128) NOT NULL PRIMARY KEY,
        creator_id INT NOT NULL,
        sid_hash VARCHAR(128) NOT NULL,
        expires_at BIGINT NOT NULL,
        FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_shares (
        id_hash VARCHAR(128) NOT NULL PRIMARY KEY,
        burn_hash VARCHAR(128) NOT NULL,
        creator_id INT NOT NULL,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        salt TEXT NOT NULL,
        has_passphrase TINYINT NOT NULL DEFAULT 0,
        sealed_label TEXT,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_audit (
        id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
        created_at BIGINT NOT NULL,
        actor_user_id INT,
        actor_kind VARCHAR(16) NOT NULL CHECK (actor_kind IN ('human', 'agent', 'public', 'cli')),
        action VARCHAR(32) NOT NULL,
        object_type VARCHAR(16),
        object_id INT,
        share_hash VARCHAR(128),
        target_user_id INT,
        ip_trunc VARCHAR(64),
        ua_family VARCHAR(64),
        via VARCHAR(8) NOT NULL CHECK (via IN ('ui', 'api', 'cli')),
        count INT,
        FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB CHARSET=utf8mb4");

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_rate (
        bucket VARCHAR(191) NOT NULL PRIMARY KEY,
        tokens DOUBLE NOT NULL,
        updated_at BIGINT NOT NULL
    ) ENGINE=InnoDB CHARSET=utf8mb4');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_agent_settings (
        agent_user_id INT NOT NULL PRIMARY KEY,
        read_cap_per_hour INT NOT NULL,
        FOREIGN KEY(agent_user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB CHARSET=utf8mb4');
}

// Resuming (final review I2): MySQL commits each DDL statement on its own, and Kanboard's SchemaHandler records the
// version only after the last one ran, so a failure in v3 or v4 leaves the earlier versions applied with the version
// unchanged, and the next request runs them again. Every version here is idempotent: each step checks the catalogue
// (add_column, add_constraint, the FK and CHECK lookups) and skips what is already done. A failure is a PDOException,
// the one type SchemaHandler catches (it then rolls back and re-enables FK checks). v3 reads
// information_schema.CHECK_CONSTRAINTS, so the floor is MySQL 8.0.16 / MariaDB 10.3.10 (README).

// R26: a principal outlives its Kanboard user row (see Sqlite.php version_2). vault_principals.user_id loses its
// FK to users; live_user_id references users ON DELETE SET NULL so the purge can find a deleted user's principal;
// grants and key rows cascade off vault_principals. MySQL names FKs itself, so they are looked up by column, and the
// migration fails if one is left (final review I1).
function version_2($pdo)
{
    add_column($pdo, 'vault_meta', 'org_pk', 'TEXT NULL');
    add_column($pdo, 'vault_meta', 'last_purge_at', 'BIGINT NULL');

    drop_user_fk($pdo, 'vault_principals', 'user_id');
    add_column($pdo, 'vault_principals', 'live_user_id', 'INT NULL');
    add_column($pdo, 'vault_principals', 'rotate_requested', 'INT NOT NULL DEFAULT 0');
    add_column($pdo, 'vault_principals', 'notices', 'INT NOT NULL DEFAULT 0');
    // Only rows not yet linked, and only to a user that exists: a re-run never relinks a deleted user's principal.
    $pdo->exec('UPDATE vault_principals SET live_user_id = user_id WHERE live_user_id IS NULL AND user_id IN (SELECT id FROM users)');
    add_constraint($pdo, 'vault_principals', 'vault_principals_live_user_fk', 'FOREIGN KEY(live_user_id) REFERENCES users(id) ON DELETE SET NULL');

    drop_user_fk($pdo, 'vault_grants', 'grantee_id');
    $pdo->exec('DELETE FROM vault_grants WHERE grantee_id NOT IN (SELECT user_id FROM vault_principals)');
    add_constraint($pdo, 'vault_grants', 'vault_grants_grantee_fk', 'FOREIGN KEY(grantee_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE');

    drop_user_fk($pdo, 'vault_keys', 'principal_id');
    $pdo->exec('DELETE FROM vault_keys WHERE principal_id NOT IN (SELECT user_id FROM vault_principals)');
    add_constraint($pdo, 'vault_keys', 'vault_keys_principal_fk', 'FOREIGN KEY(principal_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE');
}

// R39: actor_kind gains 'system'; R32: vault_rotations keeps the sweep cursor (see Sqlite.php version_3).
// MySQL turns a column CHECK into a table constraint it names itself (vault_audit_chk_N), which only DROP CONSTRAINT
// removes. MariaDB keeps it a column-level constraint named after the column, which DROP CONSTRAINT can't remove
// ("Can't DROP CONSTRAINT `actor_kind`", found on a real MariaDB in T24) and which MODIFY drops. The new, named CHECK
// is added first and the old list (found by its clause: human, without system) dropped after, so a run stopped at any
// point leaves at least one actor_kind CHECK in place, and a re-run finishes the job. Neither CHECK there at all is an
// error, rather than leaving the column unchecked.
function version_3($pdo)
{
    $old = function () use ($pdo): array {
        $stmt = $pdo->prepare("SELECT CONSTRAINT_NAME FROM information_schema.CHECK_CONSTRAINTS
            WHERE CONSTRAINT_SCHEMA = DATABASE() AND CHECK_CLAUSE LIKE '%actor_kind%' AND CHECK_CLAUSE LIKE '%human%'
              AND CHECK_CLAUSE NOT LIKE '%system%'");
        $stmt->execute();
        return $stmt->fetchAll(\PDO::FETCH_COLUMN);
    };
    $hasNew = constraint_exists($pdo, 'vault_audit', 'vault_audit_actor_kind_chk');
    if (! $hasNew && $old() === []) {
        throw new \PDOException('Vault schema v3: the actor_kind CHECK on vault_audit was not found');
    }
    add_constraint($pdo, 'vault_audit', 'vault_audit_actor_kind_chk', "CHECK (actor_kind IN ('human', 'agent', 'public', 'cli', 'system'))");
    if ($old() !== []) {
        $pdo->exec('ALTER TABLE vault_audit MODIFY actor_kind VARCHAR(16) NOT NULL');
        foreach ($old() as $name) {
            $pdo->exec('ALTER TABLE vault_audit DROP CONSTRAINT `'.str_replace('`', '', (string) $name).'`');
        }
        if ($old() !== []) {
            throw new \PDOException('Vault schema v3: the old actor_kind CHECK on vault_audit could not be dropped');
        }
    }
    if (! constraint_exists($pdo, 'vault_audit', 'vault_audit_actor_kind_chk')) {
        throw new \PDOException('Vault schema v3: the actor_kind CHECK on vault_audit is missing');
    }

    add_column($pdo, 'vault_rotations', 'sweep_type', 'VARCHAR(16) NULL');
    add_column($pdo, 'vault_rotations', 'sweep_id', 'INT NULL');
}

// T17: a reservation keeps the share expiry it was made with, because that expiry is in the share's AD and finalize
// must store exactly it; vault_shares carries crypto_v = 1 like every encrypted row (its AD binds the same 1).
// A 64 KB payload in base64 is about 87 KB, larger than TEXT's 64 KiB, so the share ciphertext becomes MEDIUMTEXT.
function version_4($pdo)
{
    add_column($pdo, 'vault_share_reservations', 'share_expires_at', 'BIGINT NOT NULL DEFAULT 0');
    add_column($pdo, 'vault_shares', 'crypto_v', 'INT NOT NULL DEFAULT 1');
    $pdo->exec('ALTER TABLE vault_shares MODIFY ciphertext MEDIUMTEXT NOT NULL');
}

function column_exists($pdo, string $table, string $column): bool
{
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND LOWER(TABLE_NAME) = LOWER(?) AND LOWER(COLUMN_NAME) = LOWER(?)');
    $stmt->execute([$table, $column]);
    return (int) $stmt->fetchColumn() > 0;
}

// Adds the column unless it is already there (written for a re-run, so the statement shape matches the old one).
function add_column($pdo, string $table, string $column, string $definition): void
{
    if (! column_exists($pdo, $table, $column)) {
        $pdo->exec('ALTER TABLE '.$table.' ADD COLUMN '.$column.' '.$definition);
    }
}

function constraint_exists($pdo, string $table, string $name): bool
{
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
        WHERE CONSTRAINT_SCHEMA = DATABASE() AND LOWER(TABLE_NAME) = LOWER(?) AND CONSTRAINT_NAME = ?');
    $stmt->execute([$table, $name]);
    return (int) $stmt->fetchColumn() > 0;
}

function add_constraint($pdo, string $table, string $name, string $definition): void
{
    if (! constraint_exists($pdo, $table, $name)) {
        $pdo->exec('ALTER TABLE '.$table.' ADD CONSTRAINT '.$name.' '.$definition);
    }
}

// The names of the FKs from $table.$column to users. Table names compare case-insensitively, so a server with
// lower_case_table_names set either way finds them.
function user_fks($pdo, string $table, string $column): array
{
    $stmt = $pdo->prepare("SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE
        WHERE TABLE_SCHEMA = DATABASE() AND LOWER(TABLE_NAME) = LOWER(?) AND LOWER(COLUMN_NAME) = LOWER(?)
          AND LOWER(REFERENCED_TABLE_NAME) = 'users'");
    $stmt->execute([$table, $column]);
    return $stmt->fetchAll(\PDO::FETCH_COLUMN);
}

function drop_user_fk($pdo, string $table, string $column): void
{
    foreach (user_fks($pdo, $table, $column) as $name) {
        $pdo->exec('ALTER TABLE '.$table.' DROP FOREIGN KEY `'.str_replace('`', '', (string) $name).'`');
    }
    assert_no_user_fk($pdo, $table, $column);
}

function assert_no_user_fk($pdo, string $table, string $column): void
{
    if (user_fks($pdo, $table, $column) !== []) {
        throw new \PDOException('Vault schema v2: '.$table.'.'.$column.' still has a foreign key to users');
    }
}
