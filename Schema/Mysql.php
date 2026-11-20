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

// R26: a principal outlives its Kanboard user row (see Sqlite.php version_2). vault_principals.user_id loses its
// FK to users; live_user_id references users ON DELETE SET NULL so the purge can find a deleted user's principal;
// grants and key rows cascade off vault_principals. MySQL names FKs itself, so they are looked up by column.
function version_2($pdo)
{
    $pdo->exec('ALTER TABLE vault_meta ADD COLUMN org_pk TEXT NULL, ADD COLUMN last_purge_at BIGINT NULL');

    drop_user_fk($pdo, 'vault_principals', 'user_id');
    $pdo->exec('ALTER TABLE vault_principals ADD COLUMN live_user_id INT NULL, ADD COLUMN rotate_requested INT NOT NULL DEFAULT 0, ADD COLUMN notices INT NOT NULL DEFAULT 0');
    $pdo->exec('UPDATE vault_principals SET live_user_id = user_id');
    $pdo->exec('ALTER TABLE vault_principals ADD CONSTRAINT vault_principals_live_user_fk FOREIGN KEY(live_user_id) REFERENCES users(id) ON DELETE SET NULL');

    drop_user_fk($pdo, 'vault_grants', 'grantee_id');
    $pdo->exec('DELETE FROM vault_grants WHERE grantee_id NOT IN (SELECT user_id FROM vault_principals)');
    $pdo->exec('ALTER TABLE vault_grants ADD CONSTRAINT vault_grants_grantee_fk FOREIGN KEY(grantee_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE');

    drop_user_fk($pdo, 'vault_keys', 'principal_id');
    $pdo->exec('DELETE FROM vault_keys WHERE principal_id NOT IN (SELECT user_id FROM vault_principals)');
    $pdo->exec('ALTER TABLE vault_keys ADD CONSTRAINT vault_keys_principal_fk FOREIGN KEY(principal_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE');
}

// R39: actor_kind gains 'system'; R32: vault_rotations keeps the sweep cursor (see Sqlite.php version_3).
// MySQL turns a column CHECK into a table constraint it names itself (vault_audit_chk_N), which only DROP CONSTRAINT
// removes. MariaDB keeps it a column-level constraint named after the column, which DROP CONSTRAINT can't remove
// ("Can't DROP CONSTRAINT `actor_kind`", found on a real MariaDB in T24) and which MODIFY drops. So: the CHECK on
// actor_kind is found by its clause (it throws if there is none, rather than leaving the old list or no list in
// place), MODIFY drops MariaDB's, every one still there afterwards (MySQL's) is dropped by name, and none may remain.
function version_3($pdo)
{
    $find = function () use ($pdo): array {
        $stmt = $pdo->prepare("SELECT CONSTRAINT_NAME FROM information_schema.CHECK_CONSTRAINTS
            WHERE CONSTRAINT_SCHEMA = DATABASE() AND CHECK_CLAUSE LIKE '%actor_kind%' AND CHECK_CLAUSE LIKE '%human%'");
        $stmt->execute();
        return $stmt->fetchAll(\PDO::FETCH_COLUMN);
    };
    if ($find() === []) {
        throw new \RuntimeException('Vault schema v3: the actor_kind CHECK on vault_audit was not found');
    }
    $pdo->exec('ALTER TABLE vault_audit MODIFY actor_kind VARCHAR(16) NOT NULL');
    foreach ($find() as $name) {
        $pdo->exec('ALTER TABLE vault_audit DROP CONSTRAINT `'.str_replace('`', '', (string) $name).'`');
    }
    if ($find() !== []) {
        throw new \RuntimeException('Vault schema v3: the old actor_kind CHECK on vault_audit could not be dropped');
    }
    $pdo->exec("ALTER TABLE vault_audit ADD CONSTRAINT vault_audit_actor_kind_chk CHECK (actor_kind IN ('human', 'agent', 'public', 'cli', 'system'))");

    $pdo->exec('ALTER TABLE vault_rotations ADD COLUMN sweep_type VARCHAR(16) NULL, ADD COLUMN sweep_id INT NULL');
}

// T17: a reservation keeps the share expiry it was made with, because that expiry is in the share's AD and finalize
// must store exactly it; vault_shares carries crypto_v = 1 like every encrypted row (its AD binds the same 1).
// A 64 KB payload in base64 is about 87 KB, larger than TEXT's 64 KiB, so the share ciphertext becomes MEDIUMTEXT.
function version_4($pdo)
{
    $pdo->exec('ALTER TABLE vault_share_reservations ADD COLUMN share_expires_at BIGINT NOT NULL DEFAULT 0');
    $pdo->exec('ALTER TABLE vault_shares ADD COLUMN crypto_v INT NOT NULL DEFAULT 1');
    $pdo->exec('ALTER TABLE vault_shares MODIFY ciphertext MEDIUMTEXT NOT NULL');
}

function drop_user_fk($pdo, string $table, string $column): void
{
    $stmt = $pdo->prepare("SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? AND REFERENCED_TABLE_NAME = 'users'");
    $stmt->execute([$table, $column]);
    foreach ($stmt->fetchAll(\PDO::FETCH_COLUMN) as $name) {
        $pdo->exec('ALTER TABLE '.$table.' DROP FOREIGN KEY `'.str_replace('`', '', (string) $name).'`');
    }
}
