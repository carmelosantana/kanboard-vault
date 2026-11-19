<?php
namespace Kanboard\Plugin\Vault\Schema;

const VERSION = 2;

// Binary values are base64 TEXT; timestamps are Unix seconds.
// Ownership references to users(id) cascade; provenance columns (created_by, granted_by, audit actor/target) are SET NULL.
// Surrogate ids are AUTOINCREMENT so a deleted object's id is never reused (grants and key rows name objects by type and id).
function version_1($pdo)
{
    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_meta (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        schema_note TEXT
    )');
    $pdo->exec("INSERT INTO vault_meta (id, schema_note) SELECT 1, 'Vault schema v1' WHERE NOT EXISTS (SELECT 1 FROM vault_meta WHERE id = 1)");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_principals (
        user_id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('human', 'agent')),
        public_key TEXT NOT NULL,
        key_gen INTEGER NOT NULL DEFAULT 1,
        state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'rotating')),
        created_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_rotations (
        user_id INTEGER PRIMARY KEY,
        old_pk TEXT NOT NULL,
        new_pk TEXT NOT NULL,
        bridge_nonce TEXT NOT NULL,
        bridge TEXT NOT NULL,
        phase TEXT NOT NULL CHECK (phase IN ('start', 'sweep', 'finish')),
        started_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_wraps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        method TEXT NOT NULL,
        credential_id TEXT,
        kdf_salt TEXT,
        kdf_ops INTEGER,
        kdf_mem INTEGER,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending')),
        key_gen INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        wrapped_sk TEXT NOT NULL,
        crypto_v INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_webauthn (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        credential_id TEXT NOT NULL,
        cose_public_key TEXT NOT NULL,
        sign_count INTEGER NOT NULL DEFAULT 0,
        prf_salt TEXT NOT NULL,
        label TEXT NOT NULL,
        origin TEXT NOT NULL,
        rp_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        purpose TEXT NOT NULL,
        challenge_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        parent_id INTEGER,
        kind TEXT NOT NULL DEFAULT 'normal' CHECK (kind IN ('normal', 'agent_created', 'import')),
        key_epoch INTEGER NOT NULL DEFAULT 1,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        crypto_v INTEGER NOT NULL,
        position INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(parent_id) REFERENCES vault_groups(id) ON DELETE CASCADE
    )");

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        owner_id INTEGER NOT NULL,
        created_by INTEGER,
        version INTEGER NOT NULL DEFAULT 1,
        key_epoch INTEGER NOT NULL DEFAULT 1,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        crypto_v INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY(group_id) REFERENCES vault_groups(id) ON DELETE CASCADE,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_grants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_type TEXT NOT NULL,
        subject_id INTEGER NOT NULL,
        grantee_id INTEGER NOT NULL,
        permission TEXT NOT NULL,
        granted_by INTEGER,
        expires_at INTEGER,
        created_at INTEGER NOT NULL,
        UNIQUE(subject_type, subject_id, grantee_id),
        FOREIGN KEY(grantee_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(granted_by) REFERENCES users(id) ON DELETE SET NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_keys (
        object_type TEXT NOT NULL,
        object_id INTEGER NOT NULL,
        principal_id INTEGER NOT NULL,
        principal_key_gen INTEGER NOT NULL,
        key_epoch INTEGER NOT NULL,
        sealed_dek TEXT NOT NULL,
        PRIMARY KEY(object_type, object_id, principal_id, principal_key_gen),
        FOREIGN KEY(principal_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_rekey_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        object_type TEXT NOT NULL,
        object_id INTEGER NOT NULL,
        expected_key_epoch INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        UNIQUE(object_type, object_id)
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_sessions (
        sid_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        enc_sk TEXT NOT NULL,
        nonce_next TEXT,
        enc_sk_next TEXT,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER NOT NULL,
        idle_expires_at INTEGER NOT NULL,
        abs_expires_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_share_reservations (
        id_hash TEXT PRIMARY KEY,
        creator_id INTEGER NOT NULL,
        sid_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_shares (
        id_hash TEXT PRIMARY KEY,
        burn_hash TEXT NOT NULL,
        creator_id INTEGER NOT NULL,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        salt TEXT NOT NULL,
        has_passphrase INTEGER NOT NULL DEFAULT 0,
        sealed_label TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        actor_user_id INTEGER,
        actor_kind TEXT NOT NULL CHECK (actor_kind IN ('human', 'agent', 'public', 'cli')),
        action TEXT NOT NULL,
        object_type TEXT,
        object_id INTEGER,
        share_hash TEXT,
        target_user_id INTEGER,
        ip_trunc TEXT,
        ua_family TEXT,
        via TEXT NOT NULL CHECK (via IN ('ui', 'api', 'cli')),
        count INTEGER,
        FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE SET NULL
    )");

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_rate (
        bucket TEXT PRIMARY KEY,
        tokens REAL NOT NULL,
        updated_at INTEGER NOT NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_agent_settings (
        agent_user_id INTEGER PRIMARY KEY,
        read_cap_per_hour INTEGER NOT NULL,
        FOREIGN KEY(agent_user_id) REFERENCES users(id) ON DELETE CASCADE
    )');
}

// R26: a principal outlives its Kanboard user row, so deleting a user can't silently cascade away the grants
// and key rows that the purge must turn into re-keys. vault_principals.user_id loses its FK to users; the new
// live_user_id references users ON DELETE SET NULL, so the purge finds a deleted user's principal even if
// SQLite later hands the same users.id to someone else. Grants and key rows now cascade off vault_principals.
// Also: the org public key and the purge throttle on the vault_meta lock row; per-principal flags for a queued
// rotation (a lowered recovery policy) and one-time notices.
// SQLite can't alter a foreign key, so the three tables are rebuilt, keeping AUTOINCREMENT counters.
function version_2($pdo)
{
    $pdo->exec('ALTER TABLE vault_meta ADD COLUMN org_pk TEXT');
    $pdo->exec('ALTER TABLE vault_meta ADD COLUMN last_purge_at INTEGER');

    $pdo->exec("CREATE TABLE vault_principals_v2 (
        user_id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('human', 'agent')),
        public_key TEXT NOT NULL,
        key_gen INTEGER NOT NULL DEFAULT 1,
        state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'rotating')),
        created_at INTEGER NOT NULL,
        live_user_id INTEGER,
        rotate_requested INTEGER NOT NULL DEFAULT 0,
        notices INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(live_user_id) REFERENCES users(id) ON DELETE SET NULL
    )");
    $pdo->exec('INSERT INTO vault_principals_v2 (user_id, kind, public_key, key_gen, state, created_at, live_user_id)
        SELECT user_id, kind, public_key, key_gen, state, created_at, user_id FROM vault_principals');
    $pdo->exec('DROP TABLE vault_principals');
    $pdo->exec('ALTER TABLE vault_principals_v2 RENAME TO vault_principals');

    rebuild_keeping_sequence($pdo, 'vault_grants', 'CREATE TABLE vault_grants_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_type TEXT NOT NULL,
        subject_id INTEGER NOT NULL,
        grantee_id INTEGER NOT NULL,
        permission TEXT NOT NULL,
        granted_by INTEGER,
        expires_at INTEGER,
        created_at INTEGER NOT NULL,
        UNIQUE(subject_type, subject_id, grantee_id),
        FOREIGN KEY(grantee_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE,
        FOREIGN KEY(granted_by) REFERENCES users(id) ON DELETE SET NULL
    )', 'grantee_id');

    rebuild_keeping_sequence($pdo, 'vault_keys', 'CREATE TABLE vault_keys_v2 (
        object_type TEXT NOT NULL,
        object_id INTEGER NOT NULL,
        principal_id INTEGER NOT NULL,
        principal_key_gen INTEGER NOT NULL,
        key_epoch INTEGER NOT NULL,
        sealed_dek TEXT NOT NULL,
        PRIMARY KEY(object_type, object_id, principal_id, principal_key_gen),
        FOREIGN KEY(principal_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE
    )', 'principal_id');
}

// Copies $table into "<table>_v2" (created by $createSql) for rows whose $principalColumn names a principal,
// swaps it in, and carries the AUTOINCREMENT counter over so ids are never reused.
function rebuild_keeping_sequence($pdo, string $table, string $createSql, string $principalColumn): void
{
    $seq = $pdo->query("SELECT seq FROM sqlite_sequence WHERE name = '".$table."'")->fetchColumn();
    $pdo->exec($createSql);
    $pdo->exec('INSERT INTO '.$table.'_v2 SELECT * FROM '.$table.' WHERE '.$principalColumn.' IN (SELECT user_id FROM vault_principals)');
    $pdo->exec('DROP TABLE '.$table);
    $pdo->exec('ALTER TABLE '.$table.'_v2 RENAME TO '.$table);
    if ($seq !== false && $seq !== null) {
        $stmt = $pdo->prepare('UPDATE sqlite_sequence SET seq = ? WHERE name = ? AND seq < ?');
        $stmt->execute([(int) $seq, $table, (int) $seq]);
        if ($pdo->query("SELECT COUNT(*) FROM sqlite_sequence WHERE name = '".$table."'")->fetchColumn() == 0) {
            $pdo->prepare('INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)')->execute([$table, (int) $seq]);
        }
    }
}
