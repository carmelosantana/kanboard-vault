<?php
namespace Kanboard\Plugin\Vault\Schema;

const VERSION = 5;

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

// R39: actor_kind gains 'system', for an action with no actor in a web request (a share expiry or a rate-limit
// summary written by the opportunistic purge). R32: vault_rotations keeps the sweep cursor, so bounded sweeps
// make progress past objects kept for an integrity fault. SQLite can't alter a CHECK, so vault_audit is rebuilt
// with its rows, ids and AUTOINCREMENT counter.
function version_3($pdo)
{
    $seq = $pdo->query("SELECT seq FROM sqlite_sequence WHERE name = 'vault_audit'")->fetchColumn();
    $pdo->exec("CREATE TABLE vault_audit_v3 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        actor_user_id INTEGER,
        actor_kind TEXT NOT NULL CHECK (actor_kind IN ('human', 'agent', 'public', 'cli', 'system')),
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
    $pdo->exec('INSERT INTO vault_audit_v3 SELECT * FROM vault_audit');
    $pdo->exec('DROP TABLE vault_audit');
    $pdo->exec('ALTER TABLE vault_audit_v3 RENAME TO vault_audit');
    if ($seq !== false && $seq !== null) {
        $pdo->prepare("UPDATE sqlite_sequence SET seq = ? WHERE name = 'vault_audit' AND seq < ?")->execute([(int) $seq, (int) $seq]);
        if ($pdo->query("SELECT COUNT(*) FROM sqlite_sequence WHERE name = 'vault_audit'")->fetchColumn() == 0) {
            $pdo->prepare("INSERT INTO sqlite_sequence (name, seq) VALUES ('vault_audit', ?)")->execute([(int) $seq]);
        }
    }

    $pdo->exec('ALTER TABLE vault_rotations ADD COLUMN sweep_type TEXT');
    $pdo->exec('ALTER TABLE vault_rotations ADD COLUMN sweep_id INTEGER');
}

// T17: a reservation keeps the share expiry it was made with, because that expiry is in the share's AD and finalize
// must store exactly it; vault_shares carries crypto_v = 1 like every encrypted row (its AD binds the same 1).
function version_4($pdo)
{
    $pdo->exec('ALTER TABLE vault_share_reservations ADD COLUMN share_expires_at INTEGER NOT NULL DEFAULT 0');
    $pdo->exec('ALTER TABLE vault_shares ADD COLUMN crypto_v INTEGER NOT NULL DEFAULT 1');
}

// Server reader (P1). Principals gain the kinds 'server' (user_id -1) and 'host' (-2 and below), which are never
// Kanboard users: kind server/host ⇔ user_id < 0 and live_user_id NULL. A principal whose user is gone and whose entry
// keeps a live Server grant stays as a tombstone, state 'orphaned'. Groups and entries now cascade off their owner
// principal, not the users row (the v2/R26 pattern grants and key rows already follow), so the purge decides what a
// deleted owner's objects become; owner_id keeps its value, so the AD that binds it still opens. Server grants carry
// consumers, fields and a rate, and only Server holds them (entry-only, read, no expiry). The audit gains actor kind
// 'server' and the Server/orphan columns; the vault_meta lock row holds the Server wrap and the sealed field-MAC key.
//
// The trap: Kanboard's SchemaHandler runs this inside its transaction, where its PRAGMA foreign_keys = OFF is a no-op,
// so FKs stay on. DROP TABLE on a parent runs an implicit DELETE, which cascades into its children. So the new tables
// are built beside the old ones (each referencing the new parents), filled parents first, and the old ones dropped
// children first. An object whose owner isn't a principal fails its copy (FKs on) and with it the migration, loudly;
// nothing is deleted silently. RENAME (SQLite >= 3.26) rewrites the other tables' REFERENCES to the final names.
function version_5($pdo)
{
    $pdo->exec("ALTER TABLE vault_meta ADD COLUMN server_provider TEXT CHECK (server_provider IN ('file', 'migrating', 'joist'))");
    $pdo->exec('ALTER TABLE vault_meta ADD COLUMN server_wrap_id INTEGER NOT NULL DEFAULT 0');
    $pdo->exec('ALTER TABLE vault_meta ADD COLUMN server_wrap_nonce TEXT');
    $pdo->exec('ALTER TABLE vault_meta ADD COLUMN server_wrapped_sk TEXT');
    $pdo->exec('ALTER TABLE vault_meta ADD COLUMN server_field_mac_sealed TEXT');

    $seq = [];
    foreach (['vault_grants', 'vault_groups', 'vault_entries', 'vault_audit'] as $table) {
        $seq[$table] = $pdo->query("SELECT seq FROM sqlite_sequence WHERE name = '".$table."'")->fetchColumn();
    }

    $pdo->exec("CREATE TABLE vault_principals_v5 (
        user_id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('human', 'agent', 'server', 'host')),
        public_key TEXT NOT NULL,
        key_gen INTEGER NOT NULL DEFAULT 1,
        state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'rotating', 'orphaned')),
        created_at INTEGER NOT NULL,
        live_user_id INTEGER,
        rotate_requested INTEGER NOT NULL DEFAULT 0,
        notices INTEGER NOT NULL DEFAULT 0,
        CHECK ((kind IN ('server', 'host')) = (user_id < 0 AND live_user_id IS NULL)),
        FOREIGN KEY(live_user_id) REFERENCES users(id) ON DELETE SET NULL
    )");
    $pdo->exec("CREATE TABLE vault_groups_v5 (
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
        FOREIGN KEY(owner_id) REFERENCES vault_principals_v5(user_id) ON DELETE CASCADE,
        FOREIGN KEY(parent_id) REFERENCES vault_groups_v5(id) ON DELETE CASCADE
    )");
    $pdo->exec('CREATE TABLE vault_entries_v5 (
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
        FOREIGN KEY(group_id) REFERENCES vault_groups_v5(id) ON DELETE CASCADE,
        FOREIGN KEY(owner_id) REFERENCES vault_principals_v5(user_id) ON DELETE CASCADE,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    )');
    $pdo->exec("CREATE TABLE vault_grants_v5 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_type TEXT NOT NULL,
        subject_id INTEGER NOT NULL,
        grantee_id INTEGER NOT NULL,
        permission TEXT NOT NULL,
        granted_by INTEGER,
        expires_at INTEGER,
        created_at INTEGER NOT NULL,
        consumers TEXT,
        fields TEXT,
        rate_per_hour INTEGER,
        rate_burst INTEGER,
        UNIQUE(subject_type, subject_id, grantee_id),
        CHECK ((grantee_id = -1) = (consumers IS NOT NULL AND fields IS NOT NULL AND rate_per_hour IS NOT NULL AND rate_burst IS NOT NULL)),
        CHECK (grantee_id >= 0 OR (subject_type = 'entry' AND permission = 'read' AND expires_at IS NULL)),
        FOREIGN KEY(grantee_id) REFERENCES vault_principals_v5(user_id) ON DELETE CASCADE,
        FOREIGN KEY(granted_by) REFERENCES users(id) ON DELETE SET NULL
    )");
    $pdo->exec('CREATE TABLE vault_keys_v5 (
        object_type TEXT NOT NULL,
        object_id INTEGER NOT NULL,
        principal_id INTEGER NOT NULL,
        principal_key_gen INTEGER NOT NULL,
        key_epoch INTEGER NOT NULL,
        sealed_dek TEXT NOT NULL,
        PRIMARY KEY(object_type, object_id, principal_id, principal_key_gen),
        FOREIGN KEY(principal_id) REFERENCES vault_principals_v5(user_id) ON DELETE CASCADE
    )');

    $copy = [
        'vault_principals' => 'user_id, kind, public_key, key_gen, state, created_at, live_user_id, rotate_requested, notices',
        'vault_groups' => 'id, owner_id, parent_id, kind, key_epoch, nonce, ciphertext, crypto_v, position, created_at, updated_at',
        'vault_entries' => 'id, group_id, owner_id, created_by, version, key_epoch, nonce, ciphertext, crypto_v, created_at, updated_at',
        'vault_grants' => 'id, subject_type, subject_id, grantee_id, permission, granted_by, expires_at, created_at',
        'vault_keys' => 'object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek',
    ];
    foreach ($copy as $table => $columns) { // parents first
        $pdo->exec('INSERT INTO '.$table.'_v5 ('.$columns.') SELECT '.$columns.' FROM '.$table);
    }
    foreach (array_reverse(array_keys($copy)) as $table) { // children first: a parent's DROP would cascade
        $pdo->exec('DROP TABLE '.$table);
    }
    foreach (array_keys($copy) as $table) {
        $pdo->exec('ALTER TABLE '.$table.'_v5 RENAME TO '.$table);
    }

    // Nothing references vault_audit, so it is rebuilt on its own, like version_3.
    $pdo->exec("CREATE TABLE vault_audit_v5 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        actor_user_id INTEGER,
        actor_kind TEXT NOT NULL CHECK (actor_kind IN ('human', 'agent', 'public', 'cli', 'system', 'server')),
        action TEXT NOT NULL,
        object_type TEXT,
        object_id INTEGER,
        share_hash TEXT,
        target_user_id INTEGER,
        ip_trunc TEXT,
        ua_family TEXT,
        via TEXT NOT NULL CHECK (via IN ('ui', 'api', 'cli')),
        count INTEGER,
        consumer TEXT,
        field_name TEXT,
        entry_version INTEGER,
        job_ref TEXT,
        correlation_id TEXT,
        reason TEXT,
        consumers TEXT,
        fields TEXT,
        old_owner_id INTEGER,
        new_owner_id INTEGER,
        key_epoch INTEGER,
        FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE SET NULL
    )");
    $columns = 'id, created_at, actor_user_id, actor_kind, action, object_type, object_id, share_hash, target_user_id, ip_trunc, ua_family, via, count';
    $pdo->exec('INSERT INTO vault_audit_v5 ('.$columns.') SELECT '.$columns.' FROM vault_audit');
    $pdo->exec('DROP TABLE vault_audit');
    $pdo->exec('ALTER TABLE vault_audit_v5 RENAME TO vault_audit');

    foreach ($seq as $table => $value) {
        restore_sequence($pdo, $table, $value);
    }
    $pdo->exec('CREATE INDEX IF NOT EXISTS vault_audit_object_idx ON vault_audit(object_id)');
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
    restore_sequence($pdo, $table, $seq);
}

// Raises $table's AUTOINCREMENT counter back to $seq (as read from sqlite_sequence before a rebuild; false or null
// when the table never had a row), inserting the counter row if the rebuilt table has none yet.
function restore_sequence($pdo, string $table, $seq): void
{
    if ($seq === false || $seq === null) {
        return;
    }
    $pdo->prepare('UPDATE sqlite_sequence SET seq = ? WHERE name = ? AND seq < ?')->execute([(int) $seq, $table, (int) $seq]);
    $count = $pdo->prepare('SELECT COUNT(*) FROM sqlite_sequence WHERE name = ?');
    $count->execute([$table]);
    if ((int) $count->fetchColumn() === 0) {
        $pdo->prepare('INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)')->execute([$table, (int) $seq]);
    }
}
