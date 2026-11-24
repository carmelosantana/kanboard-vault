<?php
namespace Kanboard\Plugin\Vault\Schema;

const VERSION = 5;

// Binary values are base64 TEXT; timestamps are Unix seconds.
// Ownership references to users(id) cascade; provenance columns (created_by, granted_by, audit actor/target) are SET NULL.
function version_1($pdo)
{
    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_meta (
        id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
        schema_note TEXT
    )');
    $pdo->exec("INSERT INTO vault_meta (id, schema_note) SELECT 1, 'Vault schema v1' WHERE NOT EXISTS (SELECT 1 FROM vault_meta WHERE id = 1)");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_principals (
        user_id INTEGER NOT NULL PRIMARY KEY,
        kind VARCHAR(16) NOT NULL CHECK (kind IN ('human', 'agent')),
        public_key TEXT NOT NULL,
        key_gen INTEGER NOT NULL DEFAULT 1,
        state VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'rotating')),
        created_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_rotations (
        user_id INTEGER NOT NULL PRIMARY KEY,
        old_pk TEXT NOT NULL,
        new_pk TEXT NOT NULL,
        bridge_nonce TEXT NOT NULL,
        bridge TEXT NOT NULL,
        phase VARCHAR(16) NOT NULL CHECK (phase IN ('start', 'sweep', 'finish')),
        started_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_wraps (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        method VARCHAR(32) NOT NULL,
        credential_id TEXT,
        kdf_salt TEXT,
        kdf_ops INTEGER,
        kdf_mem BIGINT,
        status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'pending')),
        key_gen INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        wrapped_sk TEXT NOT NULL,
        crypto_v INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )");

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_webauthn (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
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
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_challenges (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        purpose VARCHAR(32) NOT NULL,
        challenge_hash VARCHAR(128) NOT NULL,
        expires_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_groups (
        id SERIAL PRIMARY KEY,
        owner_id INTEGER NOT NULL,
        parent_id INTEGER,
        kind VARCHAR(16) NOT NULL DEFAULT 'normal' CHECK (kind IN ('normal', 'agent_created', 'import')),
        key_epoch INTEGER NOT NULL DEFAULT 1,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        crypto_v INTEGER NOT NULL,
        position INTEGER NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(parent_id) REFERENCES vault_groups(id) ON DELETE CASCADE
    )");

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_entries (
        id SERIAL PRIMARY KEY,
        group_id INTEGER NOT NULL,
        owner_id INTEGER NOT NULL,
        created_by INTEGER,
        version INTEGER NOT NULL DEFAULT 1,
        key_epoch INTEGER NOT NULL DEFAULT 1,
        nonce TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        crypto_v INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL,
        FOREIGN KEY(group_id) REFERENCES vault_groups(id) ON DELETE CASCADE,
        FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_grants (
        id SERIAL PRIMARY KEY,
        subject_type VARCHAR(16) NOT NULL,
        subject_id INTEGER NOT NULL,
        grantee_id INTEGER NOT NULL,
        permission VARCHAR(16) NOT NULL,
        granted_by INTEGER,
        expires_at BIGINT,
        created_at BIGINT NOT NULL,
        UNIQUE(subject_type, subject_id, grantee_id),
        FOREIGN KEY(grantee_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(granted_by) REFERENCES users(id) ON DELETE SET NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_keys (
        object_type VARCHAR(16) NOT NULL,
        object_id INTEGER NOT NULL,
        principal_id INTEGER NOT NULL,
        principal_key_gen INTEGER NOT NULL,
        key_epoch INTEGER NOT NULL,
        sealed_dek TEXT NOT NULL,
        PRIMARY KEY(object_type, object_id, principal_id, principal_key_gen),
        FOREIGN KEY(principal_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_rekey_queue (
        id SERIAL PRIMARY KEY,
        object_type VARCHAR(16) NOT NULL,
        object_id INTEGER NOT NULL,
        expected_key_epoch INTEGER NOT NULL,
        created_at BIGINT NOT NULL,
        UNIQUE(object_type, object_id)
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_sessions (
        sid_hash VARCHAR(128) NOT NULL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        nonce TEXT NOT NULL,
        enc_sk TEXT NOT NULL,
        nonce_next TEXT,
        enc_sk_next TEXT,
        created_at BIGINT NOT NULL,
        last_used_at BIGINT NOT NULL,
        idle_expires_at BIGINT NOT NULL,
        abs_expires_at BIGINT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_share_reservations (
        id_hash VARCHAR(128) NOT NULL PRIMARY KEY,
        creator_id INTEGER NOT NULL,
        sid_hash VARCHAR(128) NOT NULL,
        expires_at BIGINT NOT NULL,
        FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_shares (
        id_hash VARCHAR(128) NOT NULL PRIMARY KEY,
        burn_hash VARCHAR(128) NOT NULL,
        creator_id INTEGER NOT NULL,
        ciphertext TEXT NOT NULL,
        iv TEXT NOT NULL,
        salt TEXT NOT NULL,
        has_passphrase SMALLINT NOT NULL DEFAULT 0,
        sealed_label TEXT,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
    )');

    $pdo->exec("CREATE TABLE IF NOT EXISTS vault_audit (
        id SERIAL PRIMARY KEY,
        created_at BIGINT NOT NULL,
        actor_user_id INTEGER,
        actor_kind VARCHAR(16) NOT NULL CHECK (actor_kind IN ('human', 'agent', 'public', 'cli')),
        action VARCHAR(32) NOT NULL,
        object_type VARCHAR(16),
        object_id INTEGER,
        share_hash VARCHAR(128),
        target_user_id INTEGER,
        ip_trunc VARCHAR(64),
        ua_family VARCHAR(64),
        via VARCHAR(8) NOT NULL CHECK (via IN ('ui', 'api', 'cli')),
        count INTEGER,
        FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY(target_user_id) REFERENCES users(id) ON DELETE SET NULL
    )");

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_rate (
        bucket VARCHAR(191) NOT NULL PRIMARY KEY,
        tokens DOUBLE PRECISION NOT NULL,
        updated_at BIGINT NOT NULL
    )');

    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_agent_settings (
        agent_user_id INTEGER NOT NULL PRIMARY KEY,
        read_cap_per_hour INTEGER NOT NULL,
        FOREIGN KEY(agent_user_id) REFERENCES users(id) ON DELETE CASCADE
    )');
}

// R26: a principal outlives its Kanboard user row (see Sqlite.php version_2). vault_principals.user_id loses its
// FK to users; live_user_id references users ON DELETE SET NULL so the purge can find a deleted user's principal;
// grants and key rows cascade off vault_principals. The v1 FKs to users are found in the catalogue (pg_constraint),
// whatever their names, dropped by the names found, and the migration fails with a PDOException if one is left
// (final review I1: dropping an assumed name with IF EXISTS left a renamed FK cascading off users).
function version_2($pdo)
{
    $pdo->exec('ALTER TABLE vault_meta ADD COLUMN org_pk TEXT, ADD COLUMN last_purge_at BIGINT');

    drop_user_fk($pdo, 'vault_principals', 'user_id');
    $pdo->exec('ALTER TABLE vault_principals ADD COLUMN live_user_id INTEGER, ADD COLUMN rotate_requested INTEGER NOT NULL DEFAULT 0, ADD COLUMN notices INTEGER NOT NULL DEFAULT 0');
    $pdo->exec('UPDATE vault_principals SET live_user_id = user_id');
    $pdo->exec('ALTER TABLE vault_principals ADD CONSTRAINT vault_principals_live_user_fk FOREIGN KEY(live_user_id) REFERENCES users(id) ON DELETE SET NULL');

    drop_user_fk($pdo, 'vault_grants', 'grantee_id');
    $pdo->exec('DELETE FROM vault_grants WHERE grantee_id NOT IN (SELECT user_id FROM vault_principals)');
    $pdo->exec('ALTER TABLE vault_grants ADD CONSTRAINT vault_grants_grantee_fk FOREIGN KEY(grantee_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE');

    drop_user_fk($pdo, 'vault_keys', 'principal_id');
    $pdo->exec('DELETE FROM vault_keys WHERE principal_id NOT IN (SELECT user_id FROM vault_principals)');
    $pdo->exec('ALTER TABLE vault_keys ADD CONSTRAINT vault_keys_principal_fk FOREIGN KEY(principal_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE');
}

// R39: actor_kind gains 'system'; R32: vault_rotations keeps the sweep cursor (see Sqlite.php version_3). The v1
// column CHECK carries Postgres's default name; no IF EXISTS, so a missing constraint fails the migration loudly.
function version_3($pdo)
{
    $pdo->exec('ALTER TABLE vault_audit DROP CONSTRAINT vault_audit_actor_kind_check');
    $pdo->exec("ALTER TABLE vault_audit ADD CONSTRAINT vault_audit_actor_kind_check CHECK (actor_kind IN ('human', 'agent', 'public', 'cli', 'system'))");

    $pdo->exec('ALTER TABLE vault_rotations ADD COLUMN sweep_type VARCHAR(16), ADD COLUMN sweep_id INTEGER');
}

// T17: a reservation keeps the share expiry it was made with, because that expiry is in the share's AD and finalize
// must store exactly it; vault_shares carries crypto_v = 1 like every encrypted row (its AD binds the same 1).
function version_4($pdo)
{
    $pdo->exec('ALTER TABLE vault_share_reservations ADD COLUMN share_expires_at BIGINT NOT NULL DEFAULT 0');
    $pdo->exec('ALTER TABLE vault_shares ADD COLUMN crypto_v INTEGER NOT NULL DEFAULT 1');
}

// Server reader (P1); see Sqlite.php version_5 for the why. Kind and state lists are v1 column CHECKs with Postgres's
// default names; no IF EXISTS, so a mismatch fails the migration loudly, as in v3. The owner FKs to users are found in
// the catalogue (drop_user_fk) and re-pointed to vault_principals, still cascading.
function version_5($pdo)
{
    $pdo->exec('ALTER TABLE vault_meta ADD COLUMN server_provider VARCHAR(16), ADD COLUMN server_wrap_id INTEGER NOT NULL DEFAULT 0,
        ADD COLUMN server_wrap_nonce TEXT, ADD COLUMN server_wrapped_sk TEXT, ADD COLUMN server_field_mac_sealed TEXT');
    $pdo->exec("ALTER TABLE vault_meta ADD CONSTRAINT vault_meta_server_provider_check CHECK (server_provider IN ('file', 'migrating', 'joist'))");

    $pdo->exec('ALTER TABLE vault_principals DROP CONSTRAINT vault_principals_kind_check');
    $pdo->exec("ALTER TABLE vault_principals ADD CONSTRAINT vault_principals_kind_check CHECK (kind IN ('human', 'agent', 'server', 'host'))");
    $pdo->exec('ALTER TABLE vault_principals DROP CONSTRAINT vault_principals_state_check');
    $pdo->exec("ALTER TABLE vault_principals ADD CONSTRAINT vault_principals_state_check CHECK (state IN ('active', 'rotating', 'orphaned'))");
    $pdo->exec("ALTER TABLE vault_principals ADD CONSTRAINT vault_principals_identity_check CHECK ((kind IN ('server', 'host')) = (user_id < 0 AND live_user_id IS NULL))");

    drop_user_fk($pdo, 'vault_groups', 'owner_id');
    $pdo->exec('ALTER TABLE vault_groups ADD CONSTRAINT vault_groups_owner_fk FOREIGN KEY(owner_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE');
    drop_user_fk($pdo, 'vault_entries', 'owner_id');
    $pdo->exec('ALTER TABLE vault_entries ADD CONSTRAINT vault_entries_owner_fk FOREIGN KEY(owner_id) REFERENCES vault_principals(user_id) ON DELETE CASCADE');

    $pdo->exec('ALTER TABLE vault_grants ADD COLUMN consumers TEXT, ADD COLUMN fields TEXT, ADD COLUMN rate_per_hour INTEGER, ADD COLUMN rate_burst INTEGER');
    $pdo->exec('ALTER TABLE vault_grants ADD CONSTRAINT vault_grants_server_check CHECK ((grantee_id = -1) = (consumers IS NOT NULL AND fields IS NOT NULL AND rate_per_hour IS NOT NULL AND rate_burst IS NOT NULL))');
    $pdo->exec("ALTER TABLE vault_grants ADD CONSTRAINT vault_grants_negative_check CHECK (grantee_id >= 0 OR (subject_type = 'entry' AND permission = 'read' AND expires_at IS NULL))");

    $pdo->exec('ALTER TABLE vault_audit DROP CONSTRAINT vault_audit_actor_kind_check');
    $pdo->exec("ALTER TABLE vault_audit ADD CONSTRAINT vault_audit_actor_kind_check CHECK (actor_kind IN ('human', 'agent', 'public', 'cli', 'system', 'server'))");
    $pdo->exec('ALTER TABLE vault_audit ADD COLUMN consumer VARCHAR(64), ADD COLUMN field_name VARCHAR(128), ADD COLUMN entry_version INTEGER,
        ADD COLUMN job_ref VARCHAR(64), ADD COLUMN correlation_id VARCHAR(64), ADD COLUMN reason VARCHAR(32), ADD COLUMN consumers TEXT,
        ADD COLUMN fields TEXT, ADD COLUMN old_owner_id INTEGER, ADD COLUMN new_owner_id INTEGER, ADD COLUMN key_epoch INTEGER');
    $pdo->exec('CREATE INDEX IF NOT EXISTS vault_audit_object_idx ON vault_audit(object_id)');
}

// The names of the FKs from $table.$column to users, in the current schema.
function user_fks($pdo, string $table, string $column): array
{
    $stmt = $pdo->prepare("SELECT c.conname FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
        WHERE c.contype = 'f' AND n.nspname = current_schema() AND t.relname = ? AND a.attname = ?
          AND c.confrelid = to_regclass('users')::oid");
    $stmt->execute([$table, $column]);
    return $stmt->fetchAll(\PDO::FETCH_COLUMN);
}

function drop_user_fk($pdo, string $table, string $column): void
{
    foreach (user_fks($pdo, $table, $column) as $name) {
        $pdo->exec('ALTER TABLE '.$table.' DROP CONSTRAINT "'.str_replace('"', '""', (string) $name).'"');
    }
    assert_no_user_fk($pdo, $table, $column);
}

// PDOException is the one type Kanboard's SchemaHandler catches (it then rolls back and re-enables FK checks).
function assert_no_user_fk($pdo, string $table, string $column): void
{
    if (user_fks($pdo, $table, $column) !== []) {
        throw new \PDOException('Vault schema: '.$table.'.'.$column.' still has a foreign key to users');
    }
}
