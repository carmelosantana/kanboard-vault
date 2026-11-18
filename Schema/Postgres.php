<?php
namespace Kanboard\Plugin\Vault\Schema;

const VERSION = 1;

// Binary values are base64 TEXT; timestamps are Unix seconds.
// Ownership references to users(id) cascade; provenance columns (created_by, granted_by, audit actor/target) are SET NULL.
function version_1($pdo)
{
    $pdo->exec('CREATE TABLE IF NOT EXISTS vault_meta (
        id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
        schema_note TEXT
    )');
    $pdo->exec("INSERT INTO vault_meta (id, schema_note) VALUES (1, 'Vault schema v1')");

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
