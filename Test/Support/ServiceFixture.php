<?php

use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultSettings;

require_once __DIR__.'/VaultFixture.php';

// The services wired together as a request would use them, with a fast Argon2 stand-in, for the audit, notifier
// and log hygiene tests. Every service gets the test clock; the audit log and notifier come from the container
// (vaultAudit / vaultNotifier when a test sets them, the real ones otherwise).
trait ServiceFixture
{
    use VaultFixture;

    protected const IP = '203.0.113.7';
    protected const ADMIN = 1;

    // A fast stand-in for Argon2id (keyed BLAKE2b of the secret by the salt); KEKs, wraps and AD are all real.
    protected function argon(): callable
    {
        return function (string $secret, string $salt, int $ops, int $mem): string {
            $this->argonCalls++;
            if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
                throw new CryptoException('kdf: bad salt length');
            }
            return sodium_crypto_generichash($secret, $salt, 32);
        };
    }

    protected function clock(): callable
    {
        return fn (): int => $this->now;
    }

    protected function rotation(): RotationService
    {
        return new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session());
    }

    protected function recovery(): RecoveryService
    {
        return new RecoveryService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->rotation());
    }

    protected function settings(): VaultSettings
    {
        return new VaultSettings($this->container, null, $this->clock());
    }

    protected function unlockService(): UnlockService
    {
        return new UnlockService($this->container, $this->slots(), $this->argon(), $this->session(), $this->limiter(), $this->clock(), $this->rotation(), $this->recovery());
    }

    protected function store(): ObjectStore
    {
        return new ObjectStore($this->container, $this->clock());
    }

    protected function grants(): GrantModel
    {
        return new GrantModel($this->container, $this->clock());
    }

    // The principal's sk, opened from its active passphrase wrap at its current key_gen.
    protected function skFor(int $userId, string $passphrase): string
    {
        $p = $this->row('SELECT * FROM vault_principals WHERE user_id = ?', [$userId]);
        $w = $this->row("SELECT * FROM vault_wraps WHERE user_id = ? AND method = 'passphrase' AND status = 'active' AND key_gen = ?", [$userId, $p['key_gen']]);
        $this->assertNotNull($w, 'an active passphrase wrap');
        $kek = Kdf::kek(($this->argon())($passphrase, base64_decode($w['kdf_salt']), (int) $w['kdf_ops'], (int) $w['kdf_mem']), 'passphrase');
        return Wraps::unwrap($w, $kek, base64_decode($p['public_key']));
    }

    // Unlocks in a fresh PHP session and returns the session's sk.
    protected function unlockAs(int $userId, string $passphrase, string $sid, string $ip = self::IP): string
    {
        $this->sid = $sid;
        $this->loginAs($userId);
        $this->https();
        $this->unlockService()->unlock($userId, $passphrase, $ip);
        $this->sendCookieBack();
        $sk = $this->session()->secretKey();
        $this->assertNotNull($sk);
        return $sk;
    }

    // A hardware key as T20 will leave it: a vault_webauthn row and a passphrase+prf wrap of the current sk.
    protected function addHardwareKey(int $userId, string $sk): void
    {
        $p = $this->row('SELECT * FROM vault_principals WHERE user_id = ?', [$userId]);
        $this->pdo()->prepare("INSERT INTO vault_webauthn (user_id, credential_id, cose_public_key, sign_count, prf_salt, label, origin, rp_id, created_at) VALUES (?, 'Y3JlZDE', 'Y29zZQ==', 0, 'cHJm', 'YubiKey', 'https://kb.example', 'kb.example', ?)")
            ->execute([$userId, $this->now]);
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $this->pdo()->prepare("INSERT INTO vault_wraps (user_id, method, credential_id, kdf_salt, kdf_ops, kdf_mem, status, key_gen, nonce, wrapped_sk, crypto_v, created_at) VALUES (?, 'passphrase+prf', 'Y3JlZDE', ?, 3, 67108864, 'active', ?, '', '', 1, ?)")
            ->execute([$userId, base64_encode($salt), (int) $p['key_gen'], $this->now]);
        $id = (int) $this->pdo()->lastInsertId();
        $w = Wraps::wrap($sk, random_bytes(32), $userId, 'passphrase+prf', 'Y3JlZDE', $id);
        $this->pdo()->prepare('UPDATE vault_wraps SET nonce = ?, wrapped_sk = ? WHERE id = ?')->execute([$w['nonce'], $w['wrapped_sk'], $id]);
    }

    // The Agents roster table as Agents' schema version 1 creates it (Vault's own CI has no Agents checkout).
    protected function agentsTable(): void
    {
        $this->pdo()->exec('CREATE TABLE IF NOT EXISTS agents (
            "id" INTEGER PRIMARY KEY,
            "owner_user_id" INTEGER NOT NULL,
            "agent_user_id" INTEGER NOT NULL,
            "kind" TEXT NOT NULL,
            "created_at" INTEGER NOT NULL DEFAULT 0
        )');
    }

    protected function adoptAgent(int $ownerId, int $agentId): void
    {
        $this->pdo()->prepare("INSERT INTO agents (owner_user_id, agent_user_id, kind, created_at) VALUES (?, ?, 'claude', ?)")
            ->execute([$ownerId, $agentId, $this->now]);
    }

    /** @return list<array<string,mixed>> every audit row, oldest first */
    protected function auditRows(?string $action = null): array
    {
        $sql = 'SELECT * FROM vault_audit'.($action === null ? '' : ' WHERE action = ?').' ORDER BY id';
        $s = $this->pdo()->prepare($sql);
        $s->execute($action === null ? [] : [$action]);
        return $s->fetchAll(\PDO::FETCH_ASSOC);
    }

    /** @return list<string> */
    protected function auditActions(): array
    {
        return array_column($this->auditRows(), 'action');
    }
}
