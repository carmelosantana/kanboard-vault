<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\Sealer;

// The Server principal (spec amendment: Principals): kind server, reserved id -1, live_user_id NULL, never a Kanboard
// user, never an owner. Its sk is wrapped on the vault_meta lock row under the key file (FileKeyProvider); R1's
// field-MAC key is sealed to its public key beside the wrap.
//
//   enable   the key file is created and read first, outside the vault lock (R18 spirit: no file I/O under the global
//            lock). Then, in one exclusive transaction: a new keypair, the principal, the next Server wrap, a new
//            field-MAC key and one policy_change row. A no-op when Server is already on.
//   disable  in one exclusive transaction: every Server grant through GrantModel::removeSource (its key row goes and
//            the entry is queued for re-key), any -1 key row left, the wrap and field-MAC key (server_wrap_id is kept,
//            so a wrap id is never reused), the principal and the srvread:* rate buckets. One policy_change row when
//            it was on. The key file stays (it is never replaced or deleted by Vault).
class ServerPrincipal extends Base
{
    public const ID = -1;

    private ServerKeyFile $file;
    private ?FileKeyProvider $provider;
    private Closure $clock;

    public function __construct($container, ?ServerKeyFile $file = null, ?FileKeyProvider $provider = null, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->file = $file ?? (isset($container['vaultServerKeyFile']) ? $container['vaultServerKeyFile'] : new ServerKeyFile(ServerKeyFile::configuredPath()));
        $this->provider = $provider;
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    public static function of($container): self
    {
        return isset($container['vaultServerPrincipal']) ? $container['vaultServerPrincipal'] : new self($container);
    }

    public function isOn(): bool
    {
        return $this->isOnIn(new VaultDb($this->container));
    }

    /** The Server public key, raw 32 bytes; null when Server is off. */
    public function publicKey(): ?string
    {
        $row = (new VaultDb($this->container))->fetchOne("SELECT public_key FROM vault_principals WHERE user_id = ? AND kind = 'server'", [self::ID]);
        $pk = $row === null ? false : base64_decode((string) $row['public_key'], true);
        return $pk === false ? null : $pk;
    }

    public function enable(int $adminId): void
    {
        $this->file->create();
        $provider = $this->provider();
        $provider->warm();
        (new VaultLock($this->container))->exclusive(function () use ($adminId, $provider): void {
            $db = new VaultDb($this->container);
            if ($this->isOnIn($db)) {
                return;
            }
            $keypair = sodium_crypto_box_keypair();
            $sk = sodium_crypto_box_secretkey($keypair);
            $pk = sodium_crypto_box_publickey($keypair);
            $macKey = random_bytes(Sealer::FIELD_MAC_KEY_BYTES);
            try {
                PrincipalModel::assertIdentity('server', self::ID, null);
                $db->insert('vault_principals', [
                    'user_id' => self::ID,
                    'kind' => 'server',
                    'public_key' => base64_encode($pk),
                    'key_gen' => 1,
                    'state' => 'active',
                    'created_at' => (int) ($this->clock)(),
                    'live_user_id' => null,
                ], null);
                $provider->wrapNew($db, $sk);
                $db->execute('UPDATE vault_meta SET server_field_mac_sealed = ? WHERE id = 1', [base64_encode(Sealer::sealFieldMacKey($macKey, self::ID, $pk))]);
                AuditModel::of($this->container, $this->clock)->record('policy_change', ['actor_user_id' => $adminId]);
            } finally {
                sodium_memzero($keypair);
                sodium_memzero($sk);
                sodium_memzero($macKey);
            }
        });
    }

    public function disable(int $adminId): void
    {
        (new VaultLock($this->container))->exclusive(function () use ($adminId): void {
            $db = new VaultDb($this->container);
            $wasOn = $this->isOnIn($db);
            $grants = new GrantModel($this->container, $this->clock);
            foreach ($db->fetchAll('SELECT id FROM vault_grants WHERE grantee_id = ? ORDER BY id', [self::ID]) as $g) {
                $grants->removeSource((int) $g['id'], $adminId);
            }
            $db->execute('DELETE FROM vault_keys WHERE principal_id = ?', [self::ID]);
            $db->execute('UPDATE vault_meta SET server_provider = NULL, server_wrap_nonce = NULL, server_wrapped_sk = NULL, server_field_mac_sealed = NULL WHERE id = 1');
            $db->execute("DELETE FROM vault_principals WHERE user_id = ? AND kind = 'server'", [self::ID]);
            $db->execute("DELETE FROM vault_rate WHERE bucket LIKE 'srvread:%'");
            if ($wasOn) {
                AuditModel::of($this->container, $this->clock)->record('policy_change', ['actor_user_id' => $adminId]);
            }
        });
    }

    private function isOnIn(VaultDb $db): bool
    {
        return $db->fetchOne("SELECT user_id FROM vault_principals WHERE user_id = ? AND kind = 'server'", [self::ID]) !== null;
    }

    private function provider(): FileKeyProvider
    {
        if ($this->provider === null) {
            $configured = isset($this->container['vaultKeyProvider']) ? $this->container['vaultKeyProvider'] : null;
            $this->provider = $configured instanceof FileKeyProvider ? $configured : new FileKeyProvider($this->container, $this->file);
        }
        return $this->provider;
    }
}
