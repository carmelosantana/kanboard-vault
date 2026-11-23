<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use SodiumException;
use ValueError;

// The Server key from the key file (spec amendment: Server key file, security requirement 2). The Server sk exists only
// as the Server wrap on the vault_meta lock row: Wraps::wrap(sk, KEK = Kdf::kek(file_key, 'server', -1)) with the wrap
// id server_wrap_id in its AD, so a database backup without the key file opens nothing. Each open unwraps the sk,
// uses it and wipes it; only the file key is kept on the instance (read once, wiped in __destruct). Every failure is
// a bare ServerKeyUnavailable, never chained: a CryptoException or PHP warning carries nothing useful to a caller.
final class FileKeyProvider extends Base implements KeyProvider
{
    private ?string $fileKey = null;

    public function __construct($container, private ServerKeyFile $file)
    {
        parent::__construct($container);
    }

    public function __destruct()
    {
        if ($this->fileKey !== null) {
            sodium_memzero($this->fileKey);
        }
    }

    /** var_dump and print_r never show the cached file key. */
    public function __debugInfo(): array
    {
        return ['fileKey' => $this->fileKey === null ? null : '[redacted]'];
    }

    public function id(): string
    {
        return 'file';
    }

    /** Reads the key file now and keeps it, so a caller can do the file I/O before it takes the vault lock. */
    public function warm(): void
    {
        $this->fileKey();
    }

    /** The key file reads now (not the cached copy), the wrap opens, and pk(sk) is the Server principal's public key. */
    public function healthy(): bool
    {
        $key = $sk = '';
        try {
            $key = $this->file->read();
            $sk = $this->unwrapSk(new VaultDb($this->container), $key);
            return true;
        } catch (\Throwable) {
            return false;
        } finally {
            sodium_memzero($key);
            sodium_memzero($sk);
        }
    }

    public function openSealedDek(string $sealed, DekContext $ctx): string
    {
        return $this->withKeypair(static fn (#[\SensitiveParameter] string $keypair): string => Sealer::openDek($sealed, $keypair, $ctx->objectType, $ctx->objectId, $ctx->keyEpoch, $ctx->principalId));
    }

    public function openFieldMacKey(): string
    {
        return $this->withKeypair(static function (#[\SensitiveParameter] string $keypair, VaultDb $db): string {
            $row = $db->fetchOne('SELECT server_field_mac_sealed FROM vault_meta WHERE id = 1');
            $sealed = base64_decode((string) ($row['server_field_mac_sealed'] ?? ''), true);
            if ($sealed === false || $sealed === '') {
                throw new ServerKeyUnavailable();
            }
            return Sealer::openFieldMacKey($sealed, $keypair, ServerPrincipal::ID);
        });
    }

    // Inside the caller's exclusive lock: wraps $sk under the file key as the next Server wrap (server_wrap_id + 1,
    // never reused) and records the provider.
    public function wrapNew(VaultDb $db, #[\SensitiveParameter] string $sk): void
    {
        $kek = Kdf::kek($this->fileKey(), 'server', ServerPrincipal::ID);
        try {
            $meta = $db->fetchOne('SELECT server_wrap_id FROM vault_meta WHERE id = 1') ?? throw new \RuntimeException('Vault: the vault_meta lock row is missing');
            $wrap = Wraps::wrap($sk, $kek, ServerPrincipal::ID, 'server', '', (int) $meta['server_wrap_id'] + 1);
            $db->execute(
                "UPDATE vault_meta SET server_provider = 'file', server_wrap_id = ?, server_wrap_nonce = ?, server_wrapped_sk = ? WHERE id = 1",
                [$wrap['id'], $wrap['nonce'], $wrap['wrapped_sk']]
            );
        } finally {
            sodium_memzero($kek);
        }
    }

    private function fileKey(): string
    {
        return $this->fileKey ??= $this->file->read();
    }

    /**
     * Runs $fn with the Server keypair and wipes it after. Every key failure is ServerKeyUnavailable; anything else (a
     * database error) propagates, so every $fn marks its keypair parameter #[\SensitiveParameter] to keep it out of
     * that exception's trace.
     *
     * @template T
     * @param callable(string, VaultDb): T $fn
     * @return T
     */
    private function withKeypair(callable $fn): mixed
    {
        $sk = $keypair = '';
        try {
            $db = new VaultDb($this->container);
            $sk = $this->unwrapSk($db, $this->fileKey());
            $keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, sodium_crypto_box_publickey_from_secretkey($sk));
            return $fn($keypair, $db);
        } catch (CryptoException|SodiumException|ValueError|ServerKeyUnavailable) {
            throw new ServerKeyUnavailable();
        } finally {
            sodium_memzero($sk);
            sodium_memzero($keypair);
        }
    }

    // The Server sk from the vault_meta wrap; Wraps::unwrap checks pk(sk) against the principal's public key.
    private function unwrapSk(VaultDb $db, #[\SensitiveParameter] string $fileKey): string
    {
        $meta = $db->fetchOne('SELECT server_provider, server_wrap_id, server_wrap_nonce, server_wrapped_sk FROM vault_meta WHERE id = 1');
        $p = $db->fetchOne("SELECT public_key FROM vault_principals WHERE user_id = ? AND kind = 'server'", [ServerPrincipal::ID]);
        $pk = $p === null ? false : base64_decode((string) $p['public_key'], true);
        if ($meta === null || $pk === false || $meta['server_provider'] !== 'file' || $meta['server_wrapped_sk'] === null) {
            throw new ServerKeyUnavailable();
        }
        $kek = Kdf::kek($fileKey, 'server', ServerPrincipal::ID);
        try {
            return Wraps::unwrap([
                'id' => (int) $meta['server_wrap_id'],
                'user_id' => ServerPrincipal::ID,
                'method' => 'server',
                'credential_id' => null,
                'nonce' => $meta['server_wrap_nonce'],
                'wrapped_sk' => $meta['server_wrapped_sk'],
                'crypto_v' => Wraps::CRYPTO_V,
            ], $kek, $pk);
        } finally {
            sodium_memzero($kek);
        }
    }
}
