<?php

namespace Kanboard\Plugin\Vault\Crypto;

/**
 * Wraps of a principal's X25519 secret key.
 *
 * AEAD wraps (passphrase, passphrase+prf, recovery, agent) are vault_wraps rows:
 * id, user_id (the principal), method, credential_id (NULL unless passphrase+prf),
 * nonce and wrapped_sk as base64 text, crypto_v. unwrap() takes such a row as read
 * from the DB. The Server wrap (method server, principal -1) has the same shape but lives
 * on the vault_meta lock row (server_wrap_id, server_wrap_nonce, server_wrapped_sk).
 * The org wrap is a sealed box and has its own pair of helpers.
 */
final class Wraps
{
    public const CRYPTO_V = 1;
    // The methods of a human's or agent's vault_wraps rows. Server's wrap (method server) never belongs to one.
    public const HOLDER_METHODS = ['passphrase', 'passphrase+prf', 'recovery', 'agent'];
    public const METHODS = [...self::HOLDER_METHODS, 'server'];

    public static function wrap(#[\SensitiveParameter] string $sk, #[\SensitiveParameter] string $kek, int $principalId, string $method, string $credentialId, int $wrapId): array
    {
        self::checkMethod($method, $credentialId);
        $box = Aead::seal($sk, $kek, self::ad($principalId, $method, $credentialId, $wrapId));
        return [
            'id' => $wrapId,
            'user_id' => $principalId,
            'method' => $method,
            'credential_id' => $credentialId === '' ? null : $credentialId,
            'nonce' => base64_encode($box['nonce']),
            'wrapped_sk' => base64_encode($box['ct']),
            'crypto_v' => self::CRYPTO_V,
        ];
    }

    public static function unwrap(array $row, #[\SensitiveParameter] string $kek, string $expectedPk): string
    {
        if ((int) ($row['crypto_v'] ?? 0) !== self::CRYPTO_V) {
            throw new CryptoException('wrap: unsupported crypto version');
        }
        $method = (string) $row['method'];
        $credentialId = (string) ($row['credential_id'] ?? '');
        self::checkMethod($method, $credentialId);
        $nonce = base64_decode((string) $row['nonce'], true);
        $ct = base64_decode((string) $row['wrapped_sk'], true);
        if ($nonce === false || $ct === false) {
            throw new CryptoException('wrap: malformed row');
        }
        $sk = Aead::open($nonce, $ct, $kek, self::ad((int) $row['user_id'], $method, $credentialId, (int) $row['id']));
        if (!self::publicKeyMatches($sk, $expectedPk)) {
            sodium_memzero($sk);
            throw new CryptoException('wrap: public key mismatch');
        }
        return $sk;
    }

    /** The org wrap: crypto_box_seal(enc("orgwrap", principal_id, sk), org_pk). Raw bytes. */
    public static function sealOrg(#[\SensitiveParameter] string $sk, int $principalId, string $orgPk): string
    {
        if (strlen($sk) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            throw new CryptoException('orgwrap: bad secret key length');
        }
        $plain = Encoding::enc('orgwrap', $principalId, $sk);
        try {
            return sodium_crypto_box_seal($plain, $orgPk);
        } catch (\SodiumException) {
            throw new CryptoException('orgwrap: bad org public key');
        } finally {
            sodium_memzero($plain);
        }
    }

    public static function openOrg(string $sealed, #[\SensitiveParameter] string $orgKeypair, int $principalId, string $expectedPk): string
    {
        $plain = self::sealOpen($sealed, $orgKeypair, 'orgwrap');
        try {
            $sk = self::field($plain, Encoding::enc('orgwrap', $principalId), SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 'orgwrap');
        } finally {
            sodium_memzero($plain);
        }
        if (!self::publicKeyMatches($sk, $expectedPk)) {
            sodium_memzero($sk);
            throw new CryptoException('orgwrap: public key mismatch');
        }
        return $sk;
    }

    /**
     * Opens a crypto_box_seal blob. Shared with Sealer.
     * @internal
     */
    public static function sealOpen(string $sealed, #[\SensitiveParameter] string $keypair, string $label): string
    {
        try {
            $plain = sodium_crypto_box_seal_open($sealed, $keypair);
        } catch (\SodiumException) {
            $plain = false;
        }
        if ($plain === false) {
            throw new CryptoException($label.': cannot open');
        }
        return $plain;
    }

    /**
     * Returns the last field of $plain when $plain is exactly $prefix . u32($len) . <$len bytes>,
     * i.e. enc(...prefix fields, value) with a value of exactly $len bytes. Throws otherwise.
     * @internal
     */
    public static function field(#[\SensitiveParameter] string $plain, string $prefix, int $len, string $label): string
    {
        $head = $prefix.pack('N', $len);
        if (strlen($plain) !== strlen($head) + $len || !hash_equals($head, substr($plain, 0, strlen($head)))) {
            throw new CryptoException($label.': field mismatch');
        }
        return substr($plain, strlen($head));
    }

    private static function ad(int $principalId, string $method, string $credentialId, int $wrapId): string
    {
        return Encoding::enc('wrap', self::CRYPTO_V, $principalId, $method, $credentialId, $wrapId);
    }

    private static function checkMethod(string $method, string $credentialId): void
    {
        if (!in_array($method, self::METHODS, true)) {
            throw new CryptoException('wrap: unknown method');
        }
        if (($method === 'passphrase+prf') !== ($credentialId !== '')) {
            throw new CryptoException('wrap: credential id does not fit the method');
        }
    }

    /** The spec's post-unwrap check: sodium_crypto_box_publickey_from_secretkey(sk) equals the stored pk. */
    private static function publicKeyMatches(#[\SensitiveParameter] string $sk, string $expectedPk): bool
    {
        try {
            return strlen($sk) === SODIUM_CRYPTO_BOX_SECRETKEYBYTES
                && hash_equals($expectedPk, sodium_crypto_box_publickey_from_secretkey($sk));
        } catch (\SodiumException) {
            return false;
        }
    }
}
