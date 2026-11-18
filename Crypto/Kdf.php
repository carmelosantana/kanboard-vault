<?php

namespace Kanboard\Plugin\Vault\Crypto;

final class Kdf
{
    public const DEFAULT_OPS = 3;
    public const DEFAULT_MEM = 67108864;

    /** Argon2id13, 32-byte output. The salt is 16 bytes. */
    public static function argon2id(string $secret, string $salt, int $ops, int $mem): string
    {
        if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new CryptoException('kdf: bad salt length');
        }
        try {
            return sodium_crypto_pwhash(32, $secret, $salt, $ops, $mem, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
        } catch (\SodiumException) {
            throw new CryptoException('kdf: argon2id failed');
        }
    }

    /**
     * KEK = BLAKE2b-256(key = $ikm, msg = enc("kek", ...$context)). Contexts per the spec:
     * ("passphrase"), ("prf", credential_id, prf_output), ("recovery"), ("agent", agent_user_id).
     * Integers are accepted so ids encode as 8-byte integers, like every other AD.
     */
    public static function kek(string $ikm, string|int ...$context): string
    {
        // An empty key makes generichash unkeyed, which would give a public KEK; refuse anything short.
        if (strlen($ikm) < SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MIN) {
            throw new CryptoException('kdf: bad key material length');
        }
        $msg = Encoding::enc('kek', ...$context);
        try {
            return sodium_crypto_generichash($msg, $ikm, 32);
        } catch (\SodiumException) {
            throw new CryptoException('kdf: bad key material length');
        } finally {
            sodium_memzero($msg);
        }
    }
}
