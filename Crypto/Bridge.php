<?php

namespace Kanboard\Plugin\Vault\Crypto;

/**
 * The rotation bridge (spec: Key rotation, start): sk1 under XChaCha20-Poly1305 with
 * key = BLAKE2b-256(key = sk2, msg = enc("bridge")) and AD = enc("bridge", user_id, old_pk, new_pk).
 * Any surviving factor opens sk2, and sk2 opens the bridge to reach sk1. open() checks both keys against
 * their public keys before returning sk1. Keys and nonces are raw bytes.
 */
final class Bridge
{
    /** @return array{nonce:string,ct:string} */
    public static function seal(#[\SensitiveParameter] string $sk1, #[\SensitiveParameter] string $sk2, int $userId, string $oldPk, string $newPk): array
    {
        if (!self::matches($sk1, $oldPk) || !self::matches($sk2, $newPk)) {
            throw new CryptoException('bridge: key does not match its public key');
        }
        $key = self::key($sk2);
        try {
            return Aead::seal($sk1, $key, self::ad($userId, $oldPk, $newPk));
        } finally {
            sodium_memzero($key);
        }
    }

    public static function open(string $nonce, string $ct, #[\SensitiveParameter] string $sk2, int $userId, string $oldPk, string $newPk): string
    {
        if (!self::matches($sk2, $newPk)) {
            throw new CryptoException('bridge: sk2 does not match new_pk');
        }
        $key = self::key($sk2);
        try {
            $sk1 = Aead::open($nonce, $ct, $key, self::ad($userId, $oldPk, $newPk));
        } finally {
            sodium_memzero($key);
        }
        if (!self::matches($sk1, $oldPk)) {
            sodium_memzero($sk1);
            throw new CryptoException('bridge: sk1 does not match old_pk');
        }
        return $sk1;
    }

    private static function key(#[\SensitiveParameter] string $sk2): string
    {
        return sodium_crypto_generichash(Encoding::enc('bridge'), $sk2, 32);
    }

    private static function ad(int $userId, string $oldPk, string $newPk): string
    {
        return Encoding::enc('bridge', $userId, $oldPk, $newPk);
    }

    private static function matches(#[\SensitiveParameter] string $sk, string $pk): bool
    {
        try {
            return strlen($sk) === SODIUM_CRYPTO_BOX_SECRETKEYBYTES
                && strlen($pk) === SODIUM_CRYPTO_BOX_PUBLICKEYBYTES
                && hash_equals($pk, sodium_crypto_box_publickey_from_secretkey($sk));
        } catch (\SodiumException) {
            return false;
        }
    }
}
