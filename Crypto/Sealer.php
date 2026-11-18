<?php

namespace Kanboard\Plugin\Vault\Crypto;

/**
 * Sealed DEKs: crypto_box_seal(enc("dek", object_type, object_id, key_epoch, principal_id, DEK), pk).
 * A sealed box has no AD, so every field is checked after opening. Blobs are raw bytes.
 */
final class Sealer
{
    public const DEK_BYTES = 32;

    public static function sealDek(#[\SensitiveParameter] string $dek, string $objectType, int $objectId, int $keyEpoch, int $principalId, string $pk): string
    {
        if (strlen($dek) !== self::DEK_BYTES) {
            throw new CryptoException('dek: bad length');
        }
        $plain = Encoding::enc('dek', $objectType, $objectId, $keyEpoch, $principalId, $dek);
        try {
            return sodium_crypto_box_seal($plain, $pk);
        } catch (\SodiumException) {
            throw new CryptoException('dek: bad public key');
        } finally {
            sodium_memzero($plain);
        }
    }

    public static function openDek(string $sealed, #[\SensitiveParameter] string $keypair, string $objectType, int $objectId, int $keyEpoch, int $principalId): string
    {
        $plain = Wraps::sealOpen($sealed, $keypair, 'dek');
        try {
            return Wraps::field($plain, Encoding::enc('dek', $objectType, $objectId, $keyEpoch, $principalId), self::DEK_BYTES, 'dek');
        } finally {
            sodium_memzero($plain);
        }
    }
}
