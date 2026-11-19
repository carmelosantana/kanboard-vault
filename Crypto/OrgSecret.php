<?php

namespace Kanboard\Plugin\Vault\Crypto;

/**
 * The org recovery secret key (spec: Recovery, "printed once, as base32 with a checksum"): the 32-byte X25519
 * secret key as 52 Crockford-base32 characters (the last one zero-padded), then RecoveryCode's 2 check
 * characters over the 32 bytes, in groups of 4. Input is normalised like a recovery code. The checksum only
 * catches typing slips; the real check is that the key's public key equals the stored org public key.
 */
final class OrgSecret
{
    public const BYTES = SODIUM_CRYPTO_BOX_SECRETKEYBYTES;
    private const DATA_CHARS = 52;

    public static function format(#[\SensitiveParameter] string $sk): string
    {
        if (strlen($sk) !== self::BYTES) {
            throw new CryptoException('org secret: bad length');
        }
        return implode('-', str_split(RecoveryCode::encode($sk).RecoveryCode::check($sk), 4));
    }

    /** The 32-byte secret key, or throws on a bad character, length, padding or checksum. */
    public static function parse(#[\SensitiveParameter] string $input): string
    {
        $chars = RecoveryCode::normalize($input);
        if (strlen($chars) !== self::DATA_CHARS + 2 || ! RecoveryCode::inAlphabet($chars)) {
            throw new CryptoException('org secret: malformed');
        }
        $data = substr($chars, 0, self::DATA_CHARS);
        $sk = RecoveryCode::decode($data);
        // Canonical form only: the padding bits of the last character must be zero.
        if (strlen($sk) !== self::BYTES || ! hash_equals(RecoveryCode::encode($sk), $data)
            || ! hash_equals(RecoveryCode::check($sk), substr($chars, self::DATA_CHARS))) {
            sodium_memzero($sk);
            throw new CryptoException('org secret: malformed');
        }
        return $sk;
    }
}
