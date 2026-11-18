<?php

namespace Kanboard\Plugin\Vault\Crypto;

/** XChaCha20-Poly1305-IETF with a fresh random 24-byte nonce per seal. */
final class Aead
{
    public static function seal(string $plaintext, string $key, string $ad): array
    {
        self::checkKey($key);
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $ad, $nonce, $key);
        return ['nonce' => $nonce, 'ct' => $ct];
    }

    public static function open(string $nonce, string $ct, string $key, string $ad): string
    {
        self::checkKey($key);
        if (strlen($nonce) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
            throw new CryptoException('aead: bad nonce length');
        }
        try {
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, $ad, $nonce, $key);
        } catch (\SodiumException) {
            $plain = false;
        }
        if ($plain === false) {
            throw new CryptoException('aead: authentication failed');
        }
        return $plain;
    }

    private static function checkKey(string $key): void
    {
        if (strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new CryptoException('aead: bad key length');
        }
    }
}
