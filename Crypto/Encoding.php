<?php

namespace Kanboard\Plugin\Vault\Crypto;

/**
 * The one canonical encoding for every AD and sealed plaintext:
 * "vault/v1", then per field a u32 big-endian length and its bytes.
 * Integers are 8-byte big-endian. Nothing is ever plain-concatenated.
 */
final class Encoding
{
    public const TAG = 'vault/v1';

    public static function enc(string|int ...$fields): string
    {
        $out = self::TAG;
        foreach ($fields as $field) {
            $bytes = is_int($field) ? pack('J', $field) : $field;
            $out .= pack('N', strlen($bytes)).$bytes;
        }
        return $out;
    }
}
