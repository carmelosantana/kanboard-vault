<?php

namespace Kanboard\Plugin\Vault\Crypto;

/**
 * Recovery codes: 160 random bits as 32 Crockford-base32 characters (MSB first) in 8 groups
 * of 4, then 2 check characters. The check is the top 10 bits of CRC-16/T10-DIF (poly 0x8BB7,
 * init 0, no reflection) over the 20 bytes. That CRC was chosen because its top 10 bits catch
 * every single-character substitution and every adjacent transposition of the 32 data
 * characters (RecoveryCodeTest proves it exhaustively).
 */
final class RecoveryCode
{
    public const SECRET_BYTES = 20;
    private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    private const DATA_CHARS = 32;

    /** @return array{secret:string,display:string} */
    public static function generate(): array
    {
        $secret = random_bytes(self::SECRET_BYTES);
        $chars = self::encode($secret).self::check($secret);
        return ['secret' => $secret, 'display' => implode('-', str_split($chars, 4))];
    }

    /** Returns the 20-byte secret, or throws on a bad character, length or checksum. */
    public static function parse(#[\SensitiveParameter] string $input): string
    {
        $chars = self::normalize($input);
        if (strlen($chars) !== self::DATA_CHARS + 2) {
            throw new CryptoException('recovery code: wrong length');
        }
        if (strspn($chars, self::ALPHABET) !== strlen($chars)) {
            throw new CryptoException('recovery code: invalid character');
        }
        $secret = self::decode(substr($chars, 0, self::DATA_CHARS));
        if (!hash_equals(self::check($secret), substr($chars, self::DATA_CHARS))) {
            sodium_memzero($secret);
            throw new CryptoException('recovery code: checksum mismatch');
        }
        return $secret;
    }

    /**
     * Case-folded, separators dropped, I/L→1 and O→0. Shared with OrgSecret.
     * @internal
     */
    public static function normalize(#[\SensitiveParameter] string $input): string
    {
        return strtr(strtoupper((string) preg_replace('/[\s\-_.]+/', '', $input)), ['I' => '1', 'L' => '1', 'O' => '0']);
    }

    /** True when every character is in the Crockford alphabet. @internal */
    public static function inAlphabet(#[\SensitiveParameter] string $chars): bool
    {
        return strspn($chars, self::ALPHABET) === strlen($chars);
    }

    /** The 2 check characters for a 20-byte secret (OrgSecret uses them for 32 bytes). */
    public static function check(#[\SensitiveParameter] string $secret): string
    {
        $c = self::crc16($secret) >> 6;
        return self::ALPHABET[$c >> 5].self::ALPHABET[$c & 31];
    }

    /** CRC-16/T10-DIF: poly 0x8BB7, init 0, no reflection, no final xor. */
    public static function crc16(#[\SensitiveParameter] string $data): int
    {
        $crc = 0;
        for ($i = 0, $n = strlen($data); $i < $n; $i++) {
            $crc ^= ord($data[$i]) << 8;
            for ($b = 0; $b < 8; $b++) {
                $crc = ($crc & 0x8000) ? (($crc << 1) ^ 0x8BB7) & 0xFFFF : ($crc << 1) & 0xFFFF;
            }
        }
        return $crc;
    }

    /** Crockford base32, MSB first; a partial last character is zero-padded. @internal */
    public static function encode(#[\SensitiveParameter] string $bytes): string
    {
        $out = '';
        $buffer = 0;
        $bits = 0;
        for ($i = 0, $n = strlen($bytes); $i < $n; $i++) {
            $buffer = ($buffer << 8) | ord($bytes[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= self::ALPHABET[($buffer >> $bits) & 31];
            }
            $buffer &= (1 << $bits) - 1;
        }
        if ($bits > 0) {
            $out .= self::ALPHABET[($buffer << (5 - $bits)) & 31];
        }
        return $out;
    }

    /** The inverse of encode(); leftover padding bits are dropped (callers check canonical form). @internal */
    public static function decode(#[\SensitiveParameter] string $chars): string
    {
        $out = '';
        $buffer = 0;
        $bits = 0;
        for ($i = 0, $n = strlen($chars); $i < $n; $i++) {
            $buffer = ($buffer << 5) | strpos(self::ALPHABET, $chars[$i]);
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($buffer >> $bits) & 0xFF);
            }
            $buffer &= (1 << $bits) - 1;
        }
        return $out;
    }
}
