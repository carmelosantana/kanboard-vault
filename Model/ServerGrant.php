<?php
namespace Kanboard\Plugin\Vault\Model;

use JsonException;
use LogicException;

// Server grants (spec amendment), the validation and encoding part: consumer names, field names and their canonical
// lists, used by the audit checks and by grants. Lists are unique, sorted by byte, 1..MAX entries, each valid; a
// failure is VaultException payload_invalid and never echoes a value.
//
// R1: a field is a top-level entry key (stored plain) or a custom field name, which is never stored in plaintext:
// it is c: + RFC 4648 base32 (upper case, no padding) of BLAKE2b-128 keyed with the field-MAC key. A plain custom
// name is not a valid field.
final class ServerGrant
{
    public const CONSUMER_PATTERN = '/^[A-Za-z][A-Za-z0-9_]{0,63}$/D';
    // R1: the entry's top-level string keys, title included.
    public const TOP_LEVEL = EntryPayload::STRING_KEYS;
    public const MAX_CONSUMERS = 16;
    public const MAX_FIELDS = 32;
    public const MAX_FIELD_BYTES = 128;
    public const DEFAULT_RATE = 60;
    public const DEFAULT_BURST = 10;

    // c: + 26 base32 characters for 16 bytes; the last carries 3 data bits and 2 zero bits.
    private const MAC_PATTERN = '/^c:[A-Z2-7]{25}[AEIMQUY4]$/D';
    private const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR;

    public static function validConsumer(mixed $c): bool
    {
        return is_string($c) && preg_match(self::CONSUMER_PATTERN, $c) === 1;
    }

    public static function validField(mixed $f): bool
    {
        return is_string($f) && (in_array($f, self::TOP_LEVEL, true) || preg_match(self::MAC_PATTERN, $f) === 1);
    }

    // A field name as an owner or a consumer gives it (a ref, a grant request): a top-level key, or a custom name that is
    // valid UTF-8, 1..MAX_FIELD_BYTES bytes, with no control characters.
    public static function validName(#[\SensitiveParameter] mixed $name): bool
    {
        return is_string($name) && (in_array($name, self::TOP_LEVEL, true)
            || ($name !== '' && strlen($name) <= self::MAX_FIELD_BYTES && mb_check_encoding($name, 'UTF-8') && preg_match('/[\x00-\x1f\x7f]/', $name) !== 1));
    }

    // A stored custom field name (R1): what a UI never shows. A top-level name is not one.
    public static function isMac(mixed $f): bool
    {
        return is_string($f) && preg_match(self::MAC_PATTERN, $f) === 1;
    }

    /** @return list<string> */
    public static function consumers(array $list): array
    {
        return self::canonical($list, self::validConsumer(...), self::MAX_CONSUMERS);
    }

    /** @return list<string> */
    public static function fields(array $list): array
    {
        return self::canonical($list, self::validField(...), self::MAX_FIELDS);
    }

    // The stored form of a field name: a top-level name as is, a custom name as its MAC. The name must be validName.
    // $key is the 32-byte field-MAC key.
    public static function macField(#[\SensitiveParameter] string $key, #[\SensitiveParameter] string $name): string
    {
        if (strlen($key) !== SODIUM_CRYPTO_GENERICHASH_KEYBYTES) {
            throw new LogicException('Vault: the field MAC key must be 32 bytes');
        }
        if (! self::validName($name)) {
            throw new VaultException('payload_invalid');
        }
        if (in_array($name, self::TOP_LEVEL, true)) {
            return $name;
        }
        return 'c:'.self::base32(sodium_crypto_generichash($name, $key, 16));
    }

    // A grant's stored rate: the requested value (or the default) clamped to the admin maximum. A requested value
    // below 1 is payload_invalid.
    public static function rate(?int $requested, int $default, int $max): int
    {
        if ($requested !== null && $requested < 1) {
            throw new VaultException('payload_invalid');
        }
        return min($requested ?? $default, $max);
    }

    public static function encodeList(array $list): string
    {
        return json_encode(array_values($list), self::JSON_FLAGS);
    }

    // The list a canonical JSON value holds: [] for null. A value that isn't a sorted, unique list of strings in
    // encodeList's exact form is a LogicException (the stored value was not written by this class).
    /** @return list<string> */
    public static function decodeList(?string $json): array
    {
        if ($json === null) {
            return [];
        }
        try {
            $list = json_decode($json, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new LogicException('Vault: a stored list is not JSON');
        }
        if (! is_array($list) || ! array_is_list($list) || array_filter($list, 'is_string') !== $list) {
            throw new LogicException('Vault: a stored list is not a list of strings');
        }
        $sorted = array_values(array_unique($list));
        sort($sorted, SORT_STRING);
        if ($sorted !== $list || self::encodeList($list) !== $json) {
            throw new LogicException('Vault: a stored list is not canonical');
        }
        return $list;
    }

    /** @return list<string> */
    private static function canonical(array $list, callable $valid, int $max): array
    {
        foreach ($list as $item) {
            if (! $valid($item)) {
                throw new VaultException('payload_invalid');
            }
        }
        $out = array_values(array_unique($list));
        sort($out, SORT_STRING);
        if ($out === [] || count($out) > $max) {
            throw new VaultException('payload_invalid');
        }
        return $out;
    }

    private static function base32(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $c) {
            $bits .= sprintf('%08b', ord($c));
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::BASE32[bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }
}
