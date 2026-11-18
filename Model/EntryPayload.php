<?php
namespace Kanboard\Plugin\Vault\Model;

use JsonException;

// The plaintext shapes of entry and group payloads (spec: Entries, groups and grants). validate() returns the
// canonical form: every key present, in a fixed order, with defaults for missing ones. The 256 KB limit is
// on the bytes of the JSON that gets encrypted. Failures are VaultException payload_invalid or
// payload_too_large, and never echo a value.
final class EntryPayload
{
    public const MAX_BYTES = 262144;
    public const JSON_FLAGS = JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;

    // Top-level string values; readField() can return any of these.
    public const STRING_KEYS = ['title', 'username', 'password', 'url', 'notes', 'otp'];
    private const ENTRY_DEFAULTS = [
        'title' => '', 'username' => '', 'password' => '', 'url' => '', 'notes' => '',
        'tags' => [], 'expires_at' => null, 'otp' => '', 'fields' => [],
    ];
    private const GROUP_DEFAULTS = ['name' => '', 'icon' => '', 'notes' => ''];
    private const FIELD_KEYS = ['name', 'value', 'protected'];

    public static function validate(#[\SensitiveParameter] array $p): array
    {
        self::onlyKeys($p, array_keys(self::ENTRY_DEFAULTS));
        $out = $p + self::ENTRY_DEFAULTS;
        foreach (self::STRING_KEYS as $key) {
            self::string($out[$key]);
        }
        if (! is_array($out['tags']) || ! array_is_list($out['tags'])) {
            throw new VaultException('payload_invalid');
        }
        foreach ($out['tags'] as $tag) {
            self::string($tag);
        }
        if ($out['expires_at'] !== null && (! is_int($out['expires_at']) || $out['expires_at'] < 0)) {
            throw new VaultException('payload_invalid');
        }
        if (! is_array($out['fields']) || ! array_is_list($out['fields'])) {
            throw new VaultException('payload_invalid');
        }
        $names = [];
        $fields = [];
        foreach ($out['fields'] as $field) {
            if (! is_array($field)) {
                throw new VaultException('payload_invalid');
            }
            $keys = array_keys($field);
            sort($keys);
            $want = self::FIELD_KEYS;
            sort($want);
            if ($keys !== $want || ! is_bool($field['protected'])) {
                throw new VaultException('payload_invalid');
            }
            self::string($field['name']);
            self::string($field['value']);
            if ($field['name'] === '' || isset($names[$field['name']])) {
                throw new VaultException('payload_invalid');
            }
            $names[$field['name']] = true;
            $fields[] = ['name' => $field['name'], 'value' => $field['value'], 'protected' => $field['protected']];
        }
        $out['fields'] = $fields;
        $out = array_merge(self::ENTRY_DEFAULTS, $out); // canonical key order
        $json = self::encode($out);
        sodium_memzero($json);
        return $out;
    }

    // A group payload: {name, icon, notes}. The name is required.
    public static function validateGroup(#[\SensitiveParameter] array $p): array
    {
        self::onlyKeys($p, array_keys(self::GROUP_DEFAULTS));
        $out = array_merge(self::GROUP_DEFAULTS, $p);
        foreach ($out as $value) {
            self::string($value);
        }
        if ($out['name'] === '') {
            throw new VaultException('payload_invalid');
        }
        $json = self::encode($out);
        sodium_memzero($json);
        return $out;
    }

    // The exact JSON bytes that get encrypted. Throws payload_too_large over MAX_BYTES.
    public static function encode(#[\SensitiveParameter] array $p): string
    {
        try {
            $json = json_encode($p, self::JSON_FLAGS);
        } catch (JsonException) {
            throw new VaultException('payload_invalid'); // e.g. invalid UTF-8
        }
        if (strlen($json) > self::MAX_BYTES) {
            sodium_memzero($json);
            throw new VaultException('payload_too_large');
        }
        return $json;
    }

    // Decrypted JSON back to an array. Any malformed plaintext is a CryptoException-equivalent for callers.
    public static function decode(#[\SensitiveParameter] string $json): array
    {
        $p = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        if (! is_array($p)) {
            throw new JsonException('payload is not an object');
        }
        return $p;
    }

    private static function onlyKeys(#[\SensitiveParameter] array $p, array $allowed): void
    {
        if (array_diff(array_keys($p), $allowed) !== []) {
            throw new VaultException('payload_invalid');
        }
    }

    private static function string(#[\SensitiveParameter] mixed $v): void
    {
        if (! is_string($v)) {
            throw new VaultException('payload_invalid');
        }
    }
}
