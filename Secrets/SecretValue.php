<?php
namespace Kanboard\Plugin\Vault\Secrets;

use LogicException;
use WeakMap;

// A secret read for a consumer (spec amendment: security requirement 9). The bytes live in a private static WeakMap
// keyed by the instance, never in a property, so var_dump, print_r, var_export, json_encode and a printed trace
// argument show nothing. It can't be serialised, unserialised, cloned or cast to a string. reveal() is the only way out.
//
// Codex R3-03: the map holds a SecretValueBytes, which owns a buffer of its own and wipes it when the SecretValue is
// collected (the WeakMap drops the holder, the holder's destructor runs sodium_memzero). reveal() hands out a separate
// copy, so the holder stays the buffer's only owner and the wipe really zeroes it. The consumer's copy is ordinary PHP
// data and outside Vault's control.
final class SecretValue
{
    /** @var WeakMap<self, SecretValueBytes>|null */
    private static ?WeakMap $bytes = null;

    private function __construct()
    {
    }

    /** @internal Vault creates these. */
    public static function of(#[\SensitiveParameter] string $bytes): self
    {
        $value = new self();
        self::$bytes ??= new WeakMap();
        self::$bytes[$value] = new SecretValueBytes($bytes);
        return $value;
    }

    public function reveal(): string
    {
        return self::$bytes[$this]->copy();
    }

    public function __serialize(): array
    {
        throw new LogicException('Vault: a SecretValue cannot be serialised');
    }

    public function __unserialize(array $data): void
    {
        throw new LogicException('Vault: a SecretValue cannot be unserialised');
    }

    public function __clone()
    {
        throw new LogicException('Vault: a SecretValue cannot be cloned');
    }

    public function __debugInfo(): array
    {
        return [];
    }
}

/**
 * @internal SecretValue's bytes. Never handed out; reachable only through SecretValue's private WeakMap.
 */
final class SecretValueBytes
{
    private ?string $bytes;

    public function __construct(#[\SensitiveParameter] string $bytes)
    {
        $this->bytes = self::separate($bytes);
    }

    public function copy(): string
    {
        return self::separate((string) $this->bytes);
    }

    // sodium_memzero zeroes only a string nothing else holds; here the holder is its only owner.
    public function __destruct()
    {
        if ($this->bytes !== null) {
            sodium_memzero($this->bytes);
        }
    }

    public function __serialize(): array
    {
        throw new LogicException('Vault: a SecretValue cannot be serialised');
    }

    public function __unserialize(array $data): void
    {
        throw new LogicException('Vault: a SecretValue cannot be unserialised');
    }

    public function __clone()
    {
        throw new LogicException('Vault: a SecretValue cannot be cloned');
    }

    public function __debugInfo(): array
    {
        return [];
    }

    // A buffer of its own: PHP strings are shared until written, and writing one offset copies a shared string. An empty
    // string is interned and holds nothing to wipe.
    private static function separate(#[\SensitiveParameter] string $s): string
    {
        if ($s !== '') {
            $s[0] = $s[0];
        }
        return $s;
    }
}
