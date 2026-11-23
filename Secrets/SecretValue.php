<?php
namespace Kanboard\Plugin\Vault\Secrets;

use LogicException;
use WeakMap;

// A secret read for a consumer (spec amendment: security requirement 9). The bytes live in a private static WeakMap
// keyed by the instance, never in a property, so var_dump, print_r, var_export, json_encode and a printed trace
// argument show nothing. It can't be serialised, unserialised, cloned or cast to a string. reveal() is the only way out.
final class SecretValue
{
    /** @var WeakMap<self, string>|null */
    private static ?WeakMap $bytes = null;

    private function __construct()
    {
    }

    /** @internal Vault creates these. */
    public static function of(#[\SensitiveParameter] string $bytes): self
    {
        $value = new self();
        self::$bytes ??= new WeakMap();
        self::$bytes[$value] = $bytes;
        return $value;
    }

    public function reveal(): string
    {
        return self::$bytes[$this];
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
