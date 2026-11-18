<?php
namespace Kanboard\Plugin\Vault\Model;

// The one place Vault sets cookies, so tests can capture them. Options are setcookie()'s array form.
class CookieJar
{
    public function set(string $name, string $value, array $options): void
    {
        if (! headers_sent()) {
            setcookie($name, $value, $options);
        }
    }
}
