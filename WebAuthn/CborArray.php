<?php

namespace Kanboard\Plugin\Vault\WebAuthn;

// A decoded CBOR array, kept apart from maps (PHP arrays) so [] can't pass where an empty map is demanded.
final class CborArray
{
    /** @param list<mixed> $items */
    public function __construct(public readonly array $items)
    {
    }
}
