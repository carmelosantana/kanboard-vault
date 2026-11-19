<?php

namespace Kanboard\Plugin\Vault\WebAuthn;

// A decoded CBOR byte string, kept apart from text strings (PHP strings) so a text "none" or a text
// coordinate can't pass where the format demands bytes.
final class CborBytes
{
    public function __construct(public readonly string $bytes)
    {
    }
}
