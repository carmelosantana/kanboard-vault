<?php
namespace Kanboard\Plugin\Vault\Model;

use RuntimeException;

// A user-facing Vault failure. The message is the fixed code string and nothing else: it never carries a
// secret, a crypto error label or a reason that would tell one failure from another (no oracle).
// Codes: unlock_failed, rate_limited, busy (the principal's derivation is running: 429),
// busy_global (every Argon2 slot is busy: 503), https_required, passphrase_weak, passphrase_reuse,
// already_enrolled, not_enrolled.
class VaultException extends RuntimeException
{
    public function __construct(private string $errorCode)
    {
        parent::__construct($errorCode);
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }
}
