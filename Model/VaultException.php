<?php
namespace Kanboard\Plugin\Vault\Model;

use RuntimeException;

// A user-facing Vault failure. The message is the fixed code string and nothing else: it never carries a
// secret, a crypto error label or a reason that would tell one failure from another (no oracle).
// Codes: unlock_failed, rate_limited, busy (the principal's derivation is running: 429),
// busy_global (every Argon2 slot is busy: 503), https_required, passphrase_weak, passphrase_reuse,
// already_enrolled, not_enrolled, not_found (no such object, or not readable by the caller: one code for
// both), conflict (a stale entry version), payload_invalid, payload_too_large,
// invalid_move (a group moved into its own subtree, or an entry with no destination group), integrity_error
// (the owner can't open a DEK they must hold; or, per row of a list, an entitled entry that fails to decrypt).
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
