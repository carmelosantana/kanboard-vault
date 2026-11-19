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
// (the owner can't open a DEK they must hold; or, per row of a list, an entitled entry that fails to decrypt),
// rotation_in_progress (a rotation is already under way), rotation_needs_factors (the principal has wraps other
// than a passphrase, whose ceremony must present them), rotation_incomplete (finish refused: old-generation key
// rows remain), policy_forbids (the recovery policy doesn't allow a recovery code), recovery_failed (org recovery:
// a bad org secret, an unknown user, a policy below code_org or no org wrap; one code for all), org_key_exists
// (vault:org-keygen without --replace).
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
