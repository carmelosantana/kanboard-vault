<?php
namespace Kanboard\Plugin\Vault\Secrets;

use LogicException;
use RuntimeException;

// A consumer's read refused (spec amendment: consumer API). The message is the frozen reason string and nothing
// else, with no previous exception, so a logged refusal carries no secret, path or crypto label.
final class ServiceSecretException extends RuntimeException
{
    public const REASONS = ['server_off', 'server_key_unavailable', 'not_shared', 'consumer_not_allowed',
        'field_not_allowed', 'rate_limited', 'revoked', 'not_found', 'orphaned'];

    public function __construct(private string $reason)
    {
        if (! in_array($reason, self::REASONS, true)) {
            throw new LogicException('Vault: unknown service secret reason');
        }
        parent::__construct($reason);
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
