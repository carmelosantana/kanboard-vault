<?php

use Kanboard\Plugin\Vault\Model\AuditModel;

// An audit log that fails one action, to prove a multi-step change commits or rolls back as one.
class VaultFailingAudit extends AuditModel
{
    public function __construct($container, private string $failOn, ?callable $clock = null)
    {
        parent::__construct($container, null, null, $clock);
    }

    public function record(string $action, array $cols): void
    {
        if ($action === $this->failOn) {
            throw new RuntimeException('injected audit failure');
        }
        parent::record($action, $cols);
    }
}
