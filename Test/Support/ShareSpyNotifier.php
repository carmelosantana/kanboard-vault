<?php

use Kanboard\Plugin\Vault\Model\Notifier;

// Records the share-reveal notices instead of sending email.
class VaultShareSpyNotifier extends Notifier
{
    public array $revealed = [];

    public function shareRevealed(int $creatorId): bool
    {
        $this->revealed[] = $creatorId;
        return true;
    }
}
