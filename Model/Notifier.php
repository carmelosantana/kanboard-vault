<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Core\Base;
use Throwable;

// Email notices (R19; spec: Throttling, Recovery, One-time shares, Agents), sent through Kanboard's emailClient
// and skipped when email isn't configured: no usable mail transport, or a recipient without an address. Each
// notice is fixed text plus the recipient's own name; none carries a secret, an entry, a share label or an IP.
//
// A notice is best-effort and never fails the action that triggered it: callers send it after their change has
// committed, and every public method returns false (logging the exception class only) instead of throwing. The
// share-reveal and agent notices are hooks for T16/T18.
class Notifier extends Base
{
    // The container's notifier ('vaultNotifier', registered by the plugin) or a new one.
    public static function of($container): self
    {
        return isset($container['vaultNotifier']) ? $container['vaultNotifier'] : new self($container);
    }

    public function emailConfigured(): bool
    {
        return isset($this->emailClient->getAvailableTransports()[$this->helper->mail->getMailTransport()]);
    }

    // Five consecutive failed unlocks (passphrase or recovery code).
    public function unlockFailures(int $userId): bool
    {
        return $this->notice($userId, t('Vault: %d failed unlock attempts', PrincipalModel::NOTIFY_AFTER),
            t('There were %d failed attempts in a row to unlock your vault. If they were not yours, change your vault passphrase and tell your administrator.', PrincipalModel::NOTIFY_AFTER));
    }

    public function orgRecovered(int $userId): bool
    {
        return $this->notice($userId, t('Vault: your vault was recovered by an administrator'),
            t('An administrator recovered your vault with the organisation recovery key and set a new vault passphrase. Your hardware keys were removed and your keys rotated. Ask your administrator for the new passphrase, then change it.'));
    }

    // To the sender of a one-time share that was just revealed.
    public function shareRevealed(int $creatorId): bool
    {
        return $this->notice($creatorId, t('Vault: a one-time link you shared was opened'),
            t('One of your one-time links was opened and revealed. See your Vault activity for when.'));
    }

    // To the agent's owner, after the agent's vault key failed repeatedly.
    public function agentBadKey(int $agentId): bool
    {
        $owner = $this->ownerOf($agentId);
        return $owner !== null && $this->notice($owner, t('Vault: an agent\'s vault key was refused'),
            t('Repeated requests for your agent %s were refused because of a wrong vault key. See your Vault activity.', $this->username($agentId)));
    }

    // To the agent's owner, when the agent hit its read cap.
    public function agentRateLimited(int $agentId): bool
    {
        $owner = $this->ownerOf($agentId);
        return $owner !== null && $this->notice($owner, t('Vault: an agent hit its read limit'),
            t('Your agent %s reached its hourly limit of secret reads. See your Vault activity.', $this->username($agentId)));
    }

    private function notice(int $userId, string $subject, string $text): bool
    {
        try {
            return $this->send($userId, $subject, '<p>'.$this->e($text).'</p>');
        } catch (Throwable $e) {
            $this->logger->warning('Vault: a notice could not be sent ('.get_class($e).')');
            return false;
        }
    }

    // Queues the email; false when email isn't configured or the user has no address. The author is fixed: the
    // logged-in user's address (Kanboard's default reply-to) has nothing to do with a vault notice.
    protected function send(int $userId, string $subject, string $html): bool
    {
        if (! $this->emailConfigured()) {
            return false;
        }
        $user = (new VaultDb($this->container))->fetchOne('SELECT username, name, email FROM users WHERE id = ? AND is_active = 1', [$userId]);
        if ($user === null || trim((string) $user['email']) === '') {
            return false;
        }
        $name = (string) ($user['name'] ?: $user['username']);
        $this->emailClient->send((string) $user['email'], $name, $subject, '<p>'.$this->e(t('Hello %s,', $name)).'</p>'.$html, 'Kanboard Vault', '');
        return true;
    }

    // The agent's owner from Agents' roster (class_exists guard), or null.
    private function ownerOf(int $agentId): ?int
    {
        if (! class_exists('\Kanboard\Plugin\Agents\Model\AgentTable')) {
            return null;
        }
        try {
            $row = (new VaultDb($this->container))->fetchOne('SELECT owner_user_id FROM agents WHERE agent_user_id = ?', [$agentId]);
        } catch (Throwable) {
            return null;
        }
        return $row === null ? null : (int) $row['owner_user_id'];
    }

    private function username(int $userId): string
    {
        $row = (new VaultDb($this->container))->fetchOne('SELECT username FROM users WHERE id = ?', [$userId]);
        return $row === null ? '#'.$userId : (string) $row['username'];
    }

    private function e(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
