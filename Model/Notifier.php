<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Core\Base;
use Throwable;

// Email notices (R19; spec: Throttling, Recovery, One-time shares, Agents), sent through Kanboard's emailClient
// and skipped when email isn't configured. Each notice is fixed text plus the recipient's own name; none carries a
// secret, an entry, a share label or an IP.
//
// "Configured" (emailConfigured, mailUsable). Kanboard registers its smtp, sendmail and mail transports on every
// install and defaults to MAIL_TRANSPORT = mail with MAIL_FROM = notifications@kanboard.local, so registration says
// nothing. Email counts as configured only when all of these hold:
//   - the effective transport (Settings → Email when MAIL_CONFIGURATION allows it, else MAIL_TRANSPORT) is a
//     registered transport;
//   - the effective sender (Settings → Email sender address, else MAIL_FROM) is a valid address and not Kanboard's
//     stock default notifications@kanboard.local, which an install that never set up email still has;
//   - smtp: MAIL_SMTP_HOSTNAME is set (its default is empty);
//   - sendmail: the binary of MAIL_SENDMAIL_COMMAND exists and is executable;
//   - mail: the binary of PHP's sendmail_path exists and is executable (PHP's mail() hands the message to it);
//   - any other transport is a plugin's (Resend, ...), which owns its own settings: registered is enough.
// The recipient must also be an active user with an address.
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

    // Kanboard's built-in MAIL_FROM default: an install that never configured email still sends "from" it.
    public const STOCK_SENDER = 'notifications@kanboard.local';

    public function emailConfigured(): bool
    {
        return self::mailUsable(
            (string) $this->helper->mail->getMailTransport(),
            array_keys($this->emailClient->getAvailableTransports()),
            (string) $this->helper->mail->getMailSenderAddress(),
            (string) MAIL_SMTP_HOSTNAME,
            (string) MAIL_SENDMAIL_COMMAND,
            (string) ini_get('sendmail_path')
        );
    }

    // The rule above, from the effective values. Pure, so every branch is testable whatever the process's constants.
    /** @param list<string> $registered */
    public static function mailUsable(string $transport, array $registered, string $sender, string $smtpHost, string $sendmailCommand, string $sendmailPath): bool
    {
        if (! in_array($transport, $registered, true)) {
            return false;
        }
        $sender = trim($sender);
        if (filter_var($sender, FILTER_VALIDATE_EMAIL) === false || strcasecmp($sender, self::STOCK_SENDER) === 0) {
            return false;
        }
        return match ($transport) {
            'smtp' => trim($smtpHost) !== '',
            'sendmail' => self::executable($sendmailCommand),
            'mail' => self::executable($sendmailPath),
            default => true,
        };
    }

    // The command's first word is an existing executable file.
    private static function executable(string $command): bool
    {
        $bin = strtok(trim($command), " \t");
        return $bin !== false && $bin !== '' && is_file($bin) && is_executable($bin);
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
