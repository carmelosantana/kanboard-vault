<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use Kanboard\Core\Base;

// R72: while the Steward plugin's admin "switch user" session is active, the vault doesn't unlock. Steward's own
// SwitchGuard already blocks plugin actions it hasn't been told about; this holds even if Vault's actions were added
// to its allow list. The one signal is Steward's container service: $container['stewardSwitching']->isSwitched().
// No service (Steward not installed): never switched. A service that throws, or isn't Steward's: switched (fail
// closed). There is no hard dependency on Steward.
//
//   isSwitched()     the request guard's check (VaultSession::secretKey locks the session; requireUnlocked says why).
//   refuseUnlock()   every unlock path, before any Argon2, throttle or secret: unlock (passphrase and hardware key)
//                    and a recovery code's use. Audited as unlock_refused (actor, ip_trunc, ua_family; never a secret),
//                    and never a failed guess: no back-off, no IP token, no streak.
class SwitchedSessionGuard extends Base
{
    public const SERVICE = 'stewardSwitching';

    private Closure $clock;

    public function __construct($container, ?callable $clock = null)
    {
        parent::__construct($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
    }

    public function isSwitched(): bool
    {
        if (! isset($this->container[self::SERVICE])) {
            return false;
        }
        try {
            return $this->container[self::SERVICE]->isSwitched() !== false;
        } catch (\Throwable) {
            return true;
        }
    }

    // Throws VaultException('switched') while switched; the audit write never decides the refusal.
    public function refuseUnlock(int $userId, string $ip): void
    {
        if (! $this->isSwitched()) {
            return;
        }
        try {
            $ipTrunc = (new ClientIp($this->container))->truncate($ip);
            AuditModel::of($this->container, $this->clock)->record('unlock_refused', [
                'actor_user_id' => $userId,
                'ip_trunc' => $ipTrunc === '' ? null : $ipTrunc,
                'ua_family' => UaFamily::fromRequest($this->request),
            ]);
        } catch (\Throwable $e) {
            $this->logger->warning('Vault: an unlock refused while switched could not be audited ('.get_class($e).')');
        }
        throw new VaultException('switched');
    }
}
