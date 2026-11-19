<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\AgentRoster;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\ShareModel;
use Kanboard\Plugin\Vault\Model\VaultSettings;

// The Vault page and its session endpoints (spec: UI → States, Unlocked sessions).
//
//   GET  vault         first visit: enrolment; enrolled but locked: the unlock form; unlocked: the shell.
//   POST vault/enrol   {passphrase, confirm}: enrols, then unlocks with the same passphrase.
//   POST vault/unlock  {passphrase}: {ok} or {ok:false, reason}; unlock_failed 401, rate_limited 429,
//                      busy 503 with Retry-After: 2, https_required 403. Then drains the re-key queue (R28).
//   POST vault/lock    locks this session ("Lock now", and the idle timer in vault.js).
//   POST vault/recover {code, passphrase, confirm}: the locked page's "Forgot passphrase?" flow (R52), a personal
//                      recovery code and a new passphrase (RecoveryService::useCode: R15 order, its own buckets,
//                      ClientIp, roster agents refused, the re-key bounded and outside the Argon2 slot). The transport
//                      is checked first. ROTATED and PENDING are both success (R33): the user then unlocks with the
//                      new passphrase. GET vault?recover=1 shows its form instead of the unlock form.
//
// The locked page offers the hardware-key unlock (vault-webauthn.js, HardwareKeyController::unlock) when the user
// has keys. When an admin requires hardware keys and the user has fewer than two, an unlocked visit goes to the
// hardware-key page (spec: Hardware keys → Enrolment).
//
// A passphrase only ever arrives in a POST body. The forms post to their endpoints natively too (fix C1), so they
// work without vault.js: success and failure then redirect to the page, with only a reason code in the URL. On
// plain HTTP off the dev localhost both POSTs refuse with https_required before any Argon2 work, and the page says
// so up front.
class VaultController extends BaseVaultController
{
    private bool $recovering = false;

    public function index(): void
    {
        $this->handle(function (): void {
            $userId = $this->userId();
            $session = $this->vaultSession();
            $client = $this->clientConfig();
            // A native form POST comes back here with a fixed reason code; anything else shows nothing.
            $params = [
                'title' => t('Vault'),
                'client' => $client,
                'https_ok' => $session->transportAllowed(),
                'error' => $this->codeMessage('vault_error', $client['messages']),
            ];
            if ($this->principals()->get($userId) === null) {
                $template = 'enrol';
                $params['policy'] = (string) (new VaultSettings($this->container))->get(VaultSettings::POLICY);
            } else {
                // R18: the session's key is fetched before any vault lock; the shell carries no secret, so it is wiped.
                $sk = $session->secretKey();
                $policy = (string) (new VaultSettings($this->container))->get(VaultSettings::POLICY);
                if ($sk === null) {
                    $template = 'locked';
                    $params['hw_keys'] = $this->hardwareKeys()->count($userId);
                    $params['codes_allowed'] = $policy !== VaultSettings::POLICY_NONE;
                    $params['recover'] = $params['codes_allowed'] && $this->request->getStringParam('recover') === '1';
                    $notice = $this->request->getStringParam('vault_notice');
                    $params['notice'] = in_array($notice, ['recovered', 'recovered_pending'], true) ? $client['messages'][$notice] : '';
                } else {
                    sodium_memzero($sk);
                    if ($this->hardwareKeys()->enrolmentRequired($userId)) {
                        $this->redirectTo(['HardwareKeyController', 'index'], []);
                        return;
                    }
                    $template = 'shell';
                    $params['notices'] = (new RecoveryService($this->container))->takeNotices($userId);
                    $params['hw_rotate'] = $this->hardwareKeys()->rotationQueued($userId);
                    $params['failed_attempts'] = $this->principals()->failedAttemptsSinceLastUnlock($userId);
                    $params['agents_available'] = AgentRoster::of($this->container)->available();
                    $max = (int) (new VaultSettings($this->container))->get('vault_share_max_expiry');
                    $params['share_expiries'] = array_keys(array_filter(ShareModel::EXPIRIES, static fn (int $s): bool => $s <= $max));
                }
            }
            $this->respond()->html($this->helper->layout->app('Vault:vault/'.$template, $params));
        });
    }

    public function unlock(): void
    {
        $this->handle(function (): void {
            $this->requirePostCsrf();
            $userId = $this->userId();
            $sessionKey = $this->unlockService()->unlock($userId, (string) $this->request->getRawValue('passphrase'), $this->clientIp());
            // The cookie reaches the next request only, so this one opens the session with the key just issued.
            $sk = $this->vaultSession()->secretKey($sessionKey);
            sodium_memzero($sessionKey);
            if ($sk !== null) {
                try {
                    $this->housekeeping()->afterUnlock($userId, $sk);
                } finally {
                    sodium_memzero($sk);
                }
            }
            $this->succeed();
        });
    }

    public function enrol(): void
    {
        $this->handle(function (): void {
            $this->requirePostCsrf();
            if (! $this->vaultSession()->transportAllowed()) {
                throw new VaultException('https_required');
            }
            $passphrase = (string) $this->request->getRawValue('passphrase');
            if (! hash_equals($passphrase, (string) $this->request->getRawValue('confirm'))) {
                throw new VaultException('passphrase_mismatch');
            }
            $userId = $this->userId();
            $this->principals()->enrolHuman($userId, $passphrase);
            $sessionKey = $this->unlockService()->unlock($userId, $passphrase, $this->clientIp());
            sodium_memzero($sessionKey);
            $this->succeed();
        });
    }

    // R52: the locked page's recovery-code flow. Never needs an unlocked session; a passphrase or code only ever
    // arrives in a POST body, and a native form POST comes back as a redirect carrying a fixed code only.
    public function recover(): void
    {
        $this->recovering = true;
        $this->handle(function (): void {
            $this->requirePostCsrf();
            $this->requireTransport();
            $passphrase = (string) $this->request->getRawValue('passphrase');
            if (! hash_equals($passphrase, (string) $this->request->getRawValue('confirm'))) {
                throw new VaultException('passphrase_mismatch');
            }
            $result = $this->recoveryService()->useCode($this->userId(), (string) $this->request->getRawValue('code'), $passphrase, $this->clientIp());
            $pending = $result === RotationService::PENDING;
            $this->succeed(['rotation' => $pending ? 'pending' : 'done'], $pending ? 'recovered_pending' : 'recovered');
        });
    }

    public function lock(): void
    {
        $this->handle(function (): void {
            $this->requirePostCsrf();
            $session = $this->vaultSession();
            $sidHash = $session->sidHash();
            if ($sidHash !== null) {
                $session->lock($this->userId(), $sidHash);
            }
            $this->succeed();
        });
    }

    // A failed native recovery POST goes back to the recovery form, not the unlock form.
    protected function failParams(): array
    {
        return $this->recovering ? ['recover' => '1'] : [];
    }

    private function unlockService(): UnlockService
    {
        return isset($this->container['vaultUnlock']) ? $this->container['vaultUnlock'] : new UnlockService($this->container);
    }
}
