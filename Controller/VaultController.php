<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\AgentRoster;
use Kanboard\Plugin\Vault\Model\RecoveryService;
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
//
// A passphrase only ever arrives in a POST body. The forms post to their endpoints natively too (fix C1), so they
// work without vault.js: success and failure then redirect to the page, with only a reason code in the URL. On
// plain HTTP off the dev localhost both POSTs refuse with https_required before any Argon2 work, and the page says
// so up front.
class VaultController extends BaseVaultController
{
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
                if ($sk === null) {
                    $template = 'locked';
                } else {
                    sodium_memzero($sk);
                    $template = 'shell';
                    $params['notices'] = (new RecoveryService($this->container))->takeNotices($userId);
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

    private function unlockService(): UnlockService
    {
        return isset($this->container['vaultUnlock']) ? $this->container['vaultUnlock'] : new UnlockService($this->container);
    }
}
