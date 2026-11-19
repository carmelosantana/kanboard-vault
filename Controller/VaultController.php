<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultException;
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
            $code = $this->request->getStringParam('vault_error');
            $params = [
                'title' => t('Vault'),
                'client' => $client,
                'https_ok' => $session->transportAllowed(),
                'error' => $code !== '' && $code !== 'working' && isset($client['messages'][$code]) ? $client['messages'][$code] : '',
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

    // What vault.js reads from #vault-app: the CSRF token, the endpoint URLs, the idle timeout and the messages.
    /** @return array{csrf:string, endpoints:array<string,string>, idle_ms:int, messages:array<string,string>} */
    private function clientConfig(): array
    {
        $url = fn (string $action, string $controller = 'VaultController'): string => $this->helper->url->to($controller, $action, ['plugin' => 'Vault']);
        $endpoints = ['unlock' => $url('unlock'), 'lock' => $url('lock'), 'enrol' => $url('enrol')];
        foreach (['tree', 'list', 'entry', 'field', 'save', 'move', 'delete'] as $action) {
            $endpoints[$action] = $url($action, 'EntryController');
        }
        return [
            'csrf' => $this->token->getReusableCSRFToken(),
            'endpoints' => $endpoints,
            'idle_ms' => $this->vaultSession()->idleTimeout() * 1000,
            'messages' => [
                'working' => t('Working…'),
                'unlock_failed' => t('Unlock failed.'),
                'rate_limited' => t('Too many attempts. Wait a while, then try again.'),
                'busy' => t('The server is busy. Try again in a few seconds.'),
                'https_required' => t('Vault needs HTTPS. Open Kanboard over https:// to use it.'),
                'passphrase_mismatch' => t('The passphrases don\'t match.'),
                'passphrase_weak' => t('Use at least %d characters, and not your username.', PrincipalModel::MIN_PASSPHRASE_CHARS),
                'passphrase_reuse' => t('Don\'t reuse your Kanboard login password.'),
                'already_enrolled' => t('Your vault is already set up. Reload the page.'),
                'forbidden' => t('The page expired. Reload it and try again.'),
                'failed' => t('Something went wrong. Try again.'),
                'locked' => t('Your vault is locked.'),
                'not_found' => t('Not found, or you no longer have access.'),
                'conflict' => t('This entry was changed elsewhere. Reload it, then edit again.'),
                'payload_invalid' => t('Some values are not valid.'),
                'payload_too_large' => t('This entry is too large.'),
                'invalid_move' => t('It can\'t be moved there.'),
                'integrity_error' => t('This item can\'t be decrypted.'),
                'copied' => t('Copied — clears in 30 s'),
                'saved' => t('Saved.'),
                'confirm_delete' => t('Delete this for everyone it is shared with? This can\'t be undone.'),
                'group_name' => t('Group name'),
                'no_entries' => t('No entries.'),
                'shared_entries' => t('Entries shared with me'),
                'from' => t('from'),
            ],
        ];
    }

    private function unlockService(): UnlockService
    {
        return isset($this->container['vaultUnlock']) ? $this->container['vaultUnlock'] : new UnlockService($this->container);
    }

    private function principals(): PrincipalModel
    {
        return isset($this->container['vaultPrincipals']) ? $this->container['vaultPrincipals'] : new PrincipalModel($this->container);
    }
}
