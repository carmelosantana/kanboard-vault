<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Controller\BaseController;
use Kanboard\Core\Http\Response;
use InvalidArgumentException;
use Kanboard\Plugin\Vault\Model\ClientIp;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultFailure;
use Kanboard\Plugin\Vault\Model\VaultSession;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Throwable;

// What every Vault controller shares (spec: UI → Assets and headers, Secrets never go into the HTML).
//
//   respond()          every Vault response goes through it: X-Frame-Options DENY, this response's own CSP (a copy
//                      of cspRules plus frame-ancestors 'none'; the app-wide rules are never changed) and
//                      Cache-Control no-store.
//   requirePostCsrf()  state changes and secret-returning requests are POSTs carrying Kanboard's CSRF token.
//   requireUnlocked()  the session's sk (sk2 while a rotation runs), or the locked view / a JSON "locked". It is
//                      called before any vault lock is taken (R18).
//   handle()           runs every action, the page included: the opportunistic purge first, then the action; any
//                      failure goes to fail() with VaultFailure::map's fixed reason (no stack, no detail; T6/R28).
//   succeed()/fail()   answer vault.js (X-Requested-With) with JSON, and a native form POST (no JS) with a redirect
//                      to the page that carries only a reason code, so a passphrase never reaches a URL (fix C1).
//   clientIp()         ClientIp::resolve with the admin's trusted proxies, never Request::getIpAddress() (R21).
//
// Controllers expose Rekeyer::drainQueue only (through Housekeeping); Rekeyer::rekey, which re-keys an object that
// isn't queued, is never reachable from a request (T7).
abstract class BaseVaultController extends BaseController
{
    protected function respond(): Response
    {
        $rules = $this->container['cspRules'];
        $rules['frame-ancestors'] = "'none'";
        return $this->response
            ->withXframe()
            ->withContentSecurityPolicy($rules)
            ->withHeader('Cache-Control', 'no-store')
            ->withoutCache();
    }

    protected function requirePostCsrf(): void
    {
        if (! $this->request->isPost() || ! $this->token->validateReusableCSRFToken($this->request->getRawValue('csrf_token'))) {
            $this->fail(403, 'forbidden');
            throw new ResponseSent();
        }
    }

    protected function requireUnlocked(): string
    {
        $sk = $this->vaultSession()->secretKey();
        if ($sk !== null) {
            return $sk;
        }
        if ($this->request->isAjax()) {
            $this->fail(401, 'locked');
        } else {
            // A locked vault always goes back to the Vault page (its unlock form), never to returnRoute().
            $this->redirectTo(['VaultController', 'index'], []);
        }
        throw new ResponseSent();
    }

    // Requests that create or return a long-lived secret (a passphrase, a recovery code, an agent's vault key) need HTTPS,
    // or the opted-in dev localhost, as unlock does.
    protected function requireTransport(): void
    {
        if (! $this->vaultSession()->transportAllowed()) {
            throw new VaultException('https_required');
        }
    }

    // Admin settings are for Kanboard app admins only. Anyone else gets the generic forbidden answer, hardened.
    protected function requireAdmin(): void
    {
        if (! $this->userSession->isAdmin()) {
            $this->fail(403, 'forbidden');
            throw new ResponseSent();
        }
    }

    // Every Vault action, the page included (fix I1), runs here: the opportunistic purge, then the action. Any
    // exception becomes fail() with VaultFailure's fixed reason: never the message, never Kanboard's bare error page.
    protected function handle(callable $action): void
    {
        try {
            $this->housekeeping()->purge();
            $action();
        } catch (ResponseSent) {
        } catch (Throwable $e) {
            [$status, $reason] = VaultFailure::map($e);
            if ($reason === 'failed') {
                $this->logger->warning('Vault: a request failed ('.get_class($e).')');
            }
            $this->fail($status, $reason);
        }
    }

    // The success answer of a POST: {ok: true} (plus $data) to vault.js, or back to the page for a native form POST
    // (fix C1), carrying only the fixed $notice code.
    protected function succeed(array $data = [], ?string $notice = null): void
    {
        if ($this->request->isAjax()) {
            $this->respond()->json(['ok' => true] + $data);
        } else {
            $this->redirectToPage($notice === null ? [] : ['vault_notice' => $notice]);
        }
    }

    // A failure, hardened like every Vault response.
    //   vault.js (X-Requested-With): JSON {ok: false, reason}, with Retry-After on 503.
    //   A native form POST (no JS, fix C1): a redirect to the page carrying only the fixed reason code, so the
    //     browser never re-sends the form and nothing but the code reaches the URL, a log or the Referer.
    //   A native GET (the page itself, fix I1): a minimal generic error page.
    protected function fail(int $status, string $reason): void
    {
        if ($this->request->isAjax()) {
            $response = $this->respond();
            if ($status === 503) {
                $response->withHeader('Retry-After', (string) VaultFailure::RETRY_AFTER);
            }
            $response->json(['ok' => false, 'reason' => $reason], $status);
        } elseif ($this->request->isPost()) {
            $this->redirectToPage(['vault_error' => $reason]);
        } else {
            $this->respond()->html('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Vault</title></head><body><p>'
                .htmlspecialchars(t('Something went wrong. Try again.'), ENT_QUOTES, 'UTF-8').'</p></body></html>', $status);
        }
    }

    // The page a native form POST of this controller returns to: [controller, action].
    protected function returnRoute(): array
    {
        return ['VaultController', 'index'];
    }

    private function redirectToPage(array $codes = []): void
    {
        $this->redirectTo($this->returnRoute(), $codes);
    }

    private function redirectTo(array $route, array $codes): void
    {
        $this->respond()->withStatusCode(303)->redirect($this->helper->url->to($route[0], $route[1], ['plugin' => 'Vault'] + $codes));
    }

    // A fixed code from the query string ($param), shown only when $known has a message for it; '' otherwise.
    protected function codeMessage(string $param, array $known): string
    {
        $code = $this->request->getStringParam($param);
        return $code !== '' && $code !== 'working' && isset($known[$code]) ? (string) $known[$code] : '';
    }

    // What vault.js reads from #vault-app: the CSRF token, the endpoint URLs, the idle timeout and the messages.
    /** @return array{csrf:string, endpoints:array<string,string>, idle_ms:int, messages:array<string,string>} */
    protected function clientConfig(): array
    {
        $url = fn (string $action, string $controller = 'VaultController'): string => $this->helper->url->to($controller, $action, ['plugin' => 'Vault']);
        $endpoints = ['unlock' => $url('unlock'), 'lock' => $url('lock'), 'enrol' => $url('enrol')];
        foreach (['tree', 'list', 'entry', 'field', 'save', 'move', 'delete'] as $action) {
            $endpoints[$action] = $url($action, 'EntryController');
        }
        foreach (['sharing', 'grant', 'revoke', 'activity'] as $action) {
            $endpoints[$action] = $url($action, 'ShareGrantController');
        }
        $endpoints += ['passphrase' => $url('passphrase', 'SecurityController'), 'rotate' => $url('rotate', 'SecurityController'), 'recovery_code' => $url('recoveryCode', 'SecurityController')];
        $endpoints += ['agent_enrol' => $url('enrol', 'VaultAgentController'), 'agent_reenrol' => $url('reenrol', 'VaultAgentController'), 'agent_cap' => $url('cap', 'VaultAgentController')];
        return [
            'csrf' => $this->token->getReusableCSRFToken(),
            'endpoints' => $endpoints,
            'idle_ms' => $this->vaultSession()->idleTimeout() * 1000,
            'messages' => self::messages(),
        ];
    }

    /** @return array<string,string> */
    protected static function messages(): array
    {
        return [
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
            'not_enrolled' => t('They haven\'t set up their vault yet.'),
            'agent_read_only' => t('Agents can only be given Read access.'),
            'shared' => t('Shared.'),
            'rotation_in_progress' => t('A key rotation is still finishing. Lock and unlock your vault, then try again.'),
            'rotation_needs_factors' => t('Your hardware keys must take part in this change. Use the hardware key settings instead.'),
            'policy_forbids' => t('Your organisation\'s recovery policy doesn\'t allow this.'),
            'passphrase_changed' => t('Your passphrase is changed.'),
            'keys_rotated' => t('Your keys are rotated.'),
            'rotation_pending' => t('Done. Re-encrypting your vault finishes at your next unlock.'),
            'confirm_new_code' => t('This replaces your current recovery code, if you have one. Continue?'),
            'code_group_mismatch' => t('That isn\'t group 3 of the code. Check what you wrote down.'),
            'code_saved' => t('Recovery code saved. Keep it somewhere safe and offline.'),
            'owner_not_enrolled' => t('Set up your own vault first.'),
            'agents_unavailable' => t('The Agents plugin is not installed.'),
            'confirm_reenrol' => t('Re-enrol this agent? Its current vault key stops working, and what other people shared with it is unshared.'),
            'key_shown' => t('Copy this key into the agent\'s settings now. It won\'t be shown again.'),
            'key_cleared' => t('The key is cleared from this page.'),
        ];
    }

    protected function principals(): PrincipalModel
    {
        return isset($this->container['vaultPrincipals']) ? $this->container['vaultPrincipals'] : new PrincipalModel($this->container);
    }

    protected function rotationService(): RotationService
    {
        return isset($this->container['vaultRotation']) ? $this->container['vaultRotation'] : new RotationService($this->container);
    }

    protected function recoveryService(): RecoveryService
    {
        return isset($this->container['vaultRecovery']) ? $this->container['vaultRecovery'] : new RecoveryService($this->container);
    }

    // POST + CSRF, then the unlocked session's key (fetched before any vault lock, R18), wiped whatever happens.
    protected function withKey(callable $action): void
    {
        $this->handle(function () use ($action): void {
            $this->requirePostCsrf();
            $sk = $this->requireUnlocked();
            try {
                $action($this->userId(), $sk);
            } finally {
                sodium_memzero($sk);
            }
        });
    }

    protected function answer(array $data): void
    {
        $this->respond()->json(['ok' => true] + $data);
    }

    // entry or group; anything else is the generic failure (T6 minor).
    protected function type(): string
    {
        $type = (string) $this->request->getRawValue('type');
        if (! in_array($type, ObjectStore::TYPES, true)) {
            throw new InvalidArgumentException('Vault: unknown object type');
        }
        return $type;
    }

    // A decimal id, or null when absent or empty (a top-level group). Anything else matches no object.
    protected function intParam(string $name): ?int
    {
        $raw = $this->request->getRawValue($name);
        if ($raw === null || $raw === '') {
            return null;
        }
        if (is_int($raw)) {
            return max(0, $raw);
        }
        return is_string($raw) && ctype_digit($raw) && strlen($raw) < 16 ? (int) $raw : 0;
    }

    protected function userName(int $userId): string
    {
        $user = $this->userModel->getById($userId);
        if (! $user) {
            return '';
        }
        return (string) ($user['name'] !== '' && $user['name'] !== null ? $user['name'] : $user['username']);
    }

    protected function store(): ObjectStore
    {
        return isset($this->container['vaultStore']) ? $this->container['vaultStore'] : new ObjectStore($this->container);
    }

    protected function grants(): GrantModel
    {
        return isset($this->container['vaultGrants']) ? $this->container['vaultGrants'] : new GrantModel($this->container);
    }

    protected function clientIp(): string
    {
        return (new ClientIp($this->container))->resolve($this->request, (new VaultSettings($this->container))->trustedProxies());
    }

    protected function vaultSession(): VaultSession
    {
        return isset($this->container['vaultSession']) ? $this->container['vaultSession'] : new VaultSession($this->container);
    }

    protected function housekeeping(): Housekeeping
    {
        return isset($this->container['vaultHousekeeping']) ? $this->container['vaultHousekeeping'] : new Housekeeping($this->container);
    }

    protected function userId(): int
    {
        return (int) $this->userSession->getId();
    }
}
