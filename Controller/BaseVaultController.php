<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Controller\BaseController;
use Kanboard\Core\Http\Response;
use Kanboard\Plugin\Vault\Model\ClientIp;
use Kanboard\Plugin\Vault\Model\Housekeeping;
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
            $this->redirectToPage();
        }
        throw new ResponseSent();
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

    // The success answer of a POST: {ok: true} to vault.js, or back to the page for a native form POST (fix C1).
    protected function succeed(): void
    {
        if ($this->request->isAjax()) {
            $this->respond()->json(['ok' => true]);
        } else {
            $this->redirectToPage();
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
            $this->redirectToPage($reason);
        } else {
            $this->respond()->html('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Vault</title></head><body><p>'
                .htmlspecialchars(t('Something went wrong. Try again.'), ENT_QUOTES, 'UTF-8').'</p></body></html>', $status);
        }
    }

    private function redirectToPage(?string $reason = null): void
    {
        $params = ['plugin' => 'Vault'] + ($reason === null ? [] : ['vault_error' => $reason]);
        $this->respond()->withStatusCode(303)->redirect($this->helper->url->to('VaultController', 'index', $params));
    }

    protected function clientIp(): string
    {
        $cidrs = (string) (new VaultSettings($this->container))->get('vault_trusted_proxy_cidrs');
        return (new ClientIp($this->container))->resolve($this->request, array_values(array_filter(explode(',', $cidrs))));
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
