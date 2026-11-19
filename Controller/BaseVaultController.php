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
//   handle()           runs a JSON action: the opportunistic purge first, then the action; any failure becomes a
//                      JSON answer from VaultFailure::map (no stack, no detail; T6/R28), with the same headers.
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
            $this->respond()->json(['ok' => false, 'reason' => 'forbidden'], 403);
            throw new ResponseSent();
        }
    }

    protected function requireUnlocked(): string
    {
        $sk = $this->vaultSession()->secretKey();
        if ($sk !== null) {
            return $sk;
        }
        if ($this->request->isPost() || $this->request->isAjax()) {
            $this->respond()->json(['ok' => false, 'reason' => 'locked'], 401);
        } else {
            $this->respond()->redirect($this->helper->url->to('VaultController', 'index', ['plugin' => 'Vault']));
        }
        throw new ResponseSent();
    }

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
            $response = $this->respond();
            if ($status === 503) {
                $response->withHeader('Retry-After', (string) VaultFailure::RETRY_AFTER);
            }
            $response->json(['ok' => false, 'reason' => $reason], $status);
        }
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
