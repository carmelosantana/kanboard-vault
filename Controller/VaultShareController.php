<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Core\Http\Response;
use Kanboard\Plugin\Vault\Model\ShareModel;
use Kanboard\Plugin\Vault\Model\UaFamily;
use Kanboard\Plugin\Vault\Model\VaultException;

// One-time shares over HTTP (spec: One-time shares). Two actions are public (Role::APP_PUBLIC, Plugin.php): anyone
// with the link may open the page and reveal. The rest need a Kanboard login and an unlocked vault.
//
//   GET  show      the static shell. It never reads or looks up the id: the page is the same for real, burned and
//                  fake ids apart from Kanboard's per-session CSRF token, and viewing it burns nothing. vault-reveal.js
//                  (T18) reads the id from the query string and k ‖ b from the #fragment, which never reaches here.
//   POST reveal    {id, b, csrf_token} → {ok, ciphertext, iv, salt, has_passphrase, expires_at} or, for every failure
//                  of the share itself, 404 {ok:false, reason:not_available}. A secure transport is required
//                  (ClientIp::secureTransport, R41; the opted-in dev localhost, R20). Throttled per client IP
//                  (ClientIp::resolve, R21): 429 rate_limited.
//   POST reserve   {expiry: 1h|1d|7d}           → {share_id, expires_at}, bound to this user and PHP session.
//   POST create    {share_id, ciphertext, iv, salt, has_passphrase, burn_hash, label} → {}; consumes the reservation.
//   POST revoke    {id_hash}                    → {}
//   POST mine      → {links: [{id_hash, label, has_passphrase, created_at, expires_at}]}
//
// Every answer of this controller carries the public headers (no-store, Referrer-Policy no-referrer, X-Robots-Tag
// noindex, XFO DENY, frame-ancestors 'none') and every POST is answered with JSON: the page has no native form, since
// b lives in the fragment and only script can send it.
class VaultShareController extends BaseVaultController
{
    public function show(): void
    {
        $this->handle(function (): void {
            $this->respond()->html($this->template->render('Vault:share/show', [
                'csrf' => $this->token->getReusableCSRFToken(),
                'reveal_url' => $this->helper->url->to('VaultShareController', 'reveal', ['plugin' => 'Vault']),
                'https_ok' => $this->vaultSession()->transportAllowed(),
            ]));
        });
    }

    public function reveal(): void
    {
        $this->handle(function (): void {
            $this->requirePostCsrf();
            $this->requireTransport();
            $data = $this->shares()->reveal($this->stringParam('id'), $this->stringParam('b'), $this->clientIp(), UaFamily::fromRequest($this->request));
            if ($data === null) {
                $this->respond()->json(['ok' => false, 'reason' => 'not_available'], 404);
                return;
            }
            $this->answer($data);
        });
    }

    public function reserve(): void
    {
        $this->withKey(function (int $userId): void {
            $expiry = $this->stringParam('expiry');
            $this->answer($this->shares()->reserve($userId, $this->sidHash(), $expiry === '' ? '1d' : $expiry));
        });
    }

    public function create(): void
    {
        $this->withKey(function (int $userId): void {
            $body = [];
            foreach (['share_id', 'ciphertext', 'iv', 'salt', 'has_passphrase', 'burn_hash', 'label'] as $field) {
                $body[$field] = $this->request->getRawValue($field) ?? '';
            }
            $this->shares()->finalize($userId, $this->sidHash(), $body);
            $this->answer([]);
        });
    }

    public function revoke(): void
    {
        $this->withKey(function (int $userId): void {
            $this->shares()->revoke($userId, $this->stringParam('id_hash'));
            $this->answer([]);
        });
    }

    public function mine(): void
    {
        $this->withKey(function (int $userId, #[\SensitiveParameter] string $sk): void {
            $this->answer(['links' => $this->shares()->listMine($userId, $sk)]);
        });
    }

    protected function respond(): Response
    {
        return parent::respond()
            ->withHeader('Referrer-Policy', 'no-referrer')
            ->withHeader('X-Robots-Tag', 'noindex, nofollow');
    }

    // POSTs always answer JSON (vault-reveal.js and vault-onetime.js); the page keeps the generic error page.
    protected function fail(int $status, string $reason): void
    {
        if (! $this->request->isPost()) {
            parent::fail($status, $reason);
            return;
        }
        $this->respond()->json(['ok' => false, 'reason' => $reason], $status);
    }

    // A POST field as a string; '' when absent or not a string (an array can't become a different answer).
    private function stringParam(string $name): string
    {
        $v = $this->request->getRawValue($name);
        return is_string($v) ? $v : '';
    }

    private function sidHash(): string
    {
        $sid = $this->vaultSession()->sidHash();
        if ($sid === null) {
            throw new VaultException('locked');
        }
        return $sid;
    }

    private function shares(): ShareModel
    {
        return isset($this->container['vaultShares']) ? $this->container['vaultShares'] : new ShareModel($this->container);
    }
}
