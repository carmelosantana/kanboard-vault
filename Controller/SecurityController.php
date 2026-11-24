<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\OrphanService;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultFailure;
use Kanboard\Plugin\Vault\Model\VaultSettings;

// "My vault security" (R40), for the logged-in user with an unlocked vault (spec: Key rotation, Recovery).
//
//   GET  vault/security        the page: change passphrase, Rotate my keys, and (when the policy allows codes) a
//                              personal recovery code; the user's own entries at risk of becoming an orphan
//                              (OrphanService::atRisk), by id with a link. Locked: back to the Vault page.
//   POST vault/passphrase      {current, passphrase, confirm}: PrincipalModel::changePassphrase.
//   POST vault/rotate          {passphrase}: RotationService::requestManual (same passphrase, new keypair).
//   POST vault/recovery-code   {passphrase[, assertion]}: re-proves the passphrase (R54; with hardware keys, together
//                              with a fresh assertion), then RecoveryService::createCode:
//                              {ok, code}, shown once by vault-security.js, which asks for group 3 back before it
//                              clears the code from the page.
//
// Every endpoint is a POST with the CSRF token, runs in the hardened handler with the unlocked session's key
// (withKey: fetched before any vault lock, wiped after) and the IP from ClientIp (R21), and answers failures with
// VaultFailure's fixed reasons. Errors before the rotation's start() commits are failures; after it the change has
// happened: ROTATED and PENDING are both successes (R33), and PENDING says the re-encryption finishes at the next
// unlock. The ceremony re-keys at most RotationService::CEREMONY_BATCHES batches in the request (T11 M1). A change
// drops the personal recovery code (R36), so the answer offers a new one when the policy allows codes.
// The passphrase forms also POST natively (fix C1): the answer is then a redirect to this page with a fixed code.
class SecurityController extends BaseVaultController
{
    // Notices a native POST of this page returns with (vault_notice).
    private const NOTICES = ['rotated', 'rotation_pending'];

    public function index(): void
    {
        $this->handle(function (): void {
            $sk = $this->requireUnlocked();
            sodium_memzero($sk);
            $this->page();
        });
    }

    // The page. $extra['code']: a recovery code just made by a native form POST, shown once.
    private function page(array $extra = []): void
    {
        $client = $this->clientConfig();
        $notice = $this->request->getStringParam('vault_notice');
        $policy = (string) (new VaultSettings($this->container))->get(VaultSettings::POLICY);
        $this->respond()->html($this->helper->layout->app('Vault:vault/security', [
            'title' => t('Vault security'),
            'client' => $client,
            'https_ok' => $this->vaultSession()->transportAllowed(),
            'error' => $this->codeMessage('vault_error', $client['messages']),
            'notice' => in_array($notice, self::NOTICES, true) ? $client['messages'][$notice === 'rotated' ? 'passphrase_changed' : 'rotation_pending'] : '',
            'codes_allowed' => $policy !== VaultSettings::POLICY_NONE,
            'hw_keys' => $this->hardwareKeys()->count($this->userId()),
            'code' => (string) ($extra['code'] ?? ''),
            'at_risk' => (new OrphanService($this->container))->atRisk($this->userId()),
        ]));
    }

    public function passphrase(): void
    {
        $this->withKey(function (int $userId, #[\SensitiveParameter] string $sk): void {
            $this->requireTransport();
            $new = (string) $this->request->getRawValue('passphrase');
            if (! hash_equals($new, (string) $this->request->getRawValue('confirm'))) {
                throw new VaultException('passphrase_mismatch');
            }
            $result = $this->principals()->changePassphrase($userId, (string) $this->request->getRawValue('current'), $new, $sk, $this->clientIp());
            $this->ceremonyDone($result, 'passphrase');
        });
    }

    public function rotate(): void
    {
        $this->withKey(function (int $userId, #[\SensitiveParameter] string $sk): void {
            $this->requireTransport();
            $result = $this->rotationService()->requestManual($userId, $sk, (string) $this->request->getRawValue('passphrase'), $this->clientIp());
            $this->ceremonyDone($result, 'keys');
        });
    }

    // R54: a recovery code is a lasting factor that bypasses hardware keys, so an unlocked session alone can't mint
    // one: the current passphrase is re-proved first, through the passphrase change's throttled check
    // (BaseVaultController::requireFreshReauth: R15 order, the IP bucket, back-off, the streak; with hardware keys a
    // fresh assertion too). Then the code. The policy is checked up front (no Argon2 for a refusal) and again inside createCode's transaction.
    // vault.js gets {ok, code}; a native form POST gets this page with the code shown once (no-store, never in a URL).
    public function recoveryCode(): void
    {
        $this->withKey(function (int $userId, #[\SensitiveParameter] string $sk): void {
            $this->requireTransport();
            if ((string) (new VaultSettings($this->container))->get(VaultSettings::POLICY) === VaultSettings::POLICY_NONE) {
                throw new VaultException('policy_forbids');
            }
            $this->requireFreshReauth($userId, $sk);
            $code = $this->recoveryService()->createCode($userId, $sk);
            if ($this->request->isAjax()) {
                $this->answer(['code' => $code]);
            } else {
                $this->page(['code' => $code]);
            }
        });
    }

    protected function returnRoute(): array
    {
        return ['SecurityController', 'index'];
    }

    private function ceremonyDone(string $result, string $ceremony): void
    {
        $policy = (string) (new VaultSettings($this->container))->get(VaultSettings::POLICY);
        $out = VaultFailure::rotationResult($result, $policy, $ceremony);
        unset($out['ok']);
        $this->succeed($out, $result === RotationService::PENDING ? 'rotation_pending' : 'rotated');
    }
}
