<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultFailure;
use Kanboard\Plugin\Vault\Model\VaultSettings;

// "My vault security" (R40), for the logged-in user with an unlocked vault (spec: Key rotation, Recovery).
//
//   GET  vault/security        the page: change passphrase, Rotate my keys, and (when the policy allows codes) a
//                              personal recovery code. Locked: back to the Vault page.
//   POST vault/passphrase      {current, passphrase, confirm}: PrincipalModel::changePassphrase.
//   POST vault/rotate          {passphrase}: RotationService::requestManual (same passphrase, new keypair).
//   POST vault/recovery-code   RecoveryService::createCode: {ok, code}, shown once by vault-security.js, which
//                              asks for group 3 back before it clears the code from the page.
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
            ]));
        });
    }

    public function passphrase(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
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
        $this->withKey(function (int $userId, string $sk): void {
            $this->requireTransport();
            $result = $this->rotationService()->requestManual($userId, $sk, (string) $this->request->getRawValue('passphrase'), $this->clientIp());
            $this->ceremonyDone($result, 'keys');
        });
    }

    // The code is answered as JSON only (it never goes into a URL or the page HTML), with no-store like every
    // Vault response; the page's button is the only way to ask for it.
    public function recoveryCode(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $this->answer(['code' => $this->recoveryService()->createCode($userId, $sk)]);
        });
    }

    protected function returnRoute(): array
    {
        return ['SecurityController', 'index'];
    }

    private function requireTransport(): void
    {
        if (! $this->vaultSession()->transportAllowed()) {
            throw new VaultException('https_required');
        }
    }

    private function ceremonyDone(string $result, string $ceremony): void
    {
        $policy = (string) (new VaultSettings($this->container))->get(VaultSettings::POLICY);
        $out = VaultFailure::rotationResult($result, $policy, $ceremony);
        unset($out['ok']);
        $this->succeed($out, $result === RotationService::PENDING ? 'rotation_pending' : 'rotated');
    }
}
