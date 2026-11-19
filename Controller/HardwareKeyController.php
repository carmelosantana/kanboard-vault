<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\HardwareKeys;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultFailure;
use Kanboard\Plugin\Vault\Model\VaultSettings;

// Hardware keys, WebAuthn PRF (spec: Hardware keys; UI). vault-webauthn.js runs the browser side; every endpoint is a
// POST with the CSRF token in the hardened handler, the IP from ClientIp (R21), failures as VaultFailure's fixed
// reasons. WebAuthn needs JavaScript, so these endpoints have no native-form fallback: without vault.js the page says
// so and nothing is posted.
//
//   GET  vault/hwkeys             the page (unlocked): the keys, add a key, remove one, rotate with every key. The one
//                                 page open while an admin requires keys and the user has fewer than two.
//   POST vault/hwkeys/challenge   {purpose}: a single-use challenge (base64url) for register|ceremony (unlocked) or
//                                 unlock (the locked page: a logged-in user), with the rp_id, the user's credential
//                                 ids and PRF salts, and for register the user handle, the new key's PRF salt and the
//                                 ids to exclude. Nothing secret.
//   POST vault/hwkeys/register    {label, passphrase, create, assert, others}: HardwareKeys::registerKey.
//   POST vault/hwkeys/remove      {credential_id, assertion, passphrase}: HardwareKeys::removeKey.
//   POST vault/hwkeys/rotate      {passphrase, new_passphrase, confirm, assertions}: HardwareKeys::rotate; ROTATED and
//                                 PENDING are both success (R33).
//   POST vault/hwkeys/unlock      {passphrase, assertion}: UnlockService::unlock with the key (the locked page).
class HardwareKeyController extends BaseVaultController
{
    public function index(): void
    {
        $this->handle(function (): void {
            $sk = $this->requireUnlocked();
            sodium_memzero($sk);
            $userId = $this->userId();
            $hw = $this->hardwareKeys();
            $client = $this->clientConfig();
            try {
                $rp = $hw->rpBinding();
                $rpError = '';
            } catch (VaultException $e) {
                $rp = null;
                $rpError = $client['messages'][$e->errorCode()] ?? $client['messages']['failed'];
            }
            $this->respond()->html($this->helper->layout->app('Vault:vault/hwkeys', [
                'title' => t('Hardware keys'),
                'client' => $client,
                'https_ok' => $this->vaultSession()->transportAllowed(),
                'keys' => $hw->keys($userId),
                'rp' => $rp,
                'rp_error' => $rpError,
                'required' => (int) (new VaultSettings($this->container))->get('vault_hw_required') === 1,
                'enrolment_required' => $hw->enrolmentRequired($userId),
                'rotation_queued' => $hw->rotationQueued($userId),
            ]));
        });
    }

    public function challenge(): void
    {
        $this->handle(function (): void {
            $this->requirePostCsrf();
            $purpose = (string) $this->request->getRawValue('purpose');
            if (! in_array($purpose, HardwareKeys::PURPOSES, true)) {
                throw new VaultException('payload_invalid');
            }
            if ($purpose !== 'unlock') {
                $sk = $this->requireUnlocked();
                sodium_memzero($sk);
            }
            $userId = $this->userId();
            $hw = $this->hardwareKeys();
            $challenge = $hw->challenge($userId, $purpose);
            $keys = $hw->keys($userId);
            $out = [
                'challenge' => HardwareKeys::b64u($challenge),
                'rp_id' => $hw->rpBinding()['rp_id'],
                'credentials' => array_map(static fn (array $k): array => [
                    'id' => $k['credential_id'],
                    'label' => $k['label'],
                    'prf_salt' => HardwareKeys::b64u((string) base64_decode($k['prf_salt'], true)),
                ], $keys),
            ];
            if ($purpose === 'register') {
                $user = $this->userModel->getById($userId);
                $out += [
                    'rp_name' => 'Kanboard Vault',
                    'user_handle' => HardwareKeys::b64u(sodium_crypto_generichash('vault-user:'.$userId, '', 16)),
                    'user_name' => (string) ($user['username'] ?? ''),
                    'prf_salt' => HardwareKeys::b64u(HardwareKeys::prfSaltFor($challenge)),
                ];
            }
            $this->answer($out);
        });
    }

    public function register(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $this->requireTransport();
            $this->hardwareKeys()->registerKey($userId, $sk, [
                'label' => (string) $this->request->getRawValue('label'),
                'create' => HardwareKeys::parseRegistration((string) $this->request->getRawValue('create')),
                'assert' => HardwareKeys::parseAssertion((string) $this->request->getRawValue('assert')),
                'others' => HardwareKeys::parseAssertions((string) $this->request->getRawValue('others')),
            ], (string) $this->request->getRawValue('passphrase'), $this->clientIp());
            $this->answer([]);
        });
    }

    public function remove(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $this->requireTransport();
            $raw = (string) $this->request->getRawValue('assertion');
            $this->hardwareKeys()->removeKey(
                $userId,
                (string) $this->request->getRawValue('credential_id'),
                $raw === '' ? [] : HardwareKeys::parseAssertion($raw),
                $sk,
                (string) $this->request->getRawValue('passphrase'),
                $this->clientIp()
            );
            $this->answer([]);
        });
    }

    public function rotate(): void
    {
        $this->withKey(function (int $userId, string $sk): void {
            $this->requireTransport();
            $new = (string) $this->request->getRawValue('new_passphrase');
            if (! hash_equals($new, (string) $this->request->getRawValue('confirm'))) {
                throw new VaultException('passphrase_mismatch');
            }
            $result = $this->hardwareKeys()->rotate($userId, $sk, (string) $this->request->getRawValue('passphrase'), $new, HardwareKeys::parseAssertions((string) $this->request->getRawValue('assertions')), $this->clientIp());
            $out = VaultFailure::rotationResult($result, (string) (new VaultSettings($this->container))->get(VaultSettings::POLICY), $new === '' ? 'keys' : 'passphrase');
            unset($out['ok']);
            $this->answer($out);
        });
    }

    public function unlock(): void
    {
        $this->handle(function (): void {
            $this->requirePostCsrf();
            $userId = $this->userId();
            $raw = (string) $this->request->getRawValue('assertion');
            $assertion = HardwareKeys::parseAssertion($raw);
            $sessionKey = $this->unlockService()->unlock($userId, (string) $this->request->getRawValue('passphrase'), $this->clientIp(), $assertion);
            $sk = $this->vaultSession()->secretKey($sessionKey);
            sodium_memzero($sessionKey);
            if ($sk !== null) {
                try {
                    $this->housekeeping()->afterUnlock($userId, $sk);
                } finally {
                    sodium_memzero($sk);
                }
            }
            $this->answer([]);
        });
    }

    protected function hwEnrolmentExempt(): bool
    {
        return true;
    }

    protected function returnRoute(): array
    {
        return ['HardwareKeyController', 'index'];
    }

    private function unlockService(): UnlockService
    {
        return isset($this->container['vaultUnlock']) ? $this->container['vaultUnlock'] : new UnlockService($this->container);
    }
}
