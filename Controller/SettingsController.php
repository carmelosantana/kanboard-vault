<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\ClientIp;
use Kanboard\Plugin\Vault\Model\DeploymentChecks;
use Kanboard\Plugin\Vault\Model\VaultSettings;

// Settings → Vault (spec: Admin settings), for Kanboard app admins only. Anyone else gets the generic forbidden
// answer through the hardened handler, on the page and on save alike.
//
//   GET  vault/settings        the form, the effective idle cap, the bound rp_id and origin (read-only, from
//                              Kanboard's Application URL), the deployment checks and the integrity faults.
//   POST vault/settings/save   the form (CSRF). Only the keys in FIELDS are read; anything else posted (rp_id,
//                              application_url, …) is ignored. Every value is validated first, so one bad value
//                              refuses the whole form; then each changed setting is written through VaultSettings::set,
//                              which audits one policy_change per change, and routes the recovery policy through
//                              RecoveryService::setPolicy (T9: never Kanboard's generic config save).
//
// There is no "view vault" or "reset user" action here, and org recovery stays CLI only.
class SettingsController extends BaseVaultController
{
    public const FIELDS = [
        VaultSettings::POLICY,
        'vault_hw_required',
        'vault_idle_timeout',
        'vault_share_max_expiry',
        'vault_reveal_limit',
        'vault_agent_cap_max',
        'vault_audit_retention_days',
        'vault_trusted_proxy_cidrs',
    ];

    public function index(): void
    {
        $this->handle(function (): void {
            $this->requireAdmin();
            $settings = new VaultSettings($this->container);
            $values = [];
            foreach (self::FIELDS as $key) {
                $values[$key] = $settings->get($key);
            }
            $session = $this->vaultSession();
            $messages = self::messages();
            $this->respond()->html($this->helper->layout->config('Vault:config/vault', [
                'title' => t('Vault settings'),
                'vault' => $values,
                'csrf' => $this->token->getReusableCSRFToken(),
                'effective_idle' => intdiv($session->idleTimeout(), 60),
                'session_minutes' => intdiv($session->sessionLifetimeSeconds(), 60),
                'relying_party' => VaultSettings::relyingParty((string) $this->configModel->get('application_url')),
                'checks' => (new DeploymentChecks($this->container))->run($this->request),
                'mapped_cidrs' => array_values(array_filter($settings->trustedProxies(), [ClientIp::class, 'isMappedCidr'])),
                'integrity' => AuditModel::of($this->container)->integrityFaults($this->userId()),
                'share_expiries' => VaultSettings::SHARE_EXPIRIES,
                'error' => $this->codeMessage('vault_error', $messages),
                'saved' => $this->request->getStringParam('vault_notice') === 'saved',
            ]));
        });
    }

    public function save(): void
    {
        $this->handle(function (): void {
            $this->requireAdmin();
            $this->requirePostCsrf();
            $settings = new VaultSettings($this->container);
            $changes = [];
            foreach (self::FIELDS as $key) {
                $raw = $this->request->getRawValue($key);
                if ($raw === null) {
                    continue;
                }
                $value = VaultSettings::normalize($key, $raw);
                if ($value !== VaultSettings::normalize($key, $settings->get($key))) {
                    $changes[$key] = $value;
                }
            }
            foreach ($changes as $key => $value) {
                $settings->set($key, $value, $this->userId());
            }
            $this->succeed([], 'saved');
        });
    }

    protected function returnRoute(): array
    {
        return ['SettingsController', 'index'];
    }
}
