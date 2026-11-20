<?php
namespace Kanboard\Plugin\Vault\Controller;

use Kanboard\Controller\BaseController;
use Kanboard\Core\Http\Response;
use InvalidArgumentException;
use Kanboard\Plugin\Vault\Model\ClientIp;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\HardwareKeys;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\SwitchedSessionGuard;
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
//                      called before any vault lock is taken (R18). While an admin requires hardware keys and the
//                      user has fewer than two, only the hardware-key page is open (hw_enrolment_required, or a
//                      redirect there): spec, Hardware keys → Enrolment. While a Steward switch-user session is
//                      active the session locks and the answer is 'switched' (R72, SwitchedSessionGuard).
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
            if ($this->hwEnrolmentExempt() || ! $this->hardwareKeys()->enrolmentRequired($this->userId())) {
                return $sk;
            }
            sodium_memzero($sk);
            if ($this->request->isAjax()) {
                $this->fail(403, 'hw_enrolment_required');
            } else {
                $this->redirectTo(['HardwareKeyController', 'index'], []);
            }
            throw new ResponseSent();
        }
        // R72: a session locked because a Steward switch-user session is active says why (secretKey locked it).
        if ((new SwitchedSessionGuard($this->container))->isSwitched()) {
            throw new VaultException('switched');
        }
        if ($this->request->isAjax()) {
            $this->fail(401, 'locked');
        } else {
            // A locked vault always goes back to the Vault page (its unlock form), never to returnRoute().
            $this->redirectTo(['VaultController', 'index'], []);
        }
        throw new ResponseSent();
    }

    // The hardware-key page is the one place a user who must still enrol keys may go (HardwareKeyController).
    protected function hwEnrolmentExempt(): bool
    {
        return false;
    }

    // Requests that create or return a long-lived secret (a passphrase, a recovery code, an agent's vault key) need HTTPS,
    // or the opted-in dev localhost, as unlock does.
    protected function requireTransport(): void
    {
        if (! $this->vaultSession()->transportAllowed()) {
            throw new VaultException('https_required');
        }
    }

    // A fresh re-authentication for what an unlocked session alone must not do (R54: a recovery code; T23: the
    // export): the current passphrase ('passphrase') through the passphrase change's throttled check
    // (RotationService::confirmPassphrase: the principal's Argon2 slot, back-off, the IP bucket, Argon2, the streak;
    // R15), and for a user with hardware keys also a fresh assertion ('assertion', from a 'ceremony' challenge), which
    // HardwareKeys::confirm checks together with the passphrase (that key's wrap must open to exactly $sk), throttled
    // the same way. hw_assertion_required, before any Argon2, when a key user sent none. Throws on any refusal.
    protected function requireFreshReauth(int $userId, #[\SensitiveParameter] string $sk): void
    {
        $passphrase = (string) $this->request->getRawValue('passphrase');
        $hw = $this->hardwareKeys();
        if ($hw->count($userId) === 0) {
            $this->rotationService()->confirmPassphrase($userId, $sk, $passphrase, $this->clientIp());
            return;
        }
        $raw = (string) $this->request->getRawValue('assertion');
        if ($raw === '') {
            throw new VaultException('hw_assertion_required');
        }
        $hw->confirm($userId, $sk, $passphrase, HardwareKeys::parseAssertion($raw), $this->clientIp());
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
            $this->redirectToPage(['vault_error' => $reason] + $this->failParams());
        } else {
            $this->respond()->html('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Vault</title></head><body><p>'
                .htmlspecialchars(t('Something went wrong. Try again.'), ENT_QUOTES, 'UTF-8').'</p></body></html>', $status);
        }
    }

    // Extra fixed parameters a failed native form POST returns with (VaultController: back to the recovery form).
    protected function failParams(): array
    {
        return [];
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

    protected function redirectTo(array $route, array $codes): void
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
        $endpoints = ['unlock' => $url('unlock'), 'lock' => $url('lock'), 'enrol' => $url('enrol'), 'recover' => $url('recover')];
        foreach (['challenge', 'register', 'remove', 'rotate', 'unlock'] as $action) {
            $endpoints['hw_'.$action] = $url($action, 'HardwareKeyController');
        }
        foreach (['tree', 'list', 'entry', 'field', 'save', 'move', 'delete'] as $action) {
            $endpoints[$action] = $url($action, 'EntryController');
        }
        foreach (['sharing', 'grant', 'revoke', 'activity'] as $action) {
            $endpoints[$action] = $url($action, 'ShareGrantController');
        }
        $endpoints += ['passphrase' => $url('passphrase', 'SecurityController'), 'rotate' => $url('rotate', 'SecurityController'), 'recovery_code' => $url('recoveryCode', 'SecurityController')];
        foreach (['reserve', 'create', 'revoke', 'mine'] as $action) {
            $endpoints['share_'.$action] = $url($action, 'VaultShareController');
        }
        // The one-time link's base: vault-onetime.js (T18) appends &id=<share_id>#<fragment> to an absolute copy.
        $endpoints['share_show'] = $url('show', 'VaultShareController');
        $endpoints += ['import_start' => $url('start', 'ImportController'), 'import_batch' => $url('batch', 'ImportController')];
        $endpoints['export'] = $url('export', 'ExportController');
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
            'switched' => t('Vault can\'t be unlocked while you\'re signed in as another user.'),
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
            'recovered' => t('Your passphrase is reset. Unlock your vault with the new passphrase.'),
            'recovered_pending' => t('Your passphrase is reset. Unlock your vault with the new passphrase; re-encrypting it finishes then.'),
            'application_url_required' => t('Hardware keys need Kanboard\'s Application URL set to an https:// address. Ask your administrator.'),
            'rp_id_mismatch' => t('Your hardware keys are registered for a different web address than this one. Open Kanboard at the address you added them on, or remove the keys and add them again there.'),
            'hw_key_invalid' => t('The hardware key could not be verified. Try again.'),
            'hw_keys_required' => t('Hardware keys are required: you need at least two.'),
            'hw_key_limit' => t('You have the most hardware keys allowed.'),
            'hw_enrolment_required' => t('Add two hardware keys before you use your vault.'),
            'hw_assertion_required' => t('Touch one of your hardware keys to confirm.'),
            'hw_unsupported' => t('This browser can\'t use hardware keys.'),
            'hw_prf_unsupported' => t('This key can\'t be used: it doesn\'t support the PRF extension.'),
            'hw_cancelled' => t('The hardware key request was cancelled or timed out.'),
            'hw_touch' => t('Touch your hardware key.'),
            'hw_touch_other' => t('Now touch this hardware key:'),
            'hw_added' => t('Hardware key added.'),
            'hw_removed' => t('Hardware key removed.'),
            'confirm_hw_remove' => t('Remove this hardware key?'),
            // KeePassXC import (vault-import.js shows import_<reason>, else the plain reason). The pre-check's reasons
            // (vault-kdbx-header.js), then KBVaultKdbx's, then the page's own.
            'import_limit' => t('This import is too large: at most 20,000 entries, each at most 256 KB.'),
            'import_too_large' => t('This file is too large to import (over 50 MB, or over 256 MB once decompressed).'),
            'import_not_kdbx' => t('This isn\'t a KeePass database (.kdbx).'),
            'import_unsupported' => t('This database uses a format, cipher or key derivation that Vault can\'t read. Save it in KeePassXC with the current format (KDBX 4) and try again.'),
            'import_file_corrupt' => t('This file is damaged or incomplete.'),
            'import_twofish' => t('This database is encrypted with Twofish, which Vault can\'t read. In KeePassXC, change the encryption algorithm to AES-256 or ChaCha20 (Database → Database Security → Encryption Settings), save, and import it again.'),
            'import_argon_mem' => t('This database asks for more than 1 GiB of memory to open, so Vault won\'t open it. Lower the memory in KeePassXC\'s encryption settings, save, and import it again.'),
            'import_argon_iter' => t('This database asks for more than 100 key derivation passes, so Vault won\'t open it. Lower them in KeePassXC\'s encryption settings, save, and import it again.'),
            'import_argon_lanes' => t('This database asks for more than 8 parallel threads, so Vault won\'t open it. Lower them in KeePassXC\'s encryption settings, save, and import it again.'),
            'import_aes_rounds' => t('This database asks for more than 100,000,000 AES-KDF rounds, so Vault won\'t open it. Lower the rounds in KeePassXC\'s encryption settings, save, and import it again.'),
            'import_yubikey_cr' => t('If this database also needs a YubiKey, Vault can\'t use it: in KeePassXC, save a copy of the database without the YubiKey, import that copy, then delete it.'),
            'import_invalid_key' => t('The master password or key file is wrong.'),
            'import_cancelled' => t('Import cancelled. Nothing more was sent.'),
            'import_timeout' => t('Opening the database took too long, so it was stopped. Lower its key derivation settings in KeePassXC and try again.'),
            'import_kdf_limits' => t('This database asks for more key derivation work than Vault allows.'),
            'import_worker_failed' => t('This browser couldn\'t run the key derivation. Try a current browser.'),
            'import_load_failed' => t('The database couldn\'t be opened.'),
            'import_busy' => t('A database is already being opened.'),
            'import_unavailable' => t('The import scripts didn\'t load. Reload the page.'),
            'import_bad_input' => t('Choose a database file.'),
            'import_opening' => t('Opening the database… Databases that use Argon2 take 10–20 seconds.'),
            'import_uploading' => t('Saving the entries in your vault…'),
            'import_done' => t('Import finished.'),
            'import_partial' => t('{count} entries were saved before it stopped; they are in the new import group.'),
            // KeePassXC export (vault-export.js shows export_<code>, else the plain code).
            'export_password_required' => t('Choose a password for the exported file.'),
            'export_checking' => t('Checking your passphrase…'),
            'export_building' => t('Building the KeePass file… Argon2 takes a few seconds.'),
            'export_done' => t('Exported. Your browser saved the file; it never went through the server.'),
            'export_skipped' => t('{count} entries couldn\'t be decrypted and were left out.'),
            'export_cancelled' => t('Export cancelled. No file was saved.'),
            'export_timeout' => t('Building the file took too long, so it was stopped. Try again.'),
            'export_worker_failed' => t('This browser couldn\'t run the key derivation. Try a current browser.'),
            'export_unavailable' => t('The export scripts didn\'t load. Reload the page.'),
            'export_busy' => t('An export is already running.'),
            'export_save_failed' => t('The KeePass file couldn\'t be built.'),
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

    protected function hardwareKeys(): HardwareKeys
    {
        return isset($this->container['vaultHardwareKeys']) ? $this->container['vaultHardwareKeys'] : new HardwareKeys($this->container);
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
