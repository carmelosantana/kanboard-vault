<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Core\Base;
use Kanboard\Core\Http\Request;

// The deployment checks on the admin page (spec: Threat model → Deployment preconditions, Throttling → Client IP).
// run() answers one {ok, message} per check, in this order:
//
//   https                this request arrived over HTTPS, by Vault's own rule (R41, ClientIp::secureTransport): a
//                        forwarded protocol counts only from a trusted proxy.
//   plugin_installer     PLUGIN_INSTALLER is off. An admin who can install plugins can swap Vault's code.
//   plugin_dir_writable  the web server can't write to the plugin directory, for the same reason.
//   proxy_headers        forwarding headers from a sender that isn't a trusted proxy are ignored (warned; a header
//                        that only repeats REMOTE_ADDR is the local web server's, not a proxy's); a private
//                        or loopback REMOTE_ADDR with no trusted proxy probably means an unconfigured proxy (every
//                        client would share one rate-limit bucket); IPv4-mapped CIDRs match nothing (T4 minor);
//                        behind a trusted proxy, Kanboard's own TRUSTED_PROXY_HEADERS should be set.
//   sodium               ext-sodium with Argon2id.
//   lock_dir             the Argon2 slot directory (DATA_DIR/vault) is no looser than 0700 (T4 minor).
//   server_sharing       Server sharing on or off (informational, never a warning).
//   key_provider         the Server key file (VAULT_SERVER_KEY_FILE) is outside DATA_DIR, so a backup of the data
//                        directory doesn't carry it (red even while Server is off: the default path is inside); while
//                        Server is on it is also sound (ServerKeyFile::status) and opens the Server key
//                        (KeyProvider::healthy). Read only: the file is never created or chmod-repaired here.
//   entries_at_risk      no entry shared with Server is at risk of becoming an orphan nobody can claim
//                        (OrphanService::atRisk).
//
// Messages are fixed sentences: they name no filesystem path, no address and no header value.
class DeploymentChecks extends Base
{
    private const FORWARDING = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED_PROTO', 'HTTP_X_FORWARDED_SSL', 'HTTP_X_FORWARDED_HOST', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_FORWARDED'];

    private array $env;

    // $env overrides what the checks read, for tests: plugin_installer (bool), plugins_dir (string),
    // plugins_writable (bool), lock_dir (string), sodium (bool), trusted_proxy_headers (string), server_on (bool),
    // server_key_file (ServerKeyFile; its provider is then built on it), data_dir (string), at_risk (int).
    public function __construct($container, array $env = [])
    {
        parent::__construct($container);
        $this->env = $env;
    }

    /** @return array<string, array{ok:bool, message:string}> */
    public function run(Request $r): array
    {
        $cidrs = (new VaultSettings($this->container))->trustedProxies();
        return [
            'https' => $this->https($r, $cidrs),
            'plugin_installer' => $this->pluginInstaller(),
            'plugin_dir_writable' => $this->pluginDir(),
            'proxy_headers' => $this->proxyHeaders($r, $cidrs),
            'sodium' => $this->sodium(),
            'lock_dir' => $this->lockDir(),
            'server_sharing' => $this->serverSharing(),
            'key_provider' => $this->keyProvider(),
            'entries_at_risk' => $this->entriesAtRisk(),
        ];
    }

    private function serverOn(): bool
    {
        return (bool) ($this->env['server_on'] ?? ServerPrincipal::of($this->container)->isOn());
    }

    private function serverSharing(): array
    {
        return self::ok($this->serverOn()
            ? t('Server sharing is on: owners can share single entries with plugins that read them on the server.')
            : t('Server sharing is off.'));
    }

    private function keyProvider(): array
    {
        $file = $this->env['server_key_file'] ?? (isset($this->container['vaultServerKeyFile']) ? $this->container['vaultServerKeyFile'] : new ServerKeyFile(ServerKeyFile::configuredPath()));
        if ($file->isUnder((string) ($this->env['data_dir'] ?? DATA_DIR))) {
            return self::warn(t('The Server key file is inside Kanboard\'s data directory, so a backup of that directory carries the key with the database. Set VAULT_SERVER_KEY_FILE to a path outside it.'));
        }
        if (! $this->serverOn()) {
            return self::ok(t('Not in use while Server sharing is off.'));
        }
        $status = $file->status();
        if ($status === 'missing') {
            return self::warn(t('The Server key file is missing, so nothing shared with Server can be read. Restore it from its own backup.'));
        }
        if ($status !== 'ok') {
            return self::warn(t('The Server key file isn\'t safe to use: it must be a regular file owned by the web server\'s user with mode 0600, in a directory only that user can write to, with no symbolic link on the way. Vault never repairs it.'));
        }
        $provider = isset($this->env['server_key_file']) ? new FileKeyProvider($this->container, $file)
            : (isset($this->container['vaultKeyProvider']) ? $this->container['vaultKeyProvider'] : new FileKeyProvider($this->container, $file));
        if (! $provider->healthy()) {
            return self::warn(t('The Server key file doesn\'t open the Server key: it isn\'t the file Server sharing was turned on with. Restore the original file.'));
        }
        return self::ok(t('The Server key file is outside Kanboard\'s data directory and opens the Server key.'));
    }

    private function entriesAtRisk(): array
    {
        $n = (int) ($this->env['at_risk'] ?? count((new OrphanService($this->container))->atRisk()));
        return $n === 0
            ? self::ok(t('No entry shared with Server is at risk of becoming an orphan.'))
            : self::warn(t('%d entries shared with Server have a disabled owner, or no other administrator with access who could claim them if their owner were deleted. They are listed below.', $n));
    }

    private function https(Request $r, array $cidrs): array
    {
        if ((new ClientIp($this->container))->secureTransport($r, $cidrs)) {
            return self::ok(t('This page arrived over HTTPS.'));
        }
        return self::warn(t('This page arrived over plain HTTP. Vault refuses to set up or unlock a vault without HTTPS. Behind a proxy that ends TLS, add the proxy to the trusted proxy addresses so its X-Forwarded-Proto header counts.'));
    }

    private function pluginInstaller(): array
    {
        $on = (bool) ($this->env['plugin_installer'] ?? PLUGIN_INSTALLER);
        return $on
            ? self::warn(t('PLUGIN_INSTALLER is on. An administrator who can install plugins can replace Vault\'s code and read what users unlock. Set it to false.'))
            : self::ok(t('PLUGIN_INSTALLER is off.'));
    }

    private function pluginDir(): array
    {
        $writable = (bool) ($this->env['plugins_writable'] ?? is_writable((string) ($this->env['plugins_dir'] ?? PLUGINS_DIR)));
        return $writable
            ? self::warn(t('The web server can write to the plugin directory, so anyone who gains the web server\'s rights can replace Vault\'s code. Make it read-only for the web server.'))
            : self::ok(t('The web server can\'t write to the plugin directory.'));
    }

    private function proxyHeaders(Request $r, array $cidrs): array
    {
        $mapped = array_filter($cidrs, [ClientIp::class, 'isMappedCidr']);
        $effective = array_values(array_diff($cidrs, $mapped));
        $remote = $r->getServerVariable('REMOTE_ADDR');
        $ip = new ClientIp($this->container);
        $trusted = $effective !== [] && $ip->inCidrs($remote, $effective);
        $forwarded = array_filter(self::FORWARDING, static fn (string $h): bool => self::forwards($r->getServerVariable($h), $remote)) !== [];

        $problems = [];
        if ($mapped !== []) {
            $problems[] = t('An IPv4-mapped IPv6 entry (::ffff:…) in the trusted proxy addresses matches nothing. Write it as an IPv4 address or range.');
        }
        if ($forwarded && ! $trusted) {
            $problems[] = t('Forwarding headers arrived from an address that isn\'t a trusted proxy, so Vault ignores them.');
        }
        if (! $trusted && self::isPrivate($remote) && $effective === []) {
            $problems[] = t('This request came from a private or loopback address and no trusted proxy is configured. If Kanboard runs behind a proxy or tunnel, add its address, or every client shares one rate-limit bucket.');
        }
        $headers = (string) ($this->env['trusted_proxy_headers'] ?? (defined('TRUSTED_PROXY_HEADERS') ? TRUSTED_PROXY_HEADERS : ''));
        if ($trusted && $forwarded && trim($headers) === '') {
            $problems[] = t('Kanboard runs behind a trusted proxy but its own TRUSTED_PROXY_HEADERS setting is empty, so Kanboard logs the proxy\'s address instead of the client\'s.');
        }
        if ($problems !== []) {
            return self::warn(implode(' ', $problems));
        }
        return self::ok($trusted ? t('Forwarding headers come from a trusted proxy.') : t('No proxy problem seen on this request.'));
    }

    private function sodium(): array
    {
        $present = (bool) ($this->env['sodium'] ?? function_exists('sodium_crypto_pwhash'));
        return $present ? self::ok(t('ext-sodium with Argon2id is available.')) : self::warn(t('ext-sodium with Argon2id is missing. Vault can\'t run without it.'));
    }

    private function lockDir(): array
    {
        $dir = (string) ($this->env['lock_dir'] ?? (new ArgonSlots($this->container))->directory());
        clearstatcache(true, $dir);
        if (! is_dir($dir)) {
            return self::ok(t('The lock directory is created with mode 0700 at first use.'));
        }
        $perms = @fileperms($dir);
        if ($perms === false || ($perms & 0077) !== 0) {
            return self::warn(t('The lock directory in Kanboard\'s data directory is open to other system users. Set its mode to 0700.'));
        }
        return self::ok(t('The lock directory is private (0700).'));
    }

    // Does this header carry anything beyond the connection's own address? Kanboard's Docker image has its nginx set
    // X-Real-IP and X-Forwarded-For ($proxy_add_x_forwarded_for) to REMOTE_ADDR on every request: the local web
    // server, not a proxy.
    private static function forwards(string $value, string $remote): bool
    {
        foreach (explode(',', $value) as $part) {
            $part = trim($part);
            if ($part !== '' && $part !== $remote) {
                return true;
            }
        }
        return false;
    }

    // Private, loopback, link-local or otherwise reserved: anything a client on the internet wouldn't arrive from.
    private static function isPrivate(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    private static function ok(string $message): array
    {
        return ['ok' => true, 'message' => $message];
    }

    private static function warn(string $message): array
    {
        return ['ok' => false, 'message' => $message];
    }
}
