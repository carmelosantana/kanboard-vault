<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Model\DeploymentChecks;
use Kanboard\Plugin\Vault\Model\ServerKeyFile;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use KanboardTests\units\Base;

// Spec: Threat model → Deployment preconditions, Throttling → Client IP (warnings), Admin settings (the checks);
// carries R41 (the https check), T4 minors (IPv4-mapped CIDRs, the lock directory's mode).
class DeploymentChecksTest extends Base
{
    use ServerFixture;

    private string $tmp;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->tmp = sys_get_temp_dir().'/vault-t15-'.bin2hex(random_bytes(6));
        mkdir($this->tmp.'/plugins', 0755, true);
        mkdir($this->tmp.'/lock', 0700);
        $this->setUpServer();
    }

    protected function tearDown(): void
    {
        foreach (['plugins', 'lock'] as $d) {
            @chmod($this->tmp.'/'.$d, 0700);
            @rmdir($this->tmp.'/'.$d);
        }
        @rmdir($this->tmp);
        $this->tearDownServer();
        $this->tearDownVault();
        parent::tearDown();
    }

    private function checks(array $env = []): DeploymentChecks
    {
        return new DeploymentChecks($this->container, $env + [
            'plugin_installer' => false,
            'plugins_dir' => $this->tmp.'/plugins',
            'plugins_writable' => false,
            'lock_dir' => $this->tmp.'/lock',
            'sodium' => true,
            'trusted_proxy_headers' => '',
            'server_on' => false,
            'server_key_file' => new ServerKeyFile($this->keyPath),
            'data_dir' => $this->tmp,
            'at_risk' => 0,
        ]);
    }

    private function req(array $server): Request
    {
        return new Request($this->container, $server + ['REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php']);
    }

    private function cidrs(string $value): void
    {
        (new VaultSettings($this->container))->set('vault_trusted_proxy_cidrs', $value, 1);
    }

    // Spec, Throttling: "It also warns when REMOTE_ADDR is a private or loopback address and no trusted proxy is
    // configured." A private or loopback sender with no trusted CIDRs warns; once the proxy is trusted, or from a
    // public address, it doesn't. Kills: the private/loopback test dropped, the trusted-CIDR condition ignored, and
    // the warning raised for every sender.
    public function testProxyWarningWhenPrivateRemoteAndNoTrustedCidrs(): void
    {
        foreach (['10.0.0.5', '172.18.0.1', '192.168.1.20', '127.0.0.1', '::1', 'fd00::7'] as $remote) {
            $c = $this->checks()->run($this->req(['REMOTE_ADDR' => $remote, 'HTTPS' => 'on']))['proxy_headers'];
            $this->assertFalse($c['ok'], "$remote with no trusted proxy warns");
            $this->assertStringContainsString('trusted proxy', $c['message']);
        }
        $this->assertTrue($this->checks()->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']))['proxy_headers']['ok'], 'a public sender');

        $this->cidrs('10.0.0.0/8, 127.0.0.1/32');
        $this->assertTrue($this->checks()->run($this->req(['REMOTE_ADDR' => '10.0.0.5', 'HTTPS' => 'on']))['proxy_headers']['ok'], 'a trusted proxy');
        $this->assertTrue($this->checks()->run($this->req(['REMOTE_ADDR' => '127.0.0.1', 'HTTPS' => 'on']))['proxy_headers']['ok'], 'a trusted loopback proxy');
    }

    // Spec: "The admin page warns when forwarding headers arrive from an address that isn't trusted." Kills: only
    // the private-address rule implemented.
    public function testForwardingHeadersFromAnUntrustedSenderWarn(): void
    {
        foreach (['HTTP_X_FORWARDED_FOR' => '198.51.100.1', 'HTTP_CF_CONNECTING_IP' => '198.51.100.1', 'HTTP_X_FORWARDED_PROTO' => 'https'] as $h => $v) {
            $c = $this->checks()->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on', $h => $v]))['proxy_headers'];
            $this->assertFalse($c['ok'], $h);
            $this->assertStringContainsString('ignores', $c['message']);
        }
        // Kanboard's own Docker image has its nginx set X-Real-IP and X-Forwarded-For to the connection's own address
        // on every request: that is the local web server, not a proxy, and is not warned about.
        $local = $this->checks()->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on', 'HTTP_X_REAL_IP' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9']));
        $this->assertTrue($local['proxy_headers']['ok'], 'headers that only repeat REMOTE_ADDR');
        $chain = $this->checks()->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1, 203.0.113.9']));
        $this->assertFalse($chain['proxy_headers']['ok'], 'a forwarded client before the connection address');

        $this->cidrs('203.0.113.0/24');
        $ok = $this->checks(['trusted_proxy_headers' => 'HTTP_X_FORWARDED_FOR'])->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on', 'HTTP_X_FORWARDED_FOR' => '198.51.100.1']));
        $this->assertTrue($ok['proxy_headers']['ok']);
    }

    // T4 minor: an IPv4-mapped IPv6 CIDR (::ffff:10.0.0.0/104) matches nothing, because addresses are compared as
    // IPv4. It is flagged, and it doesn't count as a trusted proxy for the private-address rule. Kills: counting it.
    public function testMappedCidrIsFlaggedAndCountsForNothing(): void
    {
        $this->cidrs('::ffff:10.0.0.0/104');
        $c = $this->checks()->run($this->req(['REMOTE_ADDR' => '10.0.0.5', 'HTTPS' => 'on']))['proxy_headers'];
        $this->assertFalse($c['ok']);
        $this->assertStringContainsString('IPv4-mapped', $c['message']);
        $this->assertStringContainsString('no trusted proxy is configured', $c['message'], 'the private-address warning still applies');
    }

    // R41: the https check uses Vault's transport logic. X-Forwarded-Proto from an untrusted sender is not HTTPS;
    // from a trusted proxy it is. Kills: the check on Request::isHTTPS().
    public function testHttpsCheckTrustsForwardedProtoOnlyFromATrustedProxy(): void
    {
        $forged = ['REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_PROTO' => 'https'];
        $this->assertFalse($this->checks()->run($this->req($forged))['https']['ok']);
        $this->assertTrue($this->checks()->run($this->req(['REMOTE_ADDR' => '198.51.100.9', 'HTTPS' => 'on']))['https']['ok']);
        $this->cidrs('198.51.100.0/24');
        $this->assertTrue($this->checks()->run($this->req($forged))['https']['ok']);
    }

    // Spec, Deployment preconditions: PLUGIN_INSTALLER false, a plugin directory the web server can't write to,
    // ext-sodium; T4 minor: the lock directory no looser than 0700. Each check fails and passes on its own input,
    // and no message names a filesystem path. Kills: any check hard-wired, a path in a message, and a lock-dir
    // check that ignores group or other bits.
    public function testEveryCheckReportsWithoutPaths(): void
    {
        $good = $this->checks()->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']));
        $this->assertSame(['https', 'plugin_installer', 'plugin_dir_writable', 'proxy_headers', 'sodium', 'lock_dir', 'server_sharing', 'key_provider', 'entries_at_risk'], array_keys($good));
        foreach ($good as $key => $c) {
            $this->assertSame(['ok', 'message'], array_keys($c), $key);
            $this->assertTrue($c['ok'], "$key passes");
            $this->assertNotSame('', $c['message']);
        }

        chmod($this->tmp.'/lock', 0750);
        $bad = $this->checks(['plugin_installer' => true, 'plugins_writable' => true, 'sodium' => false, 'server_on' => true, 'at_risk' => 3])
            ->run($this->req(['REMOTE_ADDR' => '10.0.0.5']));
        unset($bad['server_sharing']); // informational: on or off, never a warning
        foreach ($bad as $key => $c) {
            $this->assertFalse($c['ok'], "$key fails");
            $this->assertStringNotContainsString($this->tmp, $c['message'], "$key names no path");
            $this->assertStringNotContainsString('/plugins', $c['message'], "$key names no path");
            $this->assertStringNotContainsString(sys_get_temp_dir(), $c['message']);
            $this->assertStringNotContainsString('10.0.0.5', $c['message'], "$key names no address");
        }
        chmod($this->tmp.'/lock', 0701);
        $this->assertFalse($this->checks()->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']))['lock_dir']['ok'], 'other-execute');
        rmdir($this->tmp.'/lock');
        $this->assertTrue($this->checks()->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']))['lock_dir']['ok'], 'not created yet: made 0700 at first use');

        // Without overrides, the real environment: is_writable on the real plugin directory, the constants.
        $real = (new DeploymentChecks($this->container))->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']));
        $this->assertSame(! PLUGIN_INSTALLER, $real['plugin_installer']['ok']);
        $this->assertSame(! is_writable(PLUGINS_DIR), $real['plugin_dir_writable']['ok']);
        $this->assertSame(function_exists('sodium_crypto_pwhash'), $real['sodium']['ok']);
    }

    private function keyProvider(array $env): array
    {
        return $this->checks($env)->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']))['key_provider'];
    }

    // Spec amendment, Server key file: the key file must live outside Kanboard's data directory (a database-and-data
    // backup must not carry it), be sound (ServerKeyFile::status) and open the Server key (KeyProvider::healthy) while
    // Server is on. Kills: the isUnder check removed; status ignored; healthy ignored; a check that chmods the file.
    public function testKeyProviderCheck(): void
    {
        $this->enableServer();
        $on = ['server_on' => true];
        $ok = $this->keyProvider($on);
        $this->assertTrue($ok['ok'], 'outside the data directory and valid: '.$ok['message']);

        $under = $this->keyProvider($on + ['data_dir' => $this->serverDir]);
        $this->assertFalse($under['ok'], 'under the data directory');
        $this->assertStringContainsString('key file is inside Kanboard', $under['message']); // t() escapes the apostrophe
        $this->assertStringContainsString('data directory', $under['message']);
        $off = $this->keyProvider(['data_dir' => $this->serverDir]);
        $this->assertFalse($off['ok'], 'under the data directory is red even while Server is off (the default path)');

        $missing = $this->keyProvider($on + ['server_key_file' => new ServerKeyFile($this->serverDir.'/vault-server/absent.key')]);
        $this->assertFalse($missing['ok'], 'missing');

        // A sound key file that isn't the one the Server wrap was made with: status ok, healthy false.
        $other = $this->serverDir.'/other';
        mkdir($other, 0700);
        (new ServerKeyFile($other.'/server.key'))->create();
        $this->assertSame('ok', (new ServerKeyFile($other.'/server.key'))->status());
        $this->assertFalse($this->keyProvider($on + ['server_key_file' => new ServerKeyFile($other.'/server.key')])['ok'], 'a key that doesn\'t open the wrap');

        chmod($this->keyPath, 0640);
        $loose = $this->keyProvider($on);
        $this->assertFalse($loose['ok'], 'mode 0640');
        clearstatcache(true, $this->keyPath);
        $this->assertSame(0640, fileperms($this->keyPath) & 0777, 'the check never repairs the mode');

        foreach ([$ok, $under, $off, $missing, $loose] as $c) {
            $this->assertStringNotContainsString($this->keyPath, $c['message']);
            $this->assertStringNotContainsString($this->serverDir, $c['message']);
            $this->assertStringNotContainsString($this->tmp, $c['message']);
            $this->assertStringNotContainsString(sys_get_temp_dir(), $c['message']);
        }
    }

    // Server off is informational: sharing says it is off, the key file is not in use (no file is looked at). The
    // at-risk count warns from one. Kills: Server off shown as a warning; the key file checked while off; the count ignored.
    public function testServerSharingAndEntriesAtRisk(): void
    {
        $r = $this->checks(['server_key_file' => new ServerKeyFile($this->serverDir.'/nothing/here.key')])->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']));
        $this->assertTrue($r['server_sharing']['ok']);
        $this->assertStringContainsString('Server sharing is off', $r['server_sharing']['message']);
        $this->assertSame(['ok' => true, 'message' => 'Not in use while Server sharing is off.'], $r['key_provider']);

        $this->enableServer();
        $real = (new DeploymentChecks($this->container, ['data_dir' => $this->tmp]))->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']));
        $this->assertTrue($real['server_sharing']['ok']);
        $this->assertStringContainsString('Server sharing is on', $real['server_sharing']['message']);
        $this->assertTrue($real['key_provider']['ok'], 'without overrides: the container\'s key file and provider');
        $this->assertTrue($real['entries_at_risk']['ok'], 'nothing shared with Server');

        $two = $this->checks(['at_risk' => 2])->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']))['entries_at_risk'];
        $this->assertFalse($two['ok']);
        $this->assertStringContainsString('2', $two['message']);
        $this->assertTrue($this->checks(['at_risk' => 0])->run($this->req(['REMOTE_ADDR' => '203.0.113.9', 'HTTPS' => 'on']))['entries_at_risk']['ok']);
    }
}
