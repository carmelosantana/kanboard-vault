<?php

use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\FileKeyProvider;
use Kanboard\Plugin\Vault\Model\ServerKeyFile;
use Kanboard\Plugin\Vault\Model\ServerPrincipal;

require_once __DIR__.'/AgentFixture.php';

// The Server principal for the Server tests (spec amendment: Principals, Server key file): a key file in a temp
// directory with no symlink in its path, and the three Server services built from it with the test clock. The caller
// runs setUpVault (or setUpAgents) first and tearDownServer last.
trait ServerFixture
{
    use AgentFixture;

    protected string $serverDir;
    protected string $keyPath;

    protected function setUpServer(): void
    {
        // realpath: the key file refuses a symlink anywhere in its path (a /tmp that is a link, say).
        $this->serverDir = realpath(sys_get_temp_dir()).'/vault-srv-'.bin2hex(random_bytes(8));
        mkdir($this->serverDir, 0700);
        $this->keyPath = $this->serverDir.'/vault-server/server.key';
        foreach (['vaultServerKeyFile', 'vaultKeyProvider', 'vaultServerPrincipal'] as $service) {
            unset($this->container[$service]);
        }
        $this->container['vaultServerKeyFile'] = fn () => new ServerKeyFile($this->keyPath);
        $this->container['vaultKeyProvider'] = fn ($c) => new FileKeyProvider($c, $c['vaultServerKeyFile']);
        $this->container['vaultServerPrincipal'] = fn ($c) => new ServerPrincipal($c, $c['vaultServerKeyFile'], $c['vaultKeyProvider'], $this->clock());
    }

    protected function tearDownServer(): void
    {
        $this->rmServerTree($this->serverDir);
    }

    protected function server(): ServerPrincipal
    {
        return ServerPrincipal::of($this->container);
    }

    protected function enableServer(): void
    {
        $this->server()->enable(self::ADMIN);
    }

    // A provider with nothing cached: it reads the key file as it is now.
    protected function freshProvider(): FileKeyProvider
    {
        return new FileKeyProvider($this->container, new ServerKeyFile($this->keyPath));
    }

    // The Server sk, opened from the vault_meta wrap with the key file, as an attacker holding both could.
    protected function serverSk(): string
    {
        $meta = $this->row('SELECT server_wrap_id, server_wrap_nonce, server_wrapped_sk FROM vault_meta WHERE id = 1');
        $p = $this->row('SELECT public_key FROM vault_principals WHERE user_id = ?', [ServerPrincipal::ID]);
        $this->assertNotNull($p, 'the Server principal');
        $wrap = ['id' => (int) $meta['server_wrap_id'], 'user_id' => ServerPrincipal::ID, 'method' => 'server', 'credential_id' => null,
            'nonce' => $meta['server_wrap_nonce'], 'wrapped_sk' => $meta['server_wrapped_sk'], 'crypto_v' => Wraps::CRYPTO_V];
        return Wraps::unwrap($wrap, Kdf::kek((new ServerKeyFile($this->keyPath))->read(), 'server', ServerPrincipal::ID), base64_decode($p['public_key']));
    }

    private function rmServerTree(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            unlink($path);
            return;
        }
        if (! is_dir($path)) {
            return;
        }
        chmod($path, 0700);
        foreach (scandir($path) as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                $this->rmServerTree($path.'/'.$entry);
            }
        }
        rmdir($path);
    }
}
