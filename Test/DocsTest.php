<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';

use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Task 13: the frozen consumer contract stays documented. The README's Server sharing section names the key-file
// constant, the container service, the ref format, the rate bucket, both events and every refusal reason; its consumer
// example is real PHP that runs against the API; docs/security.md names the Server audit action and lists, under its
// metadata-leakage heading, what Server sharing leaves in plaintext. Kills: a reason (or any frozen string) deleted
// from the README; the example drifting from the API; the leakage list losing an item.
class DocsTest extends Base
{
    use ServerFixture;

    private static function doc(string $path): string
    {
        $text = file_get_contents(__DIR__.'/../'.$path);
        self::assertIsString($text);
        return $text;
    }

    // The text from $heading (a whole line) to the next heading of the same or a higher level.
    private static function section(string $text, string $heading): string
    {
        $level = strspn($heading, '#');
        $start = strpos($text, "\n".$heading."\n");
        self::assertNotFalse($start, "heading $heading");
        $body = substr($text, $start + strlen($heading) + 2);
        if (preg_match('/^#{1,'.$level.'} /m', $body, $m, PREG_OFFSET_CAPTURE) === 1) {
            $body = substr($body, 0, $m[0][1]);
        }
        return $body;
    }

    public function testReadmeDocumentsServerSharing(): void
    {
        $server = self::section(self::doc('README.md'), '## Server sharing');
        foreach (['VAULT_SERVER_KEY_FILE', 'vaultSecrets', 'vault://<entry_id>/<field>', 'srvread:', 'vault.secret.changed', 'vault.secret.revoked'] as $s) {
            $this->assertStringContainsString($s, $server, $s);
        }
        $this->assertCount(9, ServiceSecretException::REASONS);
        foreach (ServiceSecretException::REASONS as $reason) {
            $this->assertStringContainsString('`'.$reason.'`', $server, $reason);
        }
    }

    public function testSecurityPageListsMetadataLeakage(): void
    {
        $security = self::doc('docs/security.md');
        $this->assertStringContainsString('server_read_denied', $security);
        $leakage = strtolower(self::section($security, '### Metadata leakage'));
        foreach (['consumer names', 'field names', 'rates', 'read times', 'correlation ids'] as $item) {
            $this->assertStringContainsString($item, $leakage, $item);
        }
    }

    // The README's consumer example (the first php block under The consumer API), run as written: it reads a shared field, returns null on a refusal, and never
    // runs without the service.
    public function testReadmeConsumerExampleRuns(): void
    {
        $api = self::section(self::section(self::doc('README.md'), '## Server sharing'), '### The consumer API');
        $this->assertSame(1, preg_match('/```php\n(.*?)```/s', $api, $m), 'a php block');
        $code = $m[1];
        $this->assertLessThanOrEqual(14, substr_count($code, "\n"), 'a short example');
        foreach (["isset(\$container['vaultSecrets'])", '->read(', '->reveal()', 'catch (ServiceSecretException'] as $s) {
            $this->assertStringContainsString($s, $code, $s);
        }
        $this->assertSame(1, preg_match('/^function (\w+)\(/m', $code, $fn), 'the example defines a function');
        if (! function_exists($fn[1])) {
            eval($code);
        }

        $this->setUpAgents();
        $this->setUpServer();
        try {
            $this->assertNull(($fn[1])($this->container, 'vault://1/password'), 'no service, no read');
            $e = $this->serverShare(['CveHunter'], ['password']);
            $this->container['vaultSecrets'] = $this->serverSecrets();
            $this->assertSame(Fixtures::ENTRY_PASSWORD, ($fn[1])($this->container, "vault://$e/password"));
            $log = new class () extends \Psr\Log\AbstractLogger {
                public array $lines = [];

                public function log($level, $message, array $context = []): void
                {
                    $this->lines[] = $level.' '.$message;
                }
            };
            unset($this->container['logger']);
            $this->container['logger'] = $log;
            $this->assertNull(($fn[1])($this->container, "vault://$e/username"), 'a refusal is null');
            $this->assertSame(['warning CveHunter: Vault refused the key: field_not_allowed'], $log->lines, 'the reason is logged');
        } finally {
            $this->tearDownServer();
            $this->tearDownVault();
        }
    }
}
