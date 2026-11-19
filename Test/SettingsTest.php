<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';

use Kanboard\Core\Http\Request;
use Kanboard\Core\Security\Role;
use Kanboard\Plugin\Vault\Controller\SettingsController;
use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\VaultSession;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Kanboard\Plugin\Vault\Plugin;
use KanboardTests\units\Base;

// Spec: Admin settings, Audit (policy_change), Hardware keys (the bound rp_id is read-only), Unlocked sessions (the
// effective idle cap); carries T9 (the policy only through setPolicy), R37 (integrity faults shown to the admin).
class SettingsTest extends Base
{
    use ServiceFixture;

    private array $cookies = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpVault();
        // A web request's audit context (the suite runs under the CLI SAPI, which would record via = cli).
        unset($this->container['vaultAudit'], $this->container['vaultSession']);
        $this->container['vaultAudit'] = fn () => new AuditModel($this->container, null, 'ui', $this->clock());
        $this->container['vaultSession'] = fn () => new class($this->container, $this->jar, fn () => $this->sid, $this->clock(), $this) extends VaultSession {
            public function __construct($c, $jar, $sid, $clock, private SettingsTest $t)
            {
                parent::__construct($c, $jar, $sid, $clock);
            }

            public function sessionLifetimeSeconds(): int
            {
                return $this->t->lifetime ?? parent::sessionLifetimeSeconds();
            }
        };
        $this->loginAs(self::ADMIN);
    }

    public ?int $lifetime = null;

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function token(): string
    {
        return $this->container['token']->getReusableCSRFToken();
    }

    // One request to the settings controller, over HTTPS. POSTs are fetches (X-Requested-With) unless $ajax is false.
    private function call(string $action, string $method = 'GET', array $post = [], ?bool $ajax = null, array $get = []): VaultTestResponse
    {
        $server = ['REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => '203.0.113.7'];
        if ($ajax ?? $method === 'POST') {
            $server['HTTP_X_REQUESTED_WITH'] = 'XMLHttpRequest';
        }
        $this->container['request'] = new Request($this->container, $server, $get, $post, [], []);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new SettingsController($this->container))->$action();
        return $response;
    }

    private function save(array $values, ?bool $ajax = null): VaultTestResponse
    {
        return $this->call('save', 'POST', $values + ['csrf_token' => $this->token()], $ajax);
    }

    private function settings(): VaultSettings
    {
        return new VaultSettings($this->container);
    }

    private function assertHardened(VaultTestResponse $r, string $what): void
    {
        $this->assertTrue($r->sent, "$what: sent");
        $this->assertSame('DENY', $r->headers['X-Frame-Options'] ?? null, "$what: X-Frame-Options");
        $this->assertStringContainsString("frame-ancestors 'none';", $r->headers['Content-Security-Policy'] ?? '', "$what: frame-ancestors");
        $this->assertSame('no-store', $r->headers['Cache-Control'] ?? null, "$what: no-store");
    }

    private function dom(string $html): \DOMXPath
    {
        $doc = new \DOMDocument();
        @$doc->loadHTML('<?xml encoding="utf-8"?>'.$html);
        return new \DOMXPath($doc);
    }

    // Spec: the settings are an admin page. A user, and an app manager, get the generic forbidden answer through the
    // hardened handler on the page and on save (fetch and native form alike), and nothing is written or audited.
    // Kills: no admin check; an admin check on the page only; a check that admits app managers.
    public function testNonAdminForbidden(): void
    {
        $manager = (int) $this->container['userModel']->create(['username' => 'manager', 'password' => 'manager password 1', 'role' => Role::APP_MANAGER]);
        foreach (['user' => $this->bob, 'app manager' => $manager] as $who => $id) {
            $this->loginAs($id);
            $page = $this->call('index');
            $this->assertHardened($page, "$who page");
            $this->assertSame(403, $page->status, "$who page");
            $this->assertStringNotContainsString('vault_idle_timeout', $page->body);
            $this->assertStringContainsString('Something went wrong', $page->body, 'the generic page');

            $r = $this->save(['vault_idle_timeout' => '30', 'vault_recovery_policy' => 'code']);
            $this->assertHardened($r, "$who save");
            $this->assertSame([403, ['ok' => false, 'reason' => 'forbidden']], [$r->status, $r->json_()], $who);
            $native = $this->save(['vault_idle_timeout' => '30'], false);
            $this->assertStringEndsWith('vault_error=forbidden', $native->headers['Location'] ?? '', "$who native");
        }
        $this->assertSame(15, $this->settings()->get('vault_idle_timeout'));
        $this->assertSame('none', $this->settings()->get('vault_recovery_policy'));
        $this->assertSame([], $this->auditRows('policy_change'));
    }

    // Spec: "Every change writes a policy_change row", with only the allowlisted columns (actor_user_id). One row per
    // changed setting; a save that changes nothing writes none; an invalid value refuses the whole form (nothing
    // written). Lowering the policy from this page goes through setPolicy, so the wraps go too (T9).
    // Kills: no audit; one row per form instead of per change; auditing unchanged keys; a partial write before the
    // invalid value; writing the policy with a plain config save (wraps left behind); a CSRF check dropped.
    public function testEveryChangeAuditsPolicyChange(): void
    {
        $this->principals()->enrolHuman($this->alice, $this->alicePassphrase);
        $this->recovery()->setPolicy('code', self::ADMIN);
        $this->recovery()->createCode($this->alice, $this->skFor($this->alice, $this->alicePassphrase));
        $this->pdo()->exec('DELETE FROM vault_audit');

        $changes = [
            'vault_hw_required' => '1',
            'vault_idle_timeout' => '30',
            'vault_share_max_expiry' => '86400',
            'vault_reveal_limit' => '40',
            'vault_agent_cap_max' => '120',
            'vault_audit_retention_days' => '90',
            'vault_trusted_proxy_cidrs' => "127.0.0.1/32\n172.16.0.0/12",
        ];
        $n = 0;
        foreach ($changes as $key => $value) {
            $r = $this->save([$key => $value]);
            $this->assertSame(['ok' => true], $r->json_(), $key);
            $this->assertCount(++$n, $this->auditRows('policy_change'), "$key: one row");
        }
        $this->assertSame(30, $this->settings()->get('vault_idle_timeout'));
        $this->assertSame('127.0.0.1/32,172.16.0.0/12', $this->settings()->get('vault_trusted_proxy_cidrs'));

        // The same values again, as the full form posts them: nothing changed, nothing audited.
        $form = $changes + ['vault_recovery_policy' => 'code'];
        $this->assertSame(['ok' => true], $this->save($form)->json_());
        $this->assertCount($n, $this->auditRows('policy_change'));

        // An invalid value refuses the whole form: the valid change beside it is not written either.
        $r = $this->save(['vault_reveal_limit' => '50', 'vault_idle_timeout' => '4']);
        $this->assertSame([400, ['ok' => false, 'reason' => 'payload_invalid']], [$r->status, $r->json_()]);
        $this->assertSame(40, $this->settings()->get('vault_reveal_limit'));
        $this->assertCount($n, $this->auditRows('policy_change'));
        $this->assertSame(403, $this->call('save', 'POST', ['vault_reveal_limit' => '50'])->status, 'no CSRF token');
        $this->assertSame(40, $this->settings()->get('vault_reveal_limit'));

        // The policy, lowered from this page: setPolicy deletes the recovery wrap and queues the rotation.
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE method = 'recovery'"));
        $r = $this->save(['vault_recovery_policy' => 'none'], false);
        $this->assertStringEndsWith('vault_notice=saved', $r->headers['Location'] ?? '', 'native save: back to the page');
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE method = 'recovery'"));
        $this->assertSame('1', (string) $this->row('SELECT rotate_requested FROM vault_principals WHERE user_id = ?', [$this->alice])['rotate_requested']);
        $rows = $this->auditRows('policy_change');
        $this->assertCount($n + 1, $rows);
        foreach ($rows as $row) {
            foreach ($row as $col => $value) {
                if (in_array($col, ['id', 'created_at', 'action', 'actor_kind', 'via'], true)) {
                    continue;
                }
                $this->assertSame($col === 'actor_user_id' ? (string) self::ADMIN : null, $value === null ? null : (string) $value, "policy_change.$col");
            }
            $this->assertSame(['human', 'ui'], [$row['actor_kind'], $row['via']]);
        }
        $this->assertSame(['actor_user_id'], AuditModel::ALLOW['policy_change']);
    }

    // Spec, Unlocked sessions: "the admin page shows the effective value": min(setting, session lifetime), where the
    // lifetime is SESSION_DURATION, or gc_maxlifetime when that is 0. Kills: showing the setting alone, and a cap
    // from the wrong source.
    public function testEffectiveIdleCapShown(): void
    {
        $this->save(['vault_idle_timeout' => '60']);
        $real = VaultSession::sessionLifetime((int) SESSION_DURATION, (int) ini_get('session.gc_maxlifetime'));
        $x = $this->dom($this->call('index')->body);
        $this->assertSame((string) intdiv(min(3600, $real), 60), trim((string) $x->query('//*[@data-vault-effective-idle]')->item(0)?->textContent), "this install's lifetime");

        $this->lifetime = $lifetime = 600; // a 10-minute Kanboard session
        $expected = intdiv(min(3600, $lifetime), 60);
        $x = $this->dom($this->call('index')->body);
        $this->assertSame('60', $x->query('//input[@name="vault_idle_timeout"]/@value')->item(0)?->nodeValue);
        $this->assertSame('5', $x->query('//input[@name="vault_idle_timeout"]/@min')->item(0)?->nodeValue);
        $this->assertSame('60', $x->query('//input[@name="vault_idle_timeout"]/@max')->item(0)?->nodeValue);
        $this->assertSame((string) $expected, trim((string) $x->query('//*[@data-vault-effective-idle]')->item(0)?->textContent));
        $this->assertSame(10, $expected, 'the session lifetime caps it');
        $this->assertSame(600, $this->container['vaultSession']->idleTimeout(), 'and the vault session uses the same cap');

        $this->save(['vault_idle_timeout' => '5']);
        $x = $this->dom($this->call('index')->body);
        $this->assertSame((string) intdiv(min(300, $lifetime), 60), trim((string) $x->query('//*[@data-vault-effective-idle]')->item(0)?->textContent));
    }

    // Spec, Hardware keys: "The admin page shows the bound rp_id" read-only; it comes from Kanboard's Application URL.
    // The page shows it as text, with no field for it, and a save carrying rp_id, origin or application_url changes
    // nothing. Kills: an editable rp_id field; a save that writes posted keys it doesn't own.
    public function testRpIdReadOnly(): void
    {
        $this->container['configModel']->save(['application_url' => 'https://kb.example:8443/kanboard/']);
        $this->container['memoryCache']->flush();
        $body = $this->call('index')->body;
        $x = $this->dom($body);
        $this->assertSame('kb.example', trim((string) $x->query('//*[@data-vault-rp-id]')->item(0)?->textContent));
        $this->assertSame('https://kb.example:8443', trim((string) $x->query('//*[@data-vault-origin]')->item(0)?->textContent));
        foreach (['rp_id', 'vault_rp_id', 'origin', 'application_url'] as $name) {
            $this->assertSame(0, $x->query('//*[@name="'.$name.'"]')->length, "no field named $name");
        }

        $r = $this->save(['rp_id' => 'evil.example', 'vault_rp_id' => 'evil.example', 'origin' => 'https://evil.example', 'application_url' => 'https://evil.example/']);
        $this->assertSame(['ok' => true], $r->json_());
        $this->container['memoryCache']->flush();
        $this->assertSame('https://kb.example:8443/kanboard/', $this->container['configModel']->get('application_url'));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM settings WHERE \"option\" IN ('rp_id', 'vault_rp_id', 'origin')"));
        $this->assertSame([], $this->auditRows('policy_change'));

        // Not https: hardware keys can't be enrolled, and the page says so instead of showing an rp_id.
        $this->container['configModel']->save(['application_url' => 'http://kb.example/']);
        $this->container['memoryCache']->flush();
        $x = $this->dom($this->call('index')->body);
        $this->assertSame(0, $x->query('//*[@data-vault-rp-id]')->length);
        $this->assertSame(1, $x->query('//*[@data-vault-rp-unset]')->length);
    }

    // R8/R31/R37: integrity faults reach the admin as a count plus object type and id, nothing else. The page also
    // lists every deployment check and flags an IPv4-mapped trusted CIDR (T4 minor). Kills: faults not surfaced;
    // a fault listed once per row instead of per object; a check missing from the page.
    public function testPageListsIntegrityFaultsAndChecks(): void
    {
        $audit = new AuditModel($this->container, 'system', 'ui', fn () => $this->now);
        foreach ([['entry', 5], ['entry', 5], ['group', 2]] as [$type, $id]) {
            $audit->record('integrity_error', ['actor_user_id' => $this->alice, 'object_type' => $type, 'object_id' => $id]);
        }
        $this->pdo()->exec("INSERT INTO settings (\"option\", value) VALUES ('vault_trusted_proxy_cidrs', '::ffff:10.0.0.0/104')");
        $body = $this->call('index')->body;
        $x = $this->dom($body);
        $this->assertSame('2', trim((string) $x->query('//*[@data-vault-integrity-count]')->item(0)?->textContent));
        $items = [];
        foreach ($x->query('//*[@data-vault-integrity-object]') as $li) {
            $items[] = trim(preg_replace('/\s+/', ' ', $li->textContent));
        }
        sort($items);
        $this->assertSame(['entry #5', 'group #2'], $items);
        foreach (['https', 'plugin_installer', 'plugin_dir_writable', 'proxy_headers', 'sodium', 'lock_dir'] as $key) {
            $this->assertSame(1, $x->query('//*[@data-vault-check="'.$key.'"]')->length, "check $key listed");
        }
        $this->assertSame(1, $x->query('//*[@data-vault-mapped-cidr]')->length, 'the mapped CIDR is flagged');
        $this->assertStringContainsString('Vault/Assets/css/vault.css', $body);
        $this->assertStringNotContainsString('<script', preg_replace('~<script[^>]*src="[^"]*"[^>]*></script>~', '', $body), 'no inline script');
    }
}
