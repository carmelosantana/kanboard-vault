<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Controller\ExportController;
use Kanboard\Plugin\Vault\Controller\VaultController;
use Kanboard\Plugin\Vault\Model\EntryPayload;
use Kanboard\Plugin\Vault\Model\FailedGuess;
use Kanboard\Plugin\Vault\Model\HardwareKeys;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Model\VaultDb;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use Kanboard\Plugin\Vault\Test\Support\SoftAuthenticator;
use Kanboard\Plugin\Vault\Test\Support\WebAuthnVectors;
use KanboardTests\units\Base;

// Spec: KeePassXC import and export → Export (fresh passphrase and hardware-key re-entry; the user's own entries,
// optionally those shared with them; decrypted JSON, no-store), Audit (export: actor_user_id and count only), Throttling
// (the re-entry goes through the unlock throttle: R15 order, back-off, the IP bucket, the streak), Entries, groups and
// grants (R23: only live grants). The page (vault-export.js) builds the KDBX file; this is the server's one endpoint.
class ExportControllerTest extends Base
{
    use ServiceFixture;

    private const ORIGIN = 'https://kb.example';
    private const RP = 'kb.example';

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpVault();
        $this->container['configModel']->save(['application_url' => 'https://kb.example/']);
        $this->container['memoryCache']->flush();
        $this->container['vaultUnlock'] = fn () => $this->unlockService();
        $this->container['vaultPrincipals'] = fn () => new PrincipalModel($this->container, $this->slots(), $this->argon(), $this->clock(), $this->rotation());
        $this->container['vaultRotation'] = fn () => $this->rotation();
        $this->container['vaultRecovery'] = fn () => $this->recovery();
        $this->container['vaultHousekeeping'] = fn () => new Housekeeping($this->container, $this->clock(), $this->rotation());
        $this->container['vaultHardwareKeys'] = fn () => $this->hw();
        $this->container['vaultStore'] = fn () => $this->store();
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->loginAs($this->alice);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function hw(): HardwareKeys
    {
        return new HardwareKeys($this->container, $this->slots(), $this->argon(), $this->clock(), $this->rotation());
    }

    private function token(): string
    {
        return $this->container['token']->getReusableCSRFToken();
    }

    // One request carrying the cookie the last response set. POSTs are vault.js fetches unless $ajax is false.
    private function call(string $controller, string $action, string $method = 'POST', array $post = [], array $server = [], ?bool $ajax = null): VaultTestResponse
    {
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        if ($ajax ?? $method === 'POST') {
            $server += ['HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'];
        }
        $this->container['request'] = new Request($this->container, $server + [
            'REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => self::IP,
        ], [], $post, [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new $controller($this->container))->$action();
        return $response;
    }

    private function export(array $post = [], array $server = [], ?bool $ajax = null): VaultTestResponse
    {
        return $this->call(ExportController::class, 'export', 'POST', $post + ['csrf_token' => $this->token()], $server, $ajax);
    }

    private function unlock(int $userId, string $passphrase, string $sid): string
    {
        $this->sid = $sid;
        $this->loginAs($userId);
        $r = $this->call(VaultController::class, 'unlock', 'POST', ['passphrase' => $passphrase, 'csrf_token' => $this->token()]);
        $this->assertSame(['ok' => true], $r->json_(), 'unlocked');
        $this->sendCookieBack();
        $sk = $this->session()->secretKey();
        $this->assertNotNull($sk);
        return $sk;
    }

    private function assertHardened(VaultTestResponse $r, string $what): void
    {
        $this->assertSame('DENY', $r->headers['X-Frame-Options'] ?? null, "$what: X-Frame-Options");
        $this->assertStringContainsString("frame-ancestors 'none';", $r->headers['Content-Security-Policy'] ?? '', "$what: frame-ancestors");
        $this->assertSame('no-store', $r->headers['Cache-Control'] ?? null, "$what: no-store");
    }

    private function streak(): int
    {
        return FailedGuess::streak(new VaultDb($this->container), $this->alice);
    }

    private function ipTokens(): float
    {
        return (float) ($this->row('SELECT tokens FROM vault_rate WHERE bucket = ?', [UnlockService::ipBucket(self::IP)])['tokens'] ?? -1);
    }

    // A payload with every field kind: tabs and spaces kept, Unicode, tags, expiry, a TOTP seed, plain and protected
    // custom fields.
    private static function payload(string $title): array
    {
        return [
            'title' => $title,
            'username' => "\tuser ✓ ",
            'password' => Fixtures::ENTRY_PASSWORD."\t ",
            'url' => 'https://example.test/'.rawurlencode($title),
            'notes' => "line one\n\tline two  ",
            'tags' => ['work', 'ünï'],
            'expires_at' => 1893553445,
            'otp' => Fixtures::ENTRY_OTP,
            'fields' => [
                ['name' => 'Plain', 'value' => "plain\tvalue ", 'protected' => false],
                ['name' => 'Secret', 'value' => Fixtures::FIELD_VALUE, 'protected' => true],
            ],
        ];
    }

    /** @return array<string, array> title => the exported entry */
    private static function byTitle(array $answer): array
    {
        $out = [];
        foreach ($answer['entries'] as $e) {
            $out[$e['title']] = $e;
        }
        ksort($out);
        return $out;
    }

    // ---- Hardware keys (as HardwareKeysTest registers them, against server-issued challenges) ----------------------

    private function registerKey(SoftAuthenticator $key, string $sk): void
    {
        $c = $this->hw()->challenge($this->alice, 'register');
        $this->hw()->registerKey($this->alice, $sk, [
            'label' => 'key',
            'create' => $key->create($c, self::ORIGIN, self::RP),
            'assert' => $key->get($this->hw()->challenge($this->alice, 'ceremony'), self::ORIGIN, self::RP, HardwareKeys::prfSaltFor($c)),
            'others' => [],
        ], Fixtures::PASSPHRASE, self::IP);
    }

    private function assertionWire(SoftAuthenticator $key, string $purpose = 'ceremony'): string
    {
        $row = $this->row('SELECT prf_salt FROM vault_webauthn WHERE credential_id = ?', [$key->id()]);
        $a = $key->get($this->hw()->challenge($this->alice, $purpose), self::ORIGIN, self::RP, base64_decode($row['prf_salt']));
        $out = [];
        foreach ($a as $k => $v) {
            $out[$k] = is_string($v) && $k !== 'credential_id' ? WebAuthnVectors::b64u($v) : $v;
        }
        return json_encode($out);
    }

    // Spec, Export: "Export requires a fresh passphrase (and hardware-key) re-entry." An unlocked session alone gets
    // nothing: no, an empty or a wrong passphrase is unlock_failed through the unlock throttle (a failed guess on the
    // streak, an IP token, Argon2 only for a non-empty guess), and after five failures the back-off refuses even the
    // right passphrase (rate_limited, before Argon2). It is a POST with the CSRF token from vault.js, over HTTPS, from
    // an unlocked session. With a hardware key enrolled, the passphrase alone is hw_assertion_required (before any
    // Argon2), and a fresh assertion from a 'ceremony' challenge is needed; a replayed one is refused. The answer is
    // hardened and no-store, and never echoes the passphrase. Kills: no passphrase check; a check outside the throttle;
    // the hardware-key step skipped; a GET, a missing token or a locked session answered; plain HTTP answered.
    public function testExportRequiresFreshReauth(): void
    {
        $sk = $this->unlock($this->alice, Fixtures::PASSPHRASE, 'sid-alice');
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'Mine']);
        $this->store()->createEntry($this->alice, $g, self::payload('Mail'));

        $t0 = $this->ipTokens();
        foreach (['no passphrase' => [], 'empty' => ['passphrase' => ''], 'wrong' => ['passphrase' => Fixtures::WRONG_PASSPHRASE]] as $what => $body) {
            $s0 = $this->streak();
            $calls = $this->argonCalls;
            $r = $this->export($body);
            $this->assertHardened($r, $what);
            $this->assertSame([401, ['ok' => false, 'reason' => 'unlock_failed']], [$r->status, $r->json_()], $what);
            $this->assertSame(($body['passphrase'] ?? '') === '' ? $calls : $calls + 1, $this->argonCalls, "$what: Argon2 only for a non-empty guess");
            $this->assertSame($s0 + 1, $this->streak(), "$what: a failed guess on the streak");
        }
        $this->assertEqualsWithDelta($t0 - 3, $this->ipTokens(), 0.01, 'each refusal paid an IP token');

        // Not a POST, no token, not vault.js, plain HTTP: refused before any Argon2.
        $calls = $this->argonCalls;
        $get = $this->call(ExportController::class, 'export', 'GET', ['passphrase' => Fixtures::PASSPHRASE, 'csrf_token' => $this->token()], [], true);
        $this->assertSame([403, 'forbidden'], [$get->status, $get->json_()['reason'] ?? null], 'GET');
        $noToken = $this->call(ExportController::class, 'export', 'POST', ['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([403, 'forbidden'], [$noToken->status, $noToken->json_()['reason'] ?? null], 'no CSRF token');
        $native = $this->export(['passphrase' => Fixtures::PASSPHRASE], [], false);
        $this->assertSame(303, $native->status, 'a native form POST gets no JSON page of secrets');
        $this->assertStringNotContainsString(Fixtures::ENTRY_PASSWORD, $native->body);
        $plain = $this->export(['passphrase' => Fixtures::PASSPHRASE], ['HTTPS' => '']);
        $this->assertSame([403, 'https_required'], [$plain->status, $plain->json_()['reason'] ?? null], 'plain HTTP');
        $this->assertSame($calls, $this->argonCalls, 'no Argon2 for a refused request');

        // The right passphrase: the entries, hardened and no-store; the streak resets.
        $ok = $this->export(['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame(200, $ok->status, $ok->body);
        $this->assertHardened($ok, 'export');
        $this->assertSame(['Mail'], array_keys(self::byTitle($ok->json_())));
        $this->assertSame(0, $this->streak(), 'a correct passphrase resets the streak');
        $this->assertStringNotContainsString(Fixtures::PASSPHRASE, $ok->body.implode('', $ok->headers));

        // Back-off: after five failures in a row even the right passphrase is refused, before Argon2 (R15).
        for ($i = 0; $i < 5; $i++) {
            $this->export(['passphrase' => Fixtures::WRONG_PASSPHRASE]);
        }
        $calls = $this->argonCalls;
        $limited = $this->export(['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([429, 'rate_limited', $calls], [$limited->status, $limited->json_()['reason'] ?? null, $this->argonCalls], 'back-off');
        $this->now += 3600;

        // Locked: nothing, whatever the passphrase.
        $this->session()->lock($this->alice);
        $locked = $this->export(['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([401, 'locked'], [$locked->status, $locked->json_()['reason'] ?? null], 'locked');
        $sk = $this->unlock($this->alice, Fixtures::PASSPHRASE, 'sid-alice-2');

        // With a hardware key: the passphrase alone isn't enough; a fresh assertion is, once.
        $key = new SoftAuthenticator(-8);
        $this->registerKey($key, $sk);
        $sk = $this->session()->secretKey() ?? $sk;
        $calls = $this->argonCalls;
        $noKey = $this->export(['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame([403, 'hw_assertion_required', $calls], [$noKey->status, $noKey->json_()['reason'] ?? null, $this->argonCalls], 'passphrase only');
        $wire = $this->assertionWire($key);
        $wrong = $this->export(['passphrase' => Fixtures::WRONG_PASSPHRASE, 'assertion' => $wire]);
        $this->assertSame([401, 'unlock_failed'], [$wrong->status, $wrong->json_()['reason'] ?? null], 'a key with the wrong passphrase');
        $wire = $this->assertionWire($key);
        $withKey = $this->export(['passphrase' => Fixtures::PASSPHRASE, 'assertion' => $wire]);
        $this->assertSame(200, $withKey->status, $withKey->body);
        $this->assertSame(['Mail'], array_keys(self::byTitle($withKey->json_())));
        $replay = $this->export(['passphrase' => Fixtures::PASSPHRASE, 'assertion' => $wire]);
        $this->assertNotSame(200, $replay->status, 'a replayed assertion is refused');
        $this->assertArrayNotHasKey('entries', $replay->json_());
        sodium_memzero($sk);
    }

    // Spec, Audit: "Every export is audited", as export with actor_user_id and count only (the allowlist); every other
    // column NULL, nothing else written. A refused export writes no export row. Kills: no audit row; a count that isn't
    // what was sent; an extra column (an object id, an IP); an export row for a refused request.
    public function testExportAudited(): void
    {
        $sk = $this->unlock($this->alice, Fixtures::PASSPHRASE, 'sid-alice');
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'Mine']);
        $sub = $this->store()->createGroup($this->alice, $g, ['name' => 'Sub']);
        foreach (['a' => $g, 'b' => $g, 'c' => $sub] as $title => $group) {
            $this->store()->createEntry($this->alice, $group, self::payload($title));
        }
        $this->export(['passphrase' => Fixtures::WRONG_PASSPHRASE]);
        $this->assertSame([], $this->auditRows('export'), 'a refused export is not an export');

        $r = $this->export(['passphrase' => Fixtures::PASSPHRASE]);
        $this->assertSame(200, $r->status, $r->body);
        $rows = $this->auditRows('export');
        $this->assertCount(1, $rows);
        $row = $rows[0];
        // actor_kind and via are derived as for every row (cli under PHPUnit); the export fills only these two.
        $this->assertSame([(int) $this->alice, 3], [(int) $row['actor_user_id'], (int) $row['count']]);
        foreach (['object_type', 'object_id', 'share_hash', 'target_user_id', 'ip_trunc', 'ua_family'] as $col) {
            $this->assertNull($row[$col], "$col is NULL");
        }
        $this->assertSame(3, count($r->json_()['entries']));
        foreach ($this->auditRows() as $a) {
            $this->assertStringNotContainsString(Fixtures::ENTRY_PASSWORD, json_encode($a));
        }
        sodium_memzero($sk);
    }

    // Spec, Export: "It covers the user's own entries, with an option to include entries shared with them." Without
    // include_shared: alice's own groups (with their nesting) and every entry in them, field for field. With it: also
    // a group bob shared with her (and its entries), and an entry bob shared on its own (group_id null), marked shared.
    // R23: only live grants count (an expired grant's group is left out), bob's unshared entry never appears, and an
    // own entry that can't be decrypted is skipped and counted, not a failed export. Kills: shared entries always
    // included or never; an expired grant honoured; a field dropped or rewritten; the nesting flattened; one bad row
    // failing the export.
    public function testIncludeSharedOptional(): void
    {
        $bobSk = $this->skFor($this->bob, Fixtures::BOB_PASSPHRASE);
        $s = $this->store();
        $shared = $s->createGroup($this->bob, null, ['name' => 'Ops']);
        $s->createEntry($this->bob, $shared, self::payload('bob in shared group'));
        $bobOwn = $s->createGroup($this->bob, null, ['name' => 'Bob only']);
        $loose = $s->createEntry($this->bob, $bobOwn, self::payload('bob shared alone'));
        $s->createEntry($this->bob, $bobOwn, self::payload('bob private'));
        $child = $s->createGroup($this->bob, $bobOwn, ['name' => 'Shared child']);
        $s->createEntry($this->bob, $child, self::payload('bob in shared child'));
        $expired = $s->createGroup($this->bob, null, ['name' => 'Expired']);
        $s->createEntry($this->bob, $expired, self::payload('bob expired'));
        $this->grants()->grant($this->bob, 'group', $shared, $this->alice, 'read', null, $bobSk);
        $this->grants()->grant($this->bob, 'entry', $loose, $this->alice, 'read', null, $bobSk);
        $this->grants()->grant($this->bob, 'group', $child, $this->alice, 'read', null, $bobSk);
        $this->grants()->grant($this->bob, 'group', $expired, $this->alice, 'read', $this->now + 60, $bobSk);
        sodium_memzero($bobSk);

        $sk = $this->unlock($this->alice, Fixtures::PASSPHRASE, 'sid-alice');
        $g = $s->createGroup($this->alice, null, ['name' => 'Mine']);
        $sub = $s->createGroup($this->alice, $g, ['name' => 'Sub ✓']);
        $s->createEntry($this->alice, $g, self::payload('alice top'));
        $s->createEntry($this->alice, $sub, self::payload('alice nested'));
        $broken = $s->createEntry($this->alice, $sub, self::payload('alice broken'));
        $this->pdo()->prepare('UPDATE vault_entries SET ciphertext = ? WHERE id = ?')->execute([base64_encode(random_bytes(64)), $broken]);
        // The Expired grant lapses after the unlock (whose housekeeping would sweep it), so the export itself must skip it.
        $this->now += 120;
        $lapsed = $this->pdo()->prepare('SELECT COUNT(*) FROM vault_grants WHERE subject_type = ? AND subject_id = ? AND expires_at < ?');
        $lapsed->execute(['group', $expired, $this->now]);
        $this->assertSame(1, (int) $lapsed->fetchColumn(), 'the lapsed grant is still on record');
        // Each request's housekeeping sweeps a lapsed grant first; the store must skip it on its own too (R23).
        $direct = (new ObjectStore($this->container, $this->clock()))->exportFor($this->alice, $sk, true);
        $this->assertNotContains($expired, array_column($direct['groups'], 'id'), 'a lapsed grant exports nothing');
        $this->assertSame(1, $direct['skipped'], 'only the broken entry is skipped');
        $this->assertArrayNotHasKey('bob expired', self::byTitle($direct));

        $own = $this->export(['passphrase' => Fixtures::PASSPHRASE])->json_();
        $this->assertSame(['alice nested', 'alice top'], array_keys(self::byTitle($own)), 'own entries only');
        $this->assertSame(1, $own['skipped'], 'the broken entry is skipped and counted');
        $this->assertSame([
            ['id' => $g, 'parent_id' => null, 'name' => 'Mine', 'shared' => false],
            ['id' => $sub, 'parent_id' => $g, 'name' => 'Sub ✓', 'shared' => false],
        ], $own['groups']);
        foreach (self::byTitle($own) as $title => $e) {
            $this->assertSame(['group_id' => $title === 'alice top' ? $g : $sub] + EntryPayload::validate(self::payload($title)), $e, "$title: field for field");
        }
        $this->assertSame(2, (int) $this->auditRows('export')[0]['count']);

        foreach (['1', 'on'] as $flag) {
            $all = $this->export(['passphrase' => Fixtures::PASSPHRASE, 'include_shared' => $flag])->json_();
            $this->assertSame(['alice nested', 'alice top', 'bob in shared child', 'bob in shared group', 'bob shared alone'], array_keys(self::byTitle($all)), "include_shared=$flag");
            $this->assertContains(['id' => $shared, 'parent_id' => null, 'name' => 'Ops', 'shared' => true], $all['groups']);
            // A shared subgroup whose parent isn't shared is a root of the export.
            $this->assertContains(['id' => $child, 'parent_id' => null, 'name' => 'Shared child', 'shared' => true], $all['groups']);
            $this->assertCount(4, $all['groups'], 'neither Bob only nor Expired');
            $this->assertSame($shared, self::byTitle($all)['bob in shared group']['group_id']);
            $this->assertNull(self::byTitle($all)['bob shared alone']['group_id'], 'shared on its own: no group');
            $this->assertSame(EntryPayload::validate(self::payload('bob shared alone')), array_diff_key(self::byTitle($all)['bob shared alone'], ['group_id' => 1]));
        }
        $off = $this->export(['passphrase' => Fixtures::PASSPHRASE, 'include_shared' => '0'])->json_();
        $this->assertSame(['alice nested', 'alice top'], array_keys(self::byTitle($off)), 'include_shared=0');
        $this->assertSame([2, 5, 5, 2], array_map(static fn (array $r): int => (int) $r['count'], $this->auditRows('export')));
        sodium_memzero($sk);
    }
}
