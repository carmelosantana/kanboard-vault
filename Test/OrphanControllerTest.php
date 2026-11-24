<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServerFixture.php';
require_once __DIR__.'/Support/VaultTestResponse.php';
require_once __DIR__.'/Support/SoftAuthenticator.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Controller\OrphanController;
use Kanboard\Plugin\Vault\Model\HardwareKeys;
use Kanboard\Plugin\Vault\Model\Housekeeping;
use Kanboard\Plugin\Vault\Model\OrphanService;
use Kanboard\Plugin\Vault\Model\Purger;
use Kanboard\Plugin\Vault\Plugin;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use Kanboard\Plugin\Vault\Test\Support\SoftAuthenticator;
use KanboardTests\units\Base;

// Spec amendment: security requirement 14 with Codex NEW-02. The admin endpoints around OrphanService: claim (an
// unlocked admin with CSRF; the admin's key comes from the unlocked session, never the request) and destroy (an
// unlocked admin with CSRF and step-up: the vault passphrase re-entered through confirmPassphrase).
class OrphanControllerTest extends Base
{
    use ServerFixture;

    private const ADMIN_PASSPHRASE = 'VaultFixtureSecret-adminphrase-Vq3mK8';

    protected function setUp(): void
    {
        parent::setUp();
        $this->container['logger'] = $this->createMock(\Psr\Log\LoggerInterface::class);
        (new Plugin($this->container))->initialize();
        $this->setUpAgents();
        $this->principals()->enrolHuman($this->bob, Fixtures::NEW_PASSPHRASE);
        $this->principals()->enrolHuman(self::ADMIN, self::ADMIN_PASSPHRASE);
        $this->setUpServer();
        $this->enableServer();
        foreach (['vaultRotation', 'vaultHousekeeping', 'vaultOrphans', 'vaultSession'] as $service) {
            unset($this->container[$service]);
        }
        $this->container['vaultSession'] = fn () => $this->session();
        $this->container['vaultRotation'] = fn () => $this->rotation();
        $this->container['vaultHousekeeping'] = fn () => new Housekeeping($this->container, $this->clock(), $this->rotation());
        $this->container['vaultOrphans'] = fn () => new OrphanService($this->container, $this->clock());
    }

    protected function tearDown(): void
    {
        $this->tearDownServer();
        $this->tearDownVault();
        parent::tearDown();
    }

    private function token(): string
    {
        return $this->container['token']->getReusableCSRFToken();
    }

    // One POST to the orphan controller over HTTPS, carrying the vault cookie the last unlock set. A vault.js fetch
    // unless $ajax is false.
    private function post(string $action, array $post, bool $csrf = true, bool $ajax = true, string $method = 'POST'): VaultTestResponse
    {
        $server = ['REQUEST_METHOD' => $method, 'HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'SCRIPT_NAME' => '/index.php', 'REMOTE_ADDR' => self::IP];
        if ($ajax) {
            $server['HTTP_X_REQUESTED_WITH'] = 'XMLHttpRequest';
        }
        $last = $this->jar->last();
        $cookies = $last === null || $last['value'] === '' ? [] : [$last['name'] => $last['value']];
        $post += $csrf ? ['csrf_token' => $this->token()] : [];
        $this->container['request'] = new Request($this->container, $server, $method === 'GET' ? $post : [], $method === 'POST' ? $post : [], [], $cookies);
        $response = new VaultTestResponse($this->container);
        $this->container['response'] = $response;
        (new OrphanController($this->container))->$action();
        return $response;
    }

    private function assertHardened(VaultTestResponse $r, string $what): void
    {
        $this->assertTrue($r->sent, "$what: sent");
        $this->assertSame('DENY', $r->headers['X-Frame-Options'] ?? null, "$what: X-Frame-Options");
        $this->assertSame('no-store', $r->headers['Cache-Control'] ?? null, "$what: no-store");
    }

    private function unlockAdmin(): void
    {
        $this->jar->sets = [];
        $sk = $this->unlockAs(self::ADMIN, self::ADMIN_PASSPHRASE, 'sid-admin');
        sodium_memzero($sk);
    }

    private function entryExists(int $id): bool
    {
        return $this->row('SELECT id FROM vault_entries WHERE id = ?', [$id]) !== null;
    }

    private function epoch(int $id): int
    {
        return (int) $this->row('SELECT key_epoch FROM vault_entries WHERE id = ?', [$id])['key_epoch'];
    }

    // Alice's entry shared with Server and read-shared with the admin; alice is deleted and the purge quarantines it.
    /** @return array{0:int, 1:int} [entry, a group the admin owns] */
    private function orphan(): array
    {
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'OrphanFixtureGroupTitle']);
        $e = $this->store()->createEntry($this->alice, $g, Fixtures::fullEntry());
        $this->grants()->grantServer($this->alice, $e, ['CveHunter'], ['password'], null, null, $this->aliceSk());
        $this->grants()->grant($this->alice, 'entry', $e, self::ADMIN, 'read', null, $this->aliceSk());
        $adminGroup = $this->store()->createGroup(self::ADMIN, null, ['name' => 'claimed']);
        $this->assertTrue($this->container['userModel']->remove($this->alice));
        (new Purger($this->container))->run($this->now, true);
        return [$e, $adminGroup];
    }

    // Destroy is step-up: without the passphrase, or with a wrong one, it is the reauth failure (a throttled failed
    // guess) and the entry stays; with the right one the orphan goes. Kills: destroy without the step-up; the
    // reauth result ignored.
    public function testDestroyNeedsTheVaultPassphrase(): void
    {
        [$e] = $this->orphan();
        $this->unlockAdmin();
        foreach (['no passphrase' => [], 'wrong passphrase' => ['passphrase' => Fixtures::WRONG_PASSPHRASE]] as $what => $body) {
            $r = $this->post('destroy', ['entry_id' => (string) $e] + $body);
            $this->assertHardened($r, $what);
            $this->assertSame([401, ['ok' => false, 'reason' => 'unlock_failed']], [$r->status, $r->json_()], $what);
            $this->assertTrue($this->entryExists($e), "$what: the entry is still there");
        }
        $this->assertSame([], $this->auditRows('orphan_destroy'));

        $r = $this->post('destroy', ['entry_id' => (string) $e, 'passphrase' => self::ADMIN_PASSPHRASE]);
        $this->assertHardened($r, 'destroy');
        $this->assertSame([200, ['ok' => true]], [$r->status, $r->json_()]);
        $this->assertFalse($this->entryExists($e));
        $this->assertCount(1, $this->auditRows('orphan_destroy'));
        $this->assertStringNotContainsString(self::ADMIN_PASSPHRASE, $r->body.implode('', $r->headers));
    }

    // Minor 3 (final-wave step-up ruling): destroy's step-up is the vault passphrase alone, as for turning Server on,
    // so an admin with a hardware key destroys with the passphrase (the form has no assertion field) and not without.
    // Kills: requireFreshReauth's hardware-key assertion demanded (hw_assertion_required); no step-up for key users.
    public function testAHardwareKeyAdminDestroysWithThePassphrase(): void
    {
        [$e] = $this->orphan();
        $this->unlockAdmin();
        $this->container['configModel']->save(['application_url' => 'https://kb.example/']);
        $this->container['memoryCache']->flush();
        $hw = new HardwareKeys($this->container, $this->slots(), $this->argon(), $this->clock(), $this->rotation());
        $key = new SoftAuthenticator(-7);
        $c = $hw->challenge(self::ADMIN, 'register');
        $create = $key->create($c, 'https://kb.example', 'kb.example');
        $assert = $key->get($hw->challenge(self::ADMIN, 'ceremony'), 'https://kb.example', 'kb.example', HardwareKeys::prfSaltFor($c));
        $sk = (string) $this->session()->secretKey();
        $hw->registerKey(self::ADMIN, $sk, ['label' => 'Admin key', 'create' => $create, 'assert' => $assert, 'others' => []], self::ADMIN_PASSPHRASE, self::IP);
        sodium_memzero($sk);
        $this->assertSame(1, $hw->count(self::ADMIN));

        $r = $this->post('destroy', ['entry_id' => (string) $e]);
        $this->assertSame([401, ['ok' => false, 'reason' => 'unlock_failed']], [$r->status, $r->json_()], 'no passphrase');
        $this->assertTrue($this->entryExists($e));

        $r = $this->post('destroy', ['entry_id' => (string) $e, 'passphrase' => self::ADMIN_PASSPHRASE]);
        $this->assertSame([200, ['ok' => true]], [$r->status, $r->json_()]);
        $this->assertFalse($this->entryExists($e));
    }

    // Kills: no admin check on claim or destroy; an admin check that admits a grant-holding user.
    public function testNonAdminIsForbidden(): void
    {
        [$e, $adminGroup] = $this->orphan();
        $this->jar->sets = [];
        $sk = $this->unlockAs($this->bob, Fixtures::NEW_PASSPHRASE, 'sid-bob');
        sodium_memzero($sk);
        $claim = $this->post('claim', ['entry_id' => (string) $e, 'group_id' => (string) $adminGroup]);
        $destroy = $this->post('destroy', ['entry_id' => (string) $e, 'passphrase' => Fixtures::NEW_PASSPHRASE]);
        foreach (['claim' => $claim, 'destroy' => $destroy] as $what => $r) {
            $this->assertHardened($r, $what);
            $this->assertSame([403, ['ok' => false, 'reason' => 'forbidden']], [$r->status, $r->json_()], $what);
        }
        $this->assertTrue($this->entryExists($e));
        $this->assertSame([], $this->auditRows('orphan_claim'));
        // Requirement 18: the controller's refusal is audited too. Kills: requireAdmin failing before any denied row.
        foreach (['claim', 'destroy'] as $what) {
            $rows = $this->auditRows('orphan_'.$what.'_denied');
            $this->assertCount(1, $rows, $what);
            $this->assertSame([$this->bob, 'entry', $e, 'not_allowed'], [(int) $rows[0]['actor_user_id'], $rows[0]['object_type'], (int) $rows[0]['object_id'], $rows[0]['reason']], $what);
        }
    }

    // Requirement 18: a failed step-up writes orphan_destroy_denied with the step-up's code, and a locked claim writes
    // orphan_claim_denied locked. Kills: requireFreshReauth or requireUnlocked failing before any denied row.
    public function testStepUpAndLockedRefusalsAreAudited(): void
    {
        [$e, $adminGroup] = $this->orphan();
        $this->loginAs(self::ADMIN);
        $r = $this->post('claim', ['entry_id' => (string) $e, 'group_id' => (string) $adminGroup]);
        $this->assertSame(401, $r->status);
        $this->assertSame([[self::ADMIN, $e, 'locked']], array_map(static fn (array $row): array => [(int) $row['actor_user_id'], (int) $row['object_id'], $row['reason']], $this->auditRows('orphan_claim_denied')));

        $this->unlockAdmin();
        $r = $this->post('destroy', ['entry_id' => (string) $e, 'passphrase' => Fixtures::WRONG_PASSPHRASE]);
        $this->assertSame(401, $r->status);
        $this->assertSame([[self::ADMIN, $e, 'unlock_failed']], array_map(static fn (array $row): array => [(int) $row['actor_user_id'], (int) $row['object_id'], $row['reason']], $this->auditRows('orphan_destroy_denied')));
        $this->assertTrue($this->entryExists($e));
    }

    // Kills: a CSRF check dropped on either endpoint; a GET accepted.
    public function testClaimAndDestroyNeedCsrf(): void
    {
        [$e, $adminGroup] = $this->orphan();
        $epoch = $this->epoch($e);
        $this->unlockAdmin();
        $requests = [
            'claim without a token' => ['claim', ['entry_id' => (string) $e, 'group_id' => (string) $adminGroup], false, 'POST'],
            'destroy without a token' => ['destroy', ['entry_id' => (string) $e, 'passphrase' => self::ADMIN_PASSPHRASE], false, 'POST'],
            'claim as a GET' => ['claim', ['entry_id' => (string) $e, 'group_id' => (string) $adminGroup], true, 'GET'],
            'destroy as a GET' => ['destroy', ['entry_id' => (string) $e, 'passphrase' => self::ADMIN_PASSPHRASE], true, 'GET'],
        ];
        foreach ($requests as $what => [$action, $body, $csrf, $method]) {
            $r = $this->post($action, $body, $csrf, true, $method);
            $this->assertSame([403, ['ok' => false, 'reason' => 'forbidden']], [$r->status, $r->json_()], $what);
        }
        $this->assertTrue($this->entryExists($e));
        $this->assertSame($epoch, $this->epoch($e));
    }

    // The admin's key comes from the unlocked session: locked, the claim is the locked failure; a secret key in the
    // body changes nothing. Unlocked with a group the admin owns, the claim re-keys: 200 and the new key_epoch.
    // Kills: an sk read from the request; the claim answered without key_epoch.
    public function testClaimNeedsAnUnlockedAdmin(): void
    {
        [$e, $adminGroup] = $this->orphan();
        $epoch = $this->epoch($e);
        $this->loginAs(self::ADMIN);
        $r = $this->post('claim', ['entry_id' => (string) $e, 'group_id' => (string) $adminGroup, 'sk' => base64_encode($this->skFor(self::ADMIN, self::ADMIN_PASSPHRASE))]);
        $this->assertHardened($r, 'locked');
        $this->assertSame([401, ['ok' => false, 'reason' => 'locked']], [$r->status, $r->json_()]);
        $this->assertSame($epoch, $this->epoch($e));

        $this->unlockAdmin();
        $r = $this->post('claim', ['entry_id' => (string) $e, 'group_id' => (string) $adminGroup]);
        $this->assertHardened($r, 'claim');
        $this->assertSame([200, ['ok' => true, 'key_epoch' => $epoch + 1]], [$r->status, $r->json_()]);
        $this->assertSame($epoch + 1, $this->epoch($e));
        $this->assertSame(self::ADMIN, (int) $this->row('SELECT owner_id FROM vault_entries WHERE id = ?', [$e])['owner_id']);
    }

    // A refusal from OrphanService comes back in the generic shape (a bad group is not_found), the entry unchanged;
    // native form POSTs (no JS) go back to Settings → Vault with only a fixed code.
    public function testRefusalsAndNativeForms(): void
    {
        [$e, $adminGroup] = $this->orphan();
        $epoch = $this->epoch($e);
        $this->unlockAdmin();
        $carolGroup = $this->store()->createGroup($this->carol, null, ['name' => 'carol']);
        $r = $this->post('claim', ['entry_id' => (string) $e, 'group_id' => (string) $carolGroup]);
        $this->assertSame([404, ['ok' => false, 'reason' => 'not_found']], [$r->status, $r->json_()]);
        $this->assertSame($epoch, $this->epoch($e));

        $r = $this->post('claim', ['entry_id' => (string) $e, 'group_id' => (string) $carolGroup], true, false);
        $this->assertSame(303, $r->status);
        $this->assertSame('/?controller=SettingsController&action=index&plugin=Vault&vault_error=not_found', $r->headers['Location'] ?? null);

        // Minor 2: an admin without a grant gets the plain not_allowed answer, not the generic failure.
        $this->pdo()->prepare("DELETE FROM vault_grants WHERE subject_type = 'entry' AND subject_id = ? AND grantee_id = ?")->execute([$e, self::ADMIN]);
        $r = $this->post('claim', ['entry_id' => (string) $e, 'group_id' => (string) $adminGroup]);
        $this->assertSame([403, ['ok' => false, 'reason' => 'not_allowed']], [$r->status, $r->json_()]);
        $this->assertSame($epoch, $this->epoch($e));

        $r = $this->post('destroy', ['entry_id' => (string) $e, 'passphrase' => self::ADMIN_PASSPHRASE], true, false);
        $this->assertSame('/?controller=SettingsController&action=index&plugin=Vault&vault_notice=orphan_destroyed', $r->headers['Location'] ?? null);
        $this->assertFalse($this->entryExists($e));
    }
}
