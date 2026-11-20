<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Model\Notifier;
use Kanboard\Plugin\Vault\Model\RateLimitAudit;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\UnlockService;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Unlock items carried to T11: ua_family in the session audit rows, rate_limited aggregated per bucket (R39), the
// five-failure email sent outside the Argon2 slot (R39), and the rotation resumed at unlock in bounded batches
// outside the slot (R32/R33).
class UnlockCarriesTest extends Base
{
    use ServiceFixture;

    private const UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0';
    /** @var list<bool> */
    private array $slotFreeAtNotice = [];
    private int $notices = 0;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $test = $this;
        $this->container['vaultNotifier'] = fn () => new class($this->container, $test) extends Notifier {
            public function __construct($c, private $t) { parent::__construct($c); }
            public function emailConfigured(): bool { return true; }
            protected function send(int $userId, string $subject, string $html): bool { return $this->t->noticeSent($userId); }
        };
        $this->loginAs($this->alice);
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->container['request'] = new Request($this->container, ['HTTPS' => 'on', 'HTTP_HOST' => 'kb.example', 'REQUEST_METHOD' => 'POST', 'SCRIPT_NAME' => '/index.php', 'HTTP_USER_AGENT' => self::UA]);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    public function noticeSent(int $userId): bool
    {
        $this->notices++;
        $slot = $this->slots()->acquire($userId);
        $this->slotFreeAtNotice[] = $slot !== null;
        $slot?->release();
        return true;
    }

    // Kills: ua_family not passed to unlock or unlock_failed (NULL), or the raw header stored.
    public function testUnlockRowsCarryTheUaFamily(): void
    {
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, Fixtures::WRONG_PASSPHRASE, self::IP));
        $this->unlockService()->unlock($this->alice, Fixtures::PASSPHRASE, self::IP);
        $rows = array_values(array_filter($this->auditRows(), static fn ($r) => in_array($r['action'], ['unlock', 'unlock_failed'], true)));
        $this->assertSame([['unlock_failed', 'Firefox 140 / Linux'], ['unlock', 'Firefox 140 / Linux']], array_map(static fn ($r) => [$r['action'], $r['ua_family']], $rows));
    }

    // R39: refusals by the principal's back-off are one rate_limited row for the window with the principal as
    // target; refusals by the per-IP bucket have no target. Kills: a row per refusal; the target on an IP refusal;
    // no row at all.
    public function testRateLimitedRefusalsAreAggregated(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, Fixtures::WRONG_PASSPHRASE, self::IP));
        }
        for ($i = 0; $i < 3; $i++) {
            $this->assertVaultError('rate_limited', fn () => $this->unlockService()->unlock($this->alice, Fixtures::PASSPHRASE, self::IP));
        }
        $this->assertSame([], $this->auditRows('rate_limited'));

        $this->now += 3600 * 2; // the back-off is over; drain the IP bucket of another address
        $limiter = $this->limiter();
        while ($limiter->consume(UnlockService::ipBucket('198.51.100.7'), UnlockService::IP_FAILURES, UnlockService::IP_FAILURES / UnlockService::IP_WINDOW)) {
        }
        $this->assertVaultError('rate_limited', fn () => $this->unlockService()->unlock($this->alice, Fixtures::PASSPHRASE, '198.51.100.7'));
        $this->now += RateLimitAudit::WINDOW;
        (new RateLimitAudit($this->container, $this->clock()))->flush();
        $got = array_map(static fn ($r) => [$r['target_user_id'] === null ? null : (int) $r['target_user_id'], $r['ip_trunc'], (int) $r['count']], $this->auditRows('rate_limited'));
        $this->assertSame([[$this->alice, '203.0.113.0/24', 3], [null, '198.51.100.0/24', 1]], $got);
    }

    // R39: the five-failure email goes after the Argon2 slot is released (a slow mail server must not hold a
    // slot). Kills: the notice sent from inside FailedGuess::record while unlock still holds the slot.
    public function testFailureNoticeIsSentOutsideTheArgonSlot(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, Fixtures::WRONG_PASSPHRASE, self::IP));
        }
        $this->assertSame(1, $this->notices);
        $this->assertSame([true], $this->slotFreeAtNotice);
    }

    // R32/R33: a rotation resumed at unlock sweeps at most ROTATION_BATCHES batches, after the slot is released;
    // the rest waits for later requests (Housekeeping). Kills: complete() (unbounded) at unlock; the sweep inside
    // the slot.
    public function testRotationAtUnlockIsBoundedAndOutsideTheSlot(): void
    {
        $sk1 = $this->skFor($this->alice, Fixtures::PASSPHRASE);
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'g']);
        for ($i = 0; $i < 6; $i++) {
            $this->store()->createEntry($this->alice, $g, ['title' => "e$i"]);
        }
        $crash = true;
        $free = [];
        $hook = function (string $p) use (&$crash, &$free): void {
            if ($p === 'start' && $crash) {
                throw new RuntimeException('injected crash');
            }
            if ($p === 'batch') {
                $slot = $this->slots()->acquire($this->alice);
                $free[] = $slot !== null;
                $slot?->release();
            }
        };
        $rotation = new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session(), $hook, 1);
        try {
            $rotation->requestManual($this->alice, $sk1, Fixtures::PASSPHRASE, self::IP);
            $this->fail('expected the injected crash');
        } catch (RuntimeException $e) {
            $this->assertSame('injected crash', $e->getMessage());
        }
        $crash = false;
        $this->pdo()->exec('DELETE FROM vault_sessions');

        $unlock = new UnlockService($this->container, $this->slots(), $this->argon(), $this->session(), $this->limiter(), $this->clock(), $rotation, $this->recovery(), 2);
        $unlock->unlock($this->alice, Fixtures::PASSPHRASE, self::IP);
        $this->assertSame([true, true], $free, 'two batches, both with the slot free');
        $this->assertSame(5, $this->countRows('SELECT COUNT(*) FROM (SELECT DISTINCT object_type, object_id FROM vault_keys WHERE principal_id = ? AND principal_key_gen = 1) AS t', [$this->alice]));
        $this->assertNotNull($this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]), 'the rotation stays pending');
    }
}
