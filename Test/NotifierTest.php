<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';

use Kanboard\Core\Mail\Transport\Mail;
use Kanboard\Plugin\Vault\Crypto\RecoveryCode;
use Kanboard\Plugin\Vault\Model\Notifier;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// R19: email notices through Kanboard's emailClient, skipped when email isn't configured. Spec: after 5 consecutive
// failed unlocks the user is emailed (recovery-code failures count toward the same 5); org recovery notifies the
// user; a share reveal notifies its sender; an agent's owner is told of its bad-key failures and rate limits.
// No secret ever appears in an email.
class NotifierTest extends Base
{
    use ServiceFixture;

    /** @var list<array{0:string,1:string,2:string,3:string}> */
    private array $sent = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->pdo()->prepare('UPDATE users SET email = ?, name = ? WHERE id = ?')->execute(['alice@example.test', 'Alice A', $this->alice]);
        $this->pdo()->prepare('UPDATE users SET email = ? WHERE id = ?')->execute(['bob@example.test', $this->bob]);
        $this->container['emailClient']->method('send')->willReturnCallback(function (...$args) {
            $this->sent[] = array_slice($args, 0, 4);
            return $this->container['emailClient'];
        });
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function configureEmail(): void
    {
        $this->container['emailClient']->setTransport('mail', Mail::class);
    }

    private function failUnlock(): void
    {
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, Fixtures::WRONG_PASSPHRASE, self::IP));
    }

    private function assertNoSecretIn(array $mail): void
    {
        foreach (Fixtures::SECRETS as $secret) {
            $this->assertStringNotContainsString($secret, implode("\n", $mail));
        }
    }

    // Without a usable transport nothing is queued, and the caller isn't disturbed. Kills: the configured check
    // removed (send would be called).
    public function testSkipsWhenEmailIsNotConfigured(): void
    {
        $n = new Notifier($this->container);
        $this->assertFalse($n->emailConfigured());
        $this->assertFalse($n->orgRecovered($this->alice));
        for ($i = 0; $i < 5; $i++) {
            $this->failUnlock();
        }
        $this->assertSame([], $this->sent);
    }

    // A user without an email address gets nothing even with a transport. Kills: an empty recipient sent.
    public function testSkipsAUserWithoutEmail(): void
    {
        $this->configureEmail();
        $this->pdo()->prepare("UPDATE users SET email = '' WHERE id = ?")->execute([$this->alice]);
        $this->assertFalse((new Notifier($this->container))->orgRecovered($this->alice));
        $this->assertSame([], $this->sent);
    }

    // Four failed unlocks and one failed recovery code are five consecutive failures: one email, at the fifth, and
    // none for the sixth. Kills: recovery failures not counted; notifying on every failure (>= instead of ==);
    // the notify call removed.
    public function testFiveFailuresEmailOnceCountingRecoveryCodes(): void
    {
        $this->configureEmail();
        $this->recovery()->setPolicy(VaultSettings::POLICY_CODE, self::ADMIN);
        for ($i = 0; $i < 4; $i++) {
            $this->failUnlock();
        }
        $this->assertSame([], $this->sent);
        $bad = RecoveryCode::generate()['display'];
        $this->assertVaultError('unlock_failed', fn () => $this->recovery()->useCode($this->alice, $bad, Fixtures::NEW_PASSPHRASE, self::IP));
        $this->assertCount(1, $this->sent);
        [$to, $name, $subject, $html] = $this->sent[0];
        $this->assertSame(['alice@example.test', 'Alice A'], [$to, $name]);
        $this->assertStringContainsString('5', $subject);
        $this->assertNoSecretIn($this->sent[0]);
        $this->assertStringNotContainsString($bad, $html);
        $this->assertSame(5, count($this->auditRows('unlock_failed')));

        $this->failUnlock();
        $this->assertCount(1, $this->sent, 'the sixth failure sends nothing more');
    }

    // A success resets the count, so a later streak of five emails again. Kills: the count not reset.
    public function testSuccessStartsANewStreak(): void
    {
        $this->configureEmail();
        for ($i = 0; $i < 4; $i++) {
            $this->failUnlock();
        }
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-1');
        for ($i = 0; $i < 4; $i++) {
            $this->failUnlock();
        }
        $this->assertSame([], $this->sent);
        $this->failUnlock();
        $this->assertCount(1, $this->sent);
    }

    // Org recovery emails the user once it has committed, without any secret. Kills: the call removed.
    public function testOrgRecoveryEmailsTheUser(): void
    {
        $this->configureEmail();
        $this->recovery()->setPolicy(VaultSettings::POLICY_CODE_ORG, self::ADMIN);
        $display = $this->recovery()->orgKeygen();
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-1');
        $this->assertSame(RotationService::ROTATED, $this->recovery()->orgRecover('alice-the-auditor', $display, Fixtures::NEW_PASSPHRASE));
        $this->assertCount(1, $this->sent);
        $this->assertSame('alice@example.test', $this->sent[0][0]);
        $this->assertNoSecretIn($this->sent[0]);
        $this->assertStringNotContainsString($display, implode("\n", $this->sent[0]));
    }

    // R33: once the recovery has committed, a notifier failure is contained. Kills: the post-commit try/catch
    // around the notice removed (orgRecover would throw after the change happened).
    public function testNotifierFailureAfterOrgRecoveryIsContained(): void
    {
        $this->container['vaultNotifier'] = fn () => new class($this->container) extends Notifier {
            public function orgRecovered(int $userId): bool { throw new RuntimeException('smtp down'); }
        };
        $this->recovery()->setPolicy(VaultSettings::POLICY_CODE_ORG, self::ADMIN);
        $display = $this->recovery()->orgKeygen();
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-1');
        $this->assertSame(RotationService::ROTATED, $this->recovery()->orgRecover('alice-the-auditor', $display, Fixtures::NEW_PASSPHRASE));
        $this->assertCount(1, $this->auditRows('org_recovery'));
    }

    // The failure-count notice is contained too: a notifier that throws never turns a failed guess into anything
    // but unlock_failed. Kills: the try/catch around the notice removed.
    public function testNotifierFailureOnFailuresIsContained(): void
    {
        $this->container['vaultNotifier'] = fn () => new class($this->container) extends Notifier {
            public function unlockFailures(int $userId): bool { throw new RuntimeException('smtp down'); }
        };
        for ($i = 0; $i < 5; $i++) {
            $this->failUnlock();
        }
        $this->assertCount(5, $this->auditRows('unlock_failed'));
    }

    // The hooks T16/T18 call: a share reveal tells the creator; an agent's bad key or rate limit tells its owner,
    // and a user who isn't an agent has no owner to tell. Kills: the wrong recipient; a non-agent notified.
    public function testShareAndAgentHooks(): void
    {
        $this->configureEmail();
        $n = new Notifier($this->container);
        $this->assertTrue($n->shareRevealed($this->bob));
        $this->assertSame('bob@example.test', $this->sent[0][0]);
        if (! class_exists(\Kanboard\Plugin\Agents\Model\AgentTable::class)) {
            $this->markTestSkipped('Agents is not installed');
        }
        $this->agentsTable();
        $agent = (int) $this->container['userModel']->create(['username' => 'agent-x', 'password' => 'agent login password 1', 'email' => 'agent@example.test']);
        $this->adoptAgent($this->alice, $agent);
        $this->assertTrue($n->agentBadKey($agent));
        $this->assertTrue($n->agentRateLimited($agent));
        $this->assertSame(['alice@example.test', 'alice@example.test'], [$this->sent[1][0], $this->sent[2][0]]);
        $this->assertFalse($n->agentBadKey($this->bob));
        $this->assertCount(3, $this->sent);
        foreach ($this->sent as $mail) {
            $this->assertNoSecretIn($mail);
        }
    }
}
