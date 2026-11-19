<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';

use Kanboard\ServiceProvider\MailProvider;
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

    // One wrong recovery code, past any back-off the earlier ones started (the code bucket backs off at its fifth).
    private function failCode(): void
    {
        $this->now += 3601;
        $bad = RecoveryCode::generate()['display'];
        $this->assertVaultError('unlock_failed', fn () => $this->recovery()->useCode($this->alice, $bad, Fixtures::NEW_PASSPHRASE, self::IP));
    }

    // I1: on a real install Kanboard registers smtp, sendmail and mail and defaults to mail from
    // notifications@kanboard.local; that is not configured email. With Kanboard's own MailProvider registration and
    // config values from Settings → Email: the stock sender is never enough, smtp needs MAIL_SMTP_HOSTNAME, and
    // sendmail needs its binary. Kills: the decision made from transport registration alone; the stock-sender check
    // removed (the plugin-transport case); the smtp host check removed.
    public function testCoreTransportsWithStockSettingsAreNotConfigured(): void
    {
        (new MailProvider())->register($this->container);
        $n = new Notifier($this->container);
        $this->assertSame(['smtp', 'sendmail', 'mail'], array_keys($this->container['emailClient']->getAvailableTransports()));
        $this->assertSame(Notifier::STOCK_SENDER, MAIL_FROM, 'this process runs with Kanboard\'s default sender');
        foreach (['mail', 'smtp', 'sendmail'] as $transport) {
            $this->container['configModel']->save(['mail_transport' => $transport, 'mail_sender_address' => '']);
            $this->container['memoryCache']->flush();
            $this->assertFalse($n->emailConfigured(), "$transport with the stock sender");
        }
        $this->container['configModel']->save(['mail_transport' => 'smtp', 'mail_sender_address' => 'vault@example.test']);
        $this->container['memoryCache']->flush();
        $this->assertSame(MAIL_SMTP_HOSTNAME !== '', $n->emailConfigured(), 'smtp follows MAIL_SMTP_HOSTNAME');
        $this->container['configModel']->save(['mail_transport' => 'sendmail']);
        $this->container['memoryCache']->flush();
        $bin = strtok(MAIL_SENDMAIL_COMMAND, ' ');
        $this->assertSame(is_file($bin) && is_executable($bin), $n->emailConfigured(), 'sendmail follows its binary');
        // A plugin transport (Resend's shape) owns its settings, but the stock sender still means nobody set up email.
        $this->container['emailClient']->setTransport('resend', \Kanboard\Core\Mail\Transport\Mail::class);
        $this->container['configModel']->save(['mail_transport' => 'resend', 'mail_sender_address' => '']);
        $this->container['memoryCache']->flush();
        $this->assertFalse($n->emailConfigured(), 'plugin transport with the stock sender');
        $this->container['configModel']->save(['mail_sender_address' => 'vault@example.test']);
        $this->container['memoryCache']->flush();
        $this->assertTrue($n->emailConfigured(), 'plugin transport with a real sender');
    }

    // The rule, branch by branch, with real files for the binaries. Kills: each condition of mailUsable removed or
    // inverted (registration, sender validity, stock sender, smtp host, executable check, plugin transports).
    public function testMailUsableRule(): void
    {
        $dir = sys_get_temp_dir().'/vault-mail-'.bin2hex(random_bytes(4));
        mkdir($dir);
        $exe = $dir.'/sendmail';
        $plain = $dir.'/not-exec';
        file_put_contents($exe, "#!/bin/sh\n");
        chmod($exe, 0755);
        file_put_contents($plain, '');
        chmod($plain, 0644);
        $core = ['smtp', 'sendmail', 'mail'];
        $ok = 'vault@example.test';
        try {
            $cases = [
                'smtp with host' => [true, 'smtp', $core, $ok, 'mail.example.test', '', ''],
                'smtp without host' => [false, 'smtp', $core, $ok, '  ', '', ''],
                'smtp, stock sender' => [false, 'smtp', $core, Notifier::STOCK_SENDER, 'mail.example.test', '', ''],
                'smtp, stock sender upper case' => [false, 'smtp', $core, 'Notifications@Kanboard.local', 'mail.example.test', '', ''],
                'smtp, invalid sender' => [false, 'smtp', $core, 'not an address', 'mail.example.test', '', ''],
                'sendmail binary' => [true, 'sendmail', $core, $ok, '', $exe.' -bs', ''],
                'sendmail missing' => [false, 'sendmail', $core, $ok, '', $dir.'/nope -bs', ''],
                'sendmail not executable' => [false, 'sendmail', $core, $ok, '', $plain.' -bs', ''],
                'mail via sendmail_path' => [true, 'mail', $core, $ok, '', '', $exe.' -t -i'],
                'mail, no sendmail_path' => [false, 'mail', $core, $ok, 'mail.example.test', $exe, ''],
                'plugin transport' => [true, 'resend', [...$core, 'resend'], $ok, '', '', ''],
                'unregistered transport' => [false, 'resend', $core, $ok, 'mail.example.test', $exe, $exe],
            ];
            foreach ($cases as $name => [$want, $transport, $registered, $sender, $host, $cmd, $path]) {
                $this->assertSame($want, Notifier::mailUsable($transport, $registered, $sender, $host, $cmd, $path), $name);
            }
        } finally {
            @unlink($exe);
            @unlink($plain);
            @rmdir($dir);
        }
    }

    // I2: bad codes first, then bad passphrases, are one streak: one email, at exactly the fifth. Kills: the streak
    // not shared between the two kinds of guess.
    public function testCodesThenPassphrasesNotifyOnceAtFive(): void
    {
        $this->configureEmail();
        $this->failCode();
        $this->failCode();
        $this->failUnlock();
        $this->failUnlock();
        $this->assertSame([], $this->sent);
        $this->failUnlock();
        $this->assertCount(1, $this->sent);
    }

    // I2: spending recovery-code guesses first can't suppress or fake the notice. Four bad codes, a good unlock and
    // one wrong passphrase is not five in a row; four more codes make five (one notice); after the eight stale code
    // failures, a good unlock and five wrong passphrases notify again at the fifth. Kills: the streak summed from back-off buckets that a success doesn't reset; the
    // unlock not resetting the streak.
    public function testPreSpentCodesCannotSuppressTheNotice(): void
    {
        $this->configureEmail();
        for ($i = 0; $i < 4; $i++) {
            $this->failCode();
        }
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-1');
        $this->failUnlock();
        $this->assertSame([], $this->sent, 'four stale code failures plus one is not five in a row');

        $this->failCode();
        $this->failCode();
        $this->failCode();
        $this->assertCount(0, $this->sent);
        $this->failCode();
        $this->assertCount(1, $this->sent, 'the fifth consecutive failure (one passphrase, then four codes)');
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-2');
        for ($i = 0; $i < 4; $i++) {
            $this->failUnlock();
        }
        $this->assertCount(1, $this->sent);
        $this->failUnlock();
        $this->assertCount(2, $this->sent, 'a new streak of five notifies again');
    }

    // A successful recovery-code use resets the streak too. Kills: the reset removed from useCode.
    public function testCodeUseResetsTheStreak(): void
    {
        $this->configureEmail();
        $this->recovery()->setPolicy(VaultSettings::POLICY_CODE, self::ADMIN);
        $sk = $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-1');
        $code = $this->recovery()->createCode($this->alice, $sk);
        for ($i = 0; $i < 4; $i++) {
            $this->failUnlock();
        }
        $this->assertSame(RotationService::ROTATED, $this->recovery()->useCode($this->alice, $code, Fixtures::NEW_PASSPHRASE, self::IP));
        $this->failUnlock();
        $this->assertSame([], $this->sent);
    }

    // The spec is silent past five, so a streak that goes on notifies again at each further multiple of five, never
    // in between. Kills: notifying only at exactly five (silent from then on), or at every failure from five.
    public function testLongStreakNotifiesAtEachMultipleOfFive(): void
    {
        $this->configureEmail();
        for ($i = 0; $i < 5; $i++) {
            $this->failCode();
        }
        $this->assertCount(1, $this->sent);
        for ($i = 0; $i < 4; $i++) {
            $this->failUnlock();
        }
        $this->assertCount(1, $this->sent);
        $this->now += 120; // past the unlock bucket's back-off after its fifth failure
        $this->failUnlock();
        $this->assertCount(2, $this->sent, 'the tenth');
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
