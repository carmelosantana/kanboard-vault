<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';

use Kanboard\Core\Log\File;
use Kanboard\Core\Log\Logger;
use Kanboard\Plugin\Vault\Crypto\RecoveryCode;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\Purger;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\ShareModel;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec: Audit, logging rules. "No secret, passphrase, vault key, PRF output, share key, burn capability or decrypted
// value is ever written to vault_audit, the PHP error log or Kanboard's logger. A test greps every log the suite
// produces for the fixture secrets." The test's bootstrap (setUp) routes Kanboard's logger, at debug level, and
// the PHP error log to temp files, and proves each capture works with a canary before trusting an empty grep.
// Every service then runs against the fixtures, failure paths included, and the logs, the audit table and every
// email are searched for every fixture secret and for the secrets the run itself generated.
class LogHygieneTest extends Base
{
    use ServiceFixture;

    private string $kbLog;
    private string $phpLog;
    private string|false $oldErrorLog;
    private string|false $oldLogErrors;
    private array $mails = [];
    /** @var list<string> secrets generated during the run (recovery code, org secret, keys) */
    private array $generated = [];

    protected function setUp(): void
    {
        parent::setUp();
        $dir = sys_get_temp_dir();
        $this->kbLog = tempnam($dir, 'vault-kblog-');
        $this->phpLog = tempnam($dir, 'vault-phplog-');
        $logger = new Logger();
        $driver = new File($this->kbLog);
        $driver->setLevel(\Psr\Log\LogLevel::DEBUG);
        $logger->setLogger($driver);
        $this->container['logger'] = $logger;
        $this->oldErrorLog = ini_set('error_log', $this->phpLog);
        $this->oldLogErrors = ini_set('log_errors', '1');
        $this->setUpVault();
        $this->pdo()->prepare('UPDATE users SET email = ? WHERE id IN (?, ?)')->execute(['user@example.test', $this->alice, $this->bob]);
        $this->configureEmail();
        $this->container['emailClient']->method('send')->willReturnCallback(function (...$args) {
            $this->mails[] = implode("\n", array_map('strval', $args));
            return $this->container['emailClient'];
        });
    }

    protected function tearDown(): void
    {
        ini_set('error_log', $this->oldErrorLog === false ? '' : $this->oldErrorLog);
        ini_set('log_errors', $this->oldLogErrors === false ? '0' : $this->oldLogErrors);
        @unlink($this->kbLog);
        @unlink($this->phpLog);
        $this->tearDownVault();
        parent::tearDown();
    }

    // Kills: a debug or warning line that carries a passphrase, recovery code, org secret, key or entry value;
    // an audit column filled from a secret; an email body built from one. The canary checks kill a capture that
    // silently stopped working (an empty log would otherwise pass).
    public function testNoFixtureSecretInLogs(): void
    {
        $canary = 'vault-log-canary-'.bin2hex(random_bytes(4));
        $this->container['logger']->debug($canary.'-kanboard');
        error_log($canary.'-php');

        $this->runEveryService();

        // Kanboard's own test tearDown dumps PicoDb's SQL log (statements and bound values) into the logger; do it
        // now, so that log is part of the grep.
        foreach ($this->container['db']->getLogMessages() as $msg) {
            $this->container['logger']->debug('SQL: '.$msg);
        }
        $kb = (string) file_get_contents($this->kbLog);
        $php = (string) file_get_contents($this->phpLog);
        $this->assertStringContainsString($canary.'-kanboard', $kb, 'Kanboard log capture works');
        $this->assertStringContainsString($canary.'-php', $php, 'PHP error log capture works');
        $this->assertStringContainsString('Vault: key rotation', $kb, 'the run reached a service warning path');
        $this->assertStringContainsString('SQL: ', $kb, 'the SQL log is captured');

        $audit = json_encode($this->auditRows(), JSON_THROW_ON_ERROR);
        $this->assertGreaterThan(20, count($this->auditRows()), 'the run audited its actions');
        $this->assertCount(3, $this->mails, 'the failure notice, the share-reveal notice and the org recovery notice');
        $haystacks = ['Kanboard log' => $kb, 'PHP error log' => $php, 'vault_audit' => $audit, 'emails' => implode("\n", $this->mails)];
        $needles = array_merge(Fixtures::SECRETS, $this->generated);
        $this->assertGreaterThan(count(Fixtures::SECRETS), count($needles));
        foreach ($haystacks as $where => $text) {
            foreach ($needles as $secret) {
                $this->assertStringNotContainsString($secret, $text, "a secret reached the $where");
                $this->assertStringNotContainsString(base64_encode($secret), $text, "a base64 secret reached the $where");
                $this->assertStringNotContainsString(bin2hex($secret), $text, "a hex secret reached the $where");
            }
        }
    }

    private function runEveryService(): void
    {
        $principals = $this->principals();
        $principals->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $principals->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->recovery()->setPolicy(VaultSettings::POLICY_CODE_ORG, self::ADMIN);
        $orgSecret = $this->recovery()->orgKeygen();
        $this->generated[] = $orgSecret;

        // Unlock: failures (the fifth emails), then success.
        for ($i = 0; $i < 4; $i++) {
            $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, Fixtures::WRONG_PASSPHRASE, self::IP));
        }
        $badCode = RecoveryCode::generate()['display'];
        $this->generated[] = $badCode;
        $this->assertVaultError('unlock_failed', fn () => $this->recovery()->useCode($this->alice, $badCode, Fixtures::NEW_PASSPHRASE, self::IP));
        $this->now += 3600;
        $sk = $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-alice');
        $this->generated[] = $sk;
        $this->assertGreaterThan(0, (new PrincipalModel($this->container))->failedAttemptsSinceLastUnlock($this->alice));

        // A one-time share (T17): created with a label, a wrong b, the reveal (which emails the creator, R19), the
        // list. Its id, b (hex and raw) and label are needles too.
        $shares = new ShareModel($this->container, $this->clock());
        $burn = bin2hex(random_bytes(16));
        $label = 'VaultFixtureSecret-sharelabel-'.bin2hex(random_bytes(4));
        $sidHash = (string) $this->session()->sidHash();
        $reserved = $shares->reserve($this->alice, $sidHash, '1d');
        array_push($this->generated, $burn, hex2bin($burn), $label, $reserved['share_id']);
        $shares->finalize($this->alice, $sidHash, [
            'share_id' => $reserved['share_id'], 'ciphertext' => base64_encode(random_bytes(64)), 'iv' => base64_encode(random_bytes(12)),
            'salt' => '', 'has_passphrase' => '0', 'burn_hash' => ShareModel::burnHash($burn), 'label' => $label,
        ]);
        $this->assertNull($shares->reveal($reserved['share_id'], bin2hex(random_bytes(16)), self::IP));
        $this->assertNotNull($shares->reveal($reserved['share_id'], $burn, self::IP, 'Firefox 140 / Linux'));
        $shares->listMine($this->alice, $sk);

        // Objects, grants, moves, revokes, re-keys.
        $s = $this->store();
        $g1 = $s->createGroup($this->alice, null, ['name' => 'group one', 'notes' => Fixtures::ENTRY_NOTES]);
        $g2 = $s->createGroup($this->alice, null, ['name' => 'group two']);
        $e = $s->createEntry($this->alice, $g1, Fixtures::entry());
        $this->assertSame(Fixtures::ENTRY_PASSWORD, $s->readField($this->alice, $e, 'password', $sk));
        $this->assertSame(Fixtures::FIELD_VALUE, $s->readField($this->alice, $e, 'field:api key', $sk));
        $s->listEntries($this->alice, $g1, $sk);
        $s->updateEntry($this->alice, $e, 1, Fixtures::entry('renamed'), $sk);
        $s->updateEntry($this->alice, $e, 2, ['title' => 'renamed', 'password' => Fixtures::UPDATED_PASSWORD], $sk);
        $this->grants()->grant($this->alice, 'group', $g1, $this->bob, 'edit', $this->now + 60, $sk);
        $bobSk = $this->skFor($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->generated[] = $bobSk;
        $this->assertSame(Fixtures::UPDATED_PASSWORD, $s->readField($this->bob, $e, 'password', $bobSk));
        $this->grants()->move($this->alice, 'entry', $e, $g2, $sk);
        $this->grants()->move($this->alice, 'entry', $e, $g1, $sk);
        $this->grants()->revoke($this->alice, 'group', $g1, $this->bob, $sk);
        $this->assertVaultError('not_found', fn () => $s->readField($this->bob, $e, 'password', $bobSk));

        // Recovery code: create, use (with a hardware key it removes).
        $code = $this->recovery()->createCode($this->alice, $sk);
        $this->generated[] = $code;
        $this->addHardwareKey($this->alice, $sk);
        $this->assertSame(RotationService::ROTATED, $this->recovery()->useCode($this->alice, $code, Fixtures::NEW_PASSPHRASE, self::IP));

        // A passphrase change whose rotation stalls after start (a warning is logged), then finishes at unlock.
        $sk = $this->skFor($this->alice, Fixtures::NEW_PASSPHRASE);
        $stalling = new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session(), function (string $point): void {
            if ($point === 'batch') {
                throw new RuntimeException('simulated crash');
            }
        }, 1);
        $this->assertSame(RotationService::PENDING, (new PrincipalModel($this->container, $this->slots(), $this->argon(), $this->clock(), $stalling))
            ->changePassphrase($this->alice, Fixtures::NEW_PASSPHRASE, Fixtures::PASSPHRASE, $sk, self::IP));
        $sk = $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-alice-2');
        $this->generated[] = $sk;
        $this->assertSame(Fixtures::UPDATED_PASSWORD, $s->readField($this->alice, $e, 'password', $sk));

        // Org recovery, settings, purge, delete, lock.
        $this->assertSame(RotationService::ROTATED, $this->recovery()->orgRecover('alice-the-auditor', $orgSecret, Fixtures::NEW_PASSPHRASE));
        $this->settings()->set('vault_idle_timeout', 30, self::ADMIN);
        $this->now += 120;
        (new Purger($this->container))->run($this->now, true);
        $sk = $this->unlockAs($this->alice, Fixtures::NEW_PASSPHRASE, 'sid-alice-3');
        $this->generated[] = $sk;
        $s->deleteObject($this->alice, 'group', $g1, $sk);
        $this->session()->lock($this->alice);
    }
}
