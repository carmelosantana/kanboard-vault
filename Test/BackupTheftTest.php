<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/AgentFixture.php';

use Kanboard\Plugin\Vault\Model\HardwareKeys;
use Kanboard\Plugin\Vault\Model\Importer;
use Kanboard\Plugin\Vault\Model\Rekeyer;
use Kanboard\Plugin\Vault\Model\ShareModel;
use Kanboard\Plugin\Vault\Model\VaultDb;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use Kanboard\Plugin\Vault\Test\Support\SoftAuthenticator;
use Kanboard\ServiceProvider\DatabaseProvider;
use KanboardTests\units\Base;
use PicoDb\Database;

// Spec: Testing, backup theft. "Populate fixtures, dump the DB plus config, and assert that no fixture plaintext
// (titles, usernames, passwords, notes, group names) appears anywhere in the dump."
//
// The install runs on a real SQLite file in WAL mode (Kanboard's default), not the suite's :memory: DB, so the dump is
// what a thief copies off the disk: the main file, the -wal and -shm files (freed pages and stale WAL frames included:
// SQLite does not zero them), the file again after a checkpoint, a logical dump of every table, Kanboard's config.php,
// the environment, the Argon2 slot directory and Kanboard's DATA_DIR/*.log. Every secret-bearing path writes first:
// entries and groups (every payload slot), a nested group, read and edit grants to a user, a grant to an agent, an
// agent-written entry, both kinds of one-time share (with and without a passphrase) with a sealed label, an import, a
// recovery code, org-key escrow, a hardware key (WebAuthn PRF wrap, the rotation it triggers), a passphrase change and
// an unlocked vault session, and one wrong unlock. Each fixture marker and each secret the run generated (vault keys,
// the session cookie, PRF outputs, the recovery code, the org secret, the agent's vault key, the one-time share key and
// burn, the wrong guess, an entry's and a group's DEK) is searched for raw, as hex, and as base64 and base64url at all
// three byte alignments (so a value base64ed inside a bigger blob is found).
class BackupTheftTest extends Base
{
    use AgentFixture;

    private string $dbPath;
    /** @var list<string> secrets generated during the run */
    private array $generated = [];

    protected function setUp(): void
    {
        // The stolen backup is the SQLite file itself. Skipped before Base connects, so no server connection is left
        // open (a test that skips after connecting kept Postgres from dropping the test DB for every later test).
        require_once __DIR__.'/Support/Migrate.php';
        vault_test_sqlite_only();
        parent::setUp();
        $this->dbPath = tempnam(sys_get_temp_dir(), 'vault-backup-').'.sqlite';
        unset($this->container['db']);
        $db = new Database(['driver' => 'sqlite', 'filename' => $this->dbPath, 'wal_mode' => true]);
        DatabaseProvider::runMigrations($db);
        $this->container['db'] = $db;
        $this->assertSame('wal', strtolower((string) $this->pdo()->query('PRAGMA journal_mode')->fetchColumn()));
        $this->setUpAgents();
        $this->agentsTable();
    }

    protected function tearDown(): void
    {
        if (! isset($this->dbPath)) {
            return; // skipped before setUp connected
        }
        $this->tearDownVault();
        parent::tearDown();
        foreach (['', '-wal', '-shm', '-journal'] as $suffix) {
            @unlink($this->dbPath.$suffix);
        }
        @unlink(substr($this->dbPath, 0, -strlen('.sqlite')));
    }

    // Kills: any write path that stores a payload, label, field name, share plaintext or key in the clear, or
    // base64/hex-encodes one into a column (the mutants in the T24 report: a plaintext title column and an
    // unsealed share label each fail it). The canary proves the search reads the file: a value written in the clear
    // through the same connection is found in every byte form.
    public function testDumpHasNoPlaintext(): void
    {
        $this->populate();

        $canary = 'VaultBackupCanary-'.bin2hex(random_bytes(6));
        $this->pdo()->prepare('INSERT INTO settings (option, value) VALUES (?, ?)')->execute(['vault_test_canary', base64_encode($canary)]);
        $dump = $this->dump();
        $this->assertNotSame([], $this->hits($dump, $canary), 'the search finds a base64 value written to the DB file');
        $this->pdo()->exec("DELETE FROM settings WHERE option = 'vault_test_canary'");

        $this->assertGreaterThan(100_000, strlen($dump['sqlite -wal file']), 'the live WAL holds the run');
        $this->assertGreaterThan(100_000, strlen($dump['sqlite main file after checkpoint']), 'the checkpointed file holds the run');
        $this->assertGreaterThan(0, substr_count($dump['logical dump'], 'ciphertext'), 'the logical dump has the vault rows');
        $needles = array_merge(Fixtures::SECRETS, $this->generated);
        $this->assertGreaterThan(count(Fixtures::SECRETS) + 10, count($needles));
        $found = [];
        foreach ($needles as $i => $secret) {
            // Fixture markers are test strings and are named; generated secrets are numbered, never printed.
            $name = $i < count(Fixtures::SECRETS) ? $secret : 'generated secret #'.($i - count(Fixtures::SECRETS));
            foreach ($this->hits($dump, $secret) as $hit) {
                $found[] = "$name in $hit";
            }
        }
        $this->assertSame([], $found, 'plaintext in the stolen backup');
    }

    private function populate(): void
    {
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->recovery()->setPolicy(VaultSettings::POLICY_CODE_ORG, self::ADMIN);
        $this->generated[] = $this->recovery()->orgKeygen();

        $sk = $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-alice');
        $this->generated[] = $sk;
        $this->generated[] = $this->jar->last()['value'];
        $this->generated[] = $this->recovery()->createCode($this->alice, $sk);

        // Entries and groups: every payload slot, a nested group, an edit and a read grant.
        $s = $this->store();
        $top = $s->createGroup($this->alice, null, ['name' => Fixtures::GROUP_NAME, 'notes' => Fixtures::GROUP_NOTES]);
        $nested = $s->createGroup($this->alice, $top, ['name' => Fixtures::GROUP_NAME.'-nested']);
        $entry = $s->createEntry($this->alice, $nested, Fixtures::fullEntry());
        $s->updateEntry($this->alice, $entry, 1, ['password' => Fixtures::UPDATED_PASSWORD] + Fixtures::fullEntry(), $sk);
        $other = $s->createEntry($this->alice, $top, Fixtures::entry(Fixtures::ENTRY_TITLE.'-2'));
        $this->grants()->grant($this->alice, 'group', $top, $this->bob, 'edit', $this->now + 86400, $sk);
        $this->grants()->grant($this->alice, 'entry', $other, $this->carol, 'read', null, $sk);
        $bobSk = $this->skFor($this->bob, Fixtures::BOB_PASSPHRASE);
        $this->generated[] = $bobSk;
        $this->assertSame(Fixtures::UPDATED_PASSWORD, $s->readField($this->bob, $entry, 'password', $bobSk));
        $s->createEntry($this->bob, $nested, ['title' => Fixtures::ENTRY_TITLE.'-bob', 'password' => Fixtures::ENTRY_PASSWORD]);

        // An agent: enrolled, given a read grant, writing its own entry.
        $agentKey = $this->enrolDave();
        $this->generated[] = $agentKey;
        $this->grants()->grant($this->alice, 'group', $top, $this->dave, 'read', null, $sk);
        $this->agentVault()->createEntry($this->dave, ['title' => Fixtures::ENTRY_TITLE.'-agent', 'password' => Fixtures::AGENT_SECRET]);

        // An import (T22's server half): a root group, a sub-group path and a batch.
        $importer = new Importer($this->container, $this->clock());
        $root = $importer->start($this->alice);
        $this->assertSame(1, $importer->batch($this->alice, $root, [Fixtures::IMPORT_GROUP], [
            ['title' => Fixtures::ENTRY_TITLE.'-imported', 'password' => Fixtures::IMPORT_PASSWORD, 'notes' => Fixtures::ENTRY_NOTES],
        ], $sk));

        // One-time shares, both kinds: the browser encrypts (AES-256-GCM, its key in the link's fragment); the server
        // keeps the ciphertext and a sealed label. The passphrase kind's key also depends on the passphrase.
        $shares = new ShareModel($this->container, $this->clock());
        $sidHash = (string) $this->session()->sidHash();
        foreach ([false, true] as $withPassphrase) {
            $key = random_bytes(32);
            $salt = $withPassphrase ? random_bytes(16) : '';
            if ($withPassphrase) {
                $key = sodium_crypto_generichash(Fixtures::SHARE_PASSPHRASE, $key.$salt, 32);
            }
            $iv = random_bytes(12);
            $tag = '';
            $ct = openssl_encrypt(Fixtures::SHARE_SECRET, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
            $burn = bin2hex(random_bytes(16));
            $reserved = $shares->reserve($this->alice, $sidHash, '1d');
            array_push($this->generated, $key, $burn, hex2bin($burn), $reserved['share_id']);
            $shares->finalize($this->alice, $sidHash, [
                'share_id' => $reserved['share_id'], 'ciphertext' => base64_encode($ct.$tag), 'iv' => base64_encode($iv),
                'salt' => base64_encode($salt), 'has_passphrase' => $withPassphrase ? '1' : '0',
                'burn_hash' => ShareModel::burnHash($burn), 'label' => Fixtures::SHARE_LABEL,
            ]);
        }
        $this->assertCount(2, $shares->listMine($this->alice, $sk));

        // A passphrase change (a full rotation: stale wraps and keys deleted, their pages left in the file), then an
        // unlock with the new passphrase.
        $this->principals()->changePassphrase($this->alice, Fixtures::PASSPHRASE, Fixtures::NEW_PASSPHRASE, $sk, self::IP);
        $sk = $this->unlockAs($this->alice, Fixtures::NEW_PASSPHRASE, 'sid-alice-2');
        $this->generated[] = $sk;
        $this->generated[] = $this->jar->last()['value'];
        // One wrong unlock (M13): the guess is refused and recorded as a failure, and is stored nowhere.
        $wrong = 'VaultWrongGuess-'.bin2hex(random_bytes(8));
        $this->generated[] = $wrong;
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, $wrong, self::IP));
        $this->assertSame(Fixtures::UPDATED_PASSWORD, $s->readField($this->alice, $entry, 'password', $sk));

        // A hardware key: its PRF wrap; registering it rotates nothing (the passphrase wrap stays with one key).
        $this->container['configModel']->save(['application_url' => 'https://kb.example/']);
        $this->container['memoryCache']->flush();
        $hw = new HardwareKeys($this->container, $this->slots(), $this->argon(), $this->clock(), $this->rotation());
        $key = new SoftAuthenticator(-7);
        $c = $hw->challenge($this->alice, 'register');
        $create = $key->create($c, 'https://kb.example', 'kb.example');
        $assert = $key->get($hw->challenge($this->alice, 'ceremony'), 'https://kb.example', 'kb.example', HardwareKeys::prfSaltFor($c));
        $this->generated[] = $assert['prf'];
        $hw->registerKey($this->alice, $sk, ['label' => 'Backup key', 'create' => $create, 'assert' => $assert, 'others' => []], Fixtures::NEW_PASSPHRASE, self::IP);
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE user_id = ? AND method = 'passphrase+prf'", [$this->alice]));
        $sk = (string) $this->session()->secretKey();
        $this->generated[] = $sk;
        // The vault stays unlocked: its session row is in the backup.
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->alice]));

        // The DEKs themselves (M13): an entry's and a group's, opened through Rekeyer::openDek at their current epoch.
        $rekeyer = new Rekeyer($this->container, $this->clock());
        foreach ([['entry', $entry, 'vault_entries'], ['group', $top, 'vault_groups']] as [$type, $id, $table]) {
            $epoch = (int) $this->row('SELECT key_epoch FROM '.$table.' WHERE id = ?', [$id])['key_epoch'];
            $dek = $rekeyer->openDek(new VaultDb($this->container), $type, $id, $epoch, $this->alice, $sk);
            $this->assertSame(32, strlen((string) $dek), "the $type DEK opens");
            $this->generated[] = $dek;
        }
    }

    /** @return array<string,string> what a backup holds, by name */
    private function dump(): array
    {
        $files = fn (): array => array_map(fn (string $p): string => is_file($p) ? (string) file_get_contents($p) : '', [
            'main' => $this->dbPath, 'wal' => $this->dbPath.'-wal', 'shm' => $this->dbPath.'-shm',
        ]);
        $live = $files();
        $dump = ['sqlite main file' => $live['main'], 'sqlite -wal file' => $live['wal'], 'sqlite -shm file' => $live['shm']];
        $logical = '';
        foreach ($this->pdo()->query("SELECT name FROM sqlite_master WHERE type = 'table'")->fetchAll(\PDO::FETCH_COLUMN) as $table) {
            $logical .= "-- $table\n".var_export($this->pdo()->query('SELECT * FROM "'.$table.'"')->fetchAll(\PDO::FETCH_ASSOC), true)."\n";
        }
        $dump['logical dump'] = $logical;
        $this->assertSame(0, (int) $this->pdo()->query('PRAGMA wal_checkpoint(TRUNCATE)')->fetch(\PDO::FETCH_NUM)[0], 'the checkpoint ran');
        $dump['sqlite main file after checkpoint'] = $files()['main'];
        $config = '';
        foreach ([ROOT_DIR.'/config.php', ROOT_DIR.'/config.default.php', ROOT_DIR.'/data/config.php'] as $f) {
            $config .= is_file($f) ? (string) file_get_contents($f) : '';
        }
        $dump['config.php'] = $config;
        $dump['defined constants'] = var_export(get_defined_constants(true)['user'] ?? [], true);
        $dump['environment'] = var_export([getenv(), $_ENV, $_SERVER], true);
        $slots = '';
        foreach (glob(dirname($this->slotDir).'/{,.}*', GLOB_BRACE) ?: [] as $f) {
            $slots .= $f."\n".(is_file($f) ? (string) file_get_contents($f) : '');
        }
        $dump['argon2 slot dir'] = $slots;
        // Kanboard's own logs (debug.log and any other *.log in DATA_DIR) go into backups of the data directory (M13).
        $logs = '';
        foreach (glob(DATA_DIR.'/*.log') ?: [] as $f) {
            $logs .= $f."\n".(string) file_get_contents($f);
        }
        $dump['DATA_DIR logs'] = $logs;
        return $dump;
    }

    // Where $secret shows up in the dump: raw, hex (either case), base64 and base64url at each byte alignment.
    /** @return list<string> */
    private function hits(array $dump, string $secret): array
    {
        $forms = ['raw' => $secret, 'hex' => bin2hex($secret), 'HEX' => strtoupper(bin2hex($secret))];
        for ($shift = 0; $shift < 3; $shift++) {
            $b64 = base64_encode(str_repeat("\0", $shift).$secret);
            $start = [0, 2, 3][$shift];
            $end = intdiv($shift + strlen($secret), 3) * 4;
            $core = substr($b64, $start, $end - $start);
            $forms["base64+$shift"] = $core;
            $forms["base64url+$shift"] = strtr($core, '+/', '-_');
        }
        $hits = [];
        foreach ($dump as $where => $bytes) {
            foreach ($forms as $form => $needle) {
                if (strlen($needle) >= 16 && str_contains($bytes, $needle)) {
                    $hits[] = "$where ($form)";
                }
            }
        }
        return $hits;
    }
}
