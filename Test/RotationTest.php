<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/VaultFixture.php';

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\Bridge;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\GrantModel;
use Kanboard\Plugin\Vault\Model\ObjectStore;
use Kanboard\Plugin\Vault\Model\PrincipalModel;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\UnlockService;
use KanboardTests\units\Base;

// Spec: Key rotation (ceremony, state machine, bridge, crash recovery), with "Adding a recipient" (seal to both
// keys while rotating), the write barrier and "Unlocked sessions" (rotation locks the other sessions).
// Alice rotates. She owns g1 > g2 with six entries and shares g2 with Bob; Bob owns gb with two entries and
// grants gb to Alice. So Alice's sweep covers objects she owns and objects merely shared with her.
class RotationTest extends Base
{
    use VaultFixture;

    private const IP = '203.0.113.9';
    private const NEW_PASS = 'new marble harbor twilight';
    private string $bobPassphrase = 'bob vault passphrase long';
    /** @var list<array{0:string,1:int,2:float}> */
    private array $hookLog = [];
    /** @var (callable(string,int):bool)|null */
    private $crashWhen = null;
    private array $objs = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->loginAs($this->alice);
        $this->principals()->enrolHuman($this->alice, $this->alicePassphrase);
        $this->principals()->enrolHuman($this->bob, $this->bobPassphrase);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    // A fast stand-in for Argon2id (keyed BLAKE2b of the secret by the salt). The KEK derivation, wraps and AD
    // are all real; only the memory-hard step is skipped to keep the suite fast.
    protected function argon(): callable
    {
        return function (string $secret, string $salt, int $ops, int $mem): string {
            $this->argonCalls++;
            if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
                throw new CryptoException('kdf: bad salt length');
            }
            return sodium_crypto_generichash($secret, $salt, 32);
        };
    }

    private function hook(): callable
    {
        return function (string $point, int $k, float $seconds): void {
            $this->hookLog[] = [$point, $k, $seconds];
            if ($this->crashWhen !== null && ($this->crashWhen)($point, $k)) {
                throw new \RuntimeException('injected crash');
            }
        };
    }

    private function rotation(int $batch = 100): RotationService
    {
        return new RotationService($this->container, $this->slots(), $this->argon(), fn () => $this->now, $this->session(), $this->hook(), $batch);
    }

    private function rotatingPrincipals(int $batch = 100): PrincipalModel
    {
        return new PrincipalModel($this->container, $this->slots(), $this->argon(), fn () => $this->now, $this->rotation($batch));
    }

    private function unlockService(): UnlockService
    {
        return new UnlockService($this->container, $this->slots(), $this->argon(), $this->session(), $this->limiter(), fn () => $this->now, $this->rotation());
    }

    private function store(): ObjectStore
    {
        return new ObjectStore($this->container, fn () => $this->now);
    }

    private function grants(): GrantModel
    {
        return new GrantModel($this->container, fn () => $this->now);
    }

    // The principal's sk, opened from its active passphrase wrap at its current key_gen.
    private function skFor(int $userId, string $passphrase): string
    {
        $p = $this->row('SELECT * FROM vault_principals WHERE user_id = ?', [$userId]);
        $w = $this->row("SELECT * FROM vault_wraps WHERE user_id = ? AND method = 'passphrase' AND status = 'active' AND key_gen = ?", [$userId, $p['key_gen']]);
        return Wraps::unwrap($w, $this->kek($passphrase, $w), base64_decode($p['public_key']));
    }

    private function kek(string $passphrase, array $wrap): string
    {
        return Kdf::kek(($this->argon())($passphrase, base64_decode($wrap['kdf_salt']), (int) $wrap['kdf_ops'], (int) $wrap['kdf_mem']), 'passphrase');
    }

    // Does $passphrase open this wrap row at all (whatever public key it holds)?
    private function wrapOpens(array $wrap, string $passphrase): bool
    {
        if ($wrap['kdf_salt'] === null || $wrap['nonce'] === '') {
            return false;
        }
        try {
            $sk = Aead::open(base64_decode($wrap['nonce']), base64_decode($wrap['wrapped_sk']), $this->kek($passphrase, $wrap),
                Encoding::enc('wrap', 1, (int) $wrap['user_id'], (string) $wrap['method'], (string) ($wrap['credential_id'] ?? ''), (int) $wrap['id']));
            return $sk !== '';
        } catch (CryptoException) {
            return false;
        }
    }

    private function pkOf(string $sk): string
    {
        return sodium_crypto_box_publickey_from_secretkey($sk);
    }

    private function keypair(string $sk): string
    {
        return sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, $this->pkOf($sk));
    }

    private function principalRow(int $userId): array
    {
        return $this->row('SELECT * FROM vault_principals WHERE user_id = ?', [$userId]);
    }

    private function populate(): void
    {
        $aliceSk = $this->skFor($this->alice, $this->alicePassphrase);
        $bobSk = $this->skFor($this->bob, $this->bobPassphrase);
        $s = $this->store();
        $g1 = $s->createGroup($this->alice, null, ['name' => 'g1']);
        $g2 = $s->createGroup($this->alice, $g1, ['name' => 'g2']);
        $this->objs = [['group', $g1], ['group', $g2]];
        for ($i = 1; $i <= 6; $i++) {
            $this->objs[] = ['entry', $s->createEntry($this->alice, $i <= 3 ? $g1 : $g2, ['title' => "a$i", 'password' => "pa$i"])];
        }
        $this->grants()->grant($this->alice, 'group', $g2, $this->bob, 'read', null, $aliceSk);
        $gb = $s->createGroup($this->bob, null, ['name' => 'gb']);
        $this->objs[] = ['group', $gb];
        for ($i = 1; $i <= 2; $i++) {
            $this->objs[] = ['entry', $s->createEntry($this->bob, $gb, ['title' => "b$i", 'password' => "pb$i"])];
        }
        $this->grants()->grant($this->bob, 'group', $gb, $this->alice, 'edit', null, $bobSk);
    }

    private function epochs(): array
    {
        $out = [];
        foreach ($this->objs as [$t, $id]) {
            $out["$t:$id"] = (int) $this->row('SELECT key_epoch FROM '.($t === 'entry' ? 'vault_entries' : 'vault_groups').' WHERE id = ?', [$id])['key_epoch'];
        }
        return $out;
    }

    private function read(int $actor, string $type, int $id, string $sk): array
    {
        $s = $this->store();
        return $type === 'entry' ? $s->readEntry($actor, $id, $sk)['payload'] : $s->readGroup($actor, $id, $sk)['payload'];
    }

    private function assertAliceReadsEverything(string $sk): void
    {
        foreach ($this->objs as [$t, $id]) {
            $this->assertNotSame([], $this->read($this->alice, $t, $id, $sk), "alice reads $t $id");
        }
    }

    private function oldGenRows(int $userId, int $gen): int
    {
        return $this->countRows('SELECT COUNT(*) FROM vault_keys WHERE principal_id = ? AND principal_key_gen = ?', [$userId, $gen]);
    }

    private function crashAt(string $point, int $k = 0): void
    {
        $this->crashWhen = static fn (string $p, int $i): bool => $p === $point && $i === $k;
    }

    private function thrown(callable $fn): \Throwable
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            return $e;
        }
        $this->fail('expected an exception');
    }

    // Unlocks in a fresh PHP session with no cookie, then returns the session's sk.
    private function unlockFresh(int $userId, string $passphrase, string $sid): string
    {
        $this->sid = $sid;
        $this->https();
        $this->unlockService()->unlock($userId, $passphrase, self::IP);
        $this->sendCookieBack();
        $sk = $this->session()->secretKey();
        $this->assertNotNull($sk);
        return $sk;
    }

    private function dump(): array
    {
        $out = [];
        foreach (['vault_principals', 'vault_rotations', 'vault_wraps', 'vault_groups', 'vault_entries', 'vault_keys', 'vault_sessions'] as $t) {
            $s = $this->pdo()->query("SELECT * FROM $t");
            $out[$t] = $s->fetchAll(\PDO::FETCH_ASSOC);
        }
        return $out;
    }

    // Spec start: "Delete the old active wraps in the same transaction. From this point the old credentials (for
    // example the old passphrase) open nothing". Before start the old passphrase opens sk1; after start (crash
    // right after it) no wrap row opens with it, and unlock with it fails. Kills: keeping the old wraps, or
    // deleting them in a later phase; resume loading an active (old) wrap instead of the pending one.
    public function testOldPassphraseOpensNothingAfterStart(): void
    {
        $this->populate();
        $sk1 = $this->skFor($this->alice, $this->alicePassphrase);
        $this->assertSame(base64_decode($this->principalRow($this->alice)['public_key']), $this->pkOf($sk1));
        $wraps = $this->pdo()->query('SELECT * FROM vault_wraps WHERE user_id = '.$this->alice)->fetchAll(\PDO::FETCH_ASSOC);
        $this->assertTrue($this->wrapOpens($wraps[0], $this->alicePassphrase), 'control: the old passphrase opens before start');

        $this->crashAt('start');
        $e = $this->thrown(fn () => $this->rotatingPrincipals()->changePassphrase($this->alice, $this->alicePassphrase, self::NEW_PASS, $sk1));
        $this->assertSame('injected crash', $e->getMessage());
        $this->assertSame('rotating', $this->principalRow($this->alice)['state']);
        $this->assertNotNull($this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]));

        $wraps = $this->pdo()->query('SELECT * FROM vault_wraps WHERE user_id = '.$this->alice)->fetchAll(\PDO::FETCH_ASSOC);
        $this->assertNotEmpty($wraps);
        foreach ($wraps as $w) {
            $this->assertFalse($this->wrapOpens($w, $this->alicePassphrase), 'the old passphrase opens wrap '.$w['id']);
            $this->assertSame('pending', $w['status']);
            $this->assertSame(2, (int) $w['key_gen']);
        }
        $this->crashWhen = null;
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, $this->alicePassphrase, self::IP));
        $this->assertNotNull($this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]), 'a failed unlock resumes nothing');
    }

    // Spec crash recovery: "The test deletes the initiating session, then resumes using only the new
    // credentials." Kills: unlock ignoring vault_rotations (it would look for an active gen-1 wrap and fail);
    // resume skipping the sweep or finish; the session after resume holding sk1 instead of sk2.
    public function testResumeWithOnlyNewPassphraseAfterSessionDeleted(): void
    {
        $this->populate();
        $sk1 = $this->unlockFresh($this->alice, $this->alicePassphrase, 'php-session-A');
        $this->crashAt('start');
        $this->thrown(fn () => $this->rotatingPrincipals()->changePassphrase($this->alice, $this->alicePassphrase, self::NEW_PASS, $sk1));
        $this->pdo()->exec('DELETE FROM vault_sessions');
        $this->crashWhen = null;

        $sk = $this->unlockFresh($this->alice, self::NEW_PASS, 'php-session-Z');
        $p = $this->principalRow($this->alice);
        $this->assertSame(2, (int) $p['key_gen']);
        $this->assertSame('active', $p['state']);
        $this->assertSame(base64_decode($p['public_key']), $this->pkOf($sk));
        $this->assertNotSame($this->pkOf($sk1), $this->pkOf($sk));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rotations'));
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE user_id = ? AND (status <> 'active' OR key_gen <> 2)", [$this->alice]));
        $this->assertSame(0, $this->oldGenRows($this->alice, 1));
        $this->assertAliceReadsEverything($sk);
        $bobSk = $this->skFor($this->bob, $this->bobPassphrase);
        // Bob reads g2 and its entries (shared by Alice) and his own gb with its entries.
        foreach ([1, 5, 6, 7, 8, 9, 10] as $i) {
            [$t, $id] = $this->objs[$i];
            $this->assertNotSame([], $this->read($this->bob, $t, $id, $bobSk), "bob still reads $t $id");
        }
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, $this->alicePassphrase, self::IP));
    }

    public static function crashBatches(): array
    {
        return ['after batch 0' => [0], 'after batch 1' => [1], 'after batch 2' => [2], 'after batch 3' => [3]];
    }

    // Spec: "interrupt after each phase and each batch, then resume". With batches of 2 over 11 objects, a crash
    // after batch k leaves 2(k+1) objects re-keyed. Resuming from the new passphrase alone re-keys every other
    // object exactly once. Kills: a batch that isn't its own transaction (a crash would lose or half-apply it);
    // a sweep that re-selects swept objects (double epoch bump); a resume that skips unswept ones.
    /** @dataProvider crashBatches */
    public function testCrashAfterEachSweepBatchThenResume(int $k): void
    {
        $this->populate();
        $before = $this->epochs();
        $this->assertCount(11, $before);
        $sk1 = $this->skFor($this->alice, $this->alicePassphrase);
        $this->crashAt('batch', $k);
        $e = $this->thrown(fn () => $this->rotatingPrincipals(2)->changePassphrase($this->alice, $this->alicePassphrase, self::NEW_PASS, $sk1));
        $this->assertSame('injected crash', $e->getMessage());
        $batches = array_values(array_filter($this->hookLog, static fn (array $h): bool => $h[0] === 'batch'));
        $this->assertSame(range(0, $k), array_column($batches, 1));

        $mid = $this->epochs();
        $bumped = count(array_filter(array_keys($mid), static fn (string $o): bool => $mid[$o] === $before[$o] + 1));
        $this->assertSame(2 * ($k + 1), $bumped, 'each committed batch re-keyed its 2 objects');
        $this->assertSame(11 - 2 * ($k + 1), $this->countRows('SELECT COUNT(*) FROM (SELECT DISTINCT object_type, object_id FROM vault_keys WHERE principal_id = ? AND principal_key_gen = 1)', [$this->alice]));
        $this->assertSame('sweep', $this->row('SELECT phase FROM vault_rotations WHERE user_id = ?', [$this->alice])['phase']);

        $this->pdo()->exec('DELETE FROM vault_sessions');
        $this->crashWhen = null;
        $sk = $this->unlockFresh($this->alice, self::NEW_PASS, 'php-session-R');
        $after = $this->epochs();
        foreach ($before as $o => $epoch) {
            $this->assertSame($epoch + 1, $after[$o], "$o re-keyed exactly once");
        }
        $this->assertSame(0, $this->oldGenRows($this->alice, 1));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rotations'));
        $this->assertAliceReadsEverything($sk);
        $bobSk = $this->skFor($this->bob, $this->bobPassphrase);
        $this->assertSame('b1', $this->read($this->bob, 'entry', $this->objs[9][1], $bobSk)['title']);
        $this->assertSame('a4', $this->read($this->bob, 'entry', $this->objs[5][1], $bobSk)['title']);
    }

    // Spec: "While the state is rotating, new grants seal to both keys", and a grant made mid-rotation ends up
    // sealed only to the new key. Kills: principalKeysForSealing ignoring the rotation (old key only: sk2 can't
    // open it directly, and finish would strand it); a sweep that skips objects granted after start.
    public function testGrantDuringRotationEndsSealedToNewKeyOnly(): void
    {
        $this->populate();
        $bobSk = $this->skFor($this->bob, $this->bobPassphrase);
        $gx = $this->store()->createGroup($this->bob, null, ['name' => 'late']);
        $ex = $this->store()->createEntry($this->bob, $gx, ['title' => 'late entry', 'password' => 'late pw']);
        $sk1 = $this->skFor($this->alice, $this->alicePassphrase);
        $this->crashAt('start');
        $this->thrown(fn () => $this->rotation()->requestManual($this->alice, $sk1, $this->alicePassphrase));
        $this->crashWhen = null;
        $pending = $this->row("SELECT * FROM vault_wraps WHERE user_id = ? AND status = 'pending'", [$this->alice]);
        $rot = $this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]);
        $sk2 = Wraps::unwrap($pending, $this->kek($this->alicePassphrase, $pending), base64_decode($rot['new_pk']));

        $this->grants()->grant($this->bob, 'entry', $ex, $this->alice, 'read', null, $bobSk);
        $rows = $this->pdo()->query("SELECT principal_key_gen, sealed_dek, key_epoch FROM vault_keys WHERE object_type = 'entry' AND object_id = $ex AND principal_id = {$this->alice} ORDER BY principal_key_gen")->fetchAll(\PDO::FETCH_ASSOC);
        $this->assertSame([1, 2], array_map('intval', array_column($rows, 'principal_key_gen')), 'sealed to both keys');
        $this->assertSame(32, strlen(Sealer::openDek(base64_decode($rows[0]['sealed_dek']), $this->keypair($sk1), 'entry', $ex, 1, $this->alice)));
        $this->assertSame(32, strlen(Sealer::openDek(base64_decode($rows[1]['sealed_dek']), $this->keypair($sk2), 'entry', $ex, 1, $this->alice)));
        $this->assertSame('late entry', $this->read($this->alice, 'entry', $ex, $sk2)['title']);

        $keys = $this->rotation()->resume($this->alice, $sk2);
        $this->assertSame($sk1, $keys['sk1']);
        $this->assertSame($sk2, $keys['sk2']);
        $this->rotation()->complete($this->alice, $keys['sk1'], $keys['sk2']);

        $rows = $this->pdo()->query("SELECT principal_key_gen, sealed_dek, key_epoch FROM vault_keys WHERE object_type = 'entry' AND object_id = $ex AND principal_id = {$this->alice}")->fetchAll(\PDO::FETCH_ASSOC);
        $this->assertCount(1, $rows);
        $this->assertSame(2, (int) $rows[0]['principal_key_gen']);
        $this->assertSame(2, (int) $rows[0]['key_epoch'], 're-keyed by the sweep');
        $this->assertSame('late entry', $this->read($this->alice, 'entry', $ex, $sk2)['title']);
        $this->assertSame('late entry', $this->read($this->bob, 'entry', $ex, $bobSk)['title']);
        $this->assertVaultError('not_found', fn () => $this->read($this->alice, 'entry', $ex, $sk1));
    }

    // Spec finish: "Require that no key row for the principal is at the old generation. If any is, go back to
    // sweep." Kills: a finish without that check (it would flip the wraps and drop the bridge, stranding the
    // old-generation rows that only sk1 opens).
    public function testFinishRefusesWhileOldGenRowsRemain(): void
    {
        $this->populate();
        $sk1 = $this->skFor($this->alice, $this->alicePassphrase);
        $this->crashAt('start');
        $this->thrown(fn () => $this->rotation()->requestManual($this->alice, $sk1, $this->alicePassphrase));
        $this->crashWhen = null;
        $pending = $this->row("SELECT * FROM vault_wraps WHERE user_id = ? AND status = 'pending'", [$this->alice]);
        $rot = $this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]);
        $sk2 = Wraps::unwrap($pending, $this->kek($this->alicePassphrase, $pending), base64_decode($rot['new_pk']));

        $assertUnfinished = function (): void {
            $this->assertNotNull($this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]));
            $this->assertSame(1, (int) $this->principalRow($this->alice)['key_gen']);
            $this->assertSame('rotating', $this->principalRow($this->alice)['state']);
            $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE user_id = ? AND status = 'active'", [$this->alice]));
        };
        $this->assertVaultError('rotation_incomplete', fn () => $this->rotation()->finish($this->alice));
        $assertUnfinished();

        $left = $this->rotation()->sweep($this->alice, $sk1, $sk2, 2, 1);
        $this->assertSame(9, $left);
        $this->assertVaultError('rotation_incomplete', fn () => $this->rotation()->finish($this->alice));
        $assertUnfinished();
        $this->assertSame('sweep', $this->row('SELECT phase FROM vault_rotations WHERE user_id = ?', [$this->alice])['phase']);

        $this->assertSame(0, $this->rotation()->sweep($this->alice, $sk1, $sk2));
        $this->assertSame('finish', $this->row('SELECT phase FROM vault_rotations WHERE user_id = ?', [$this->alice])['phase']);
        $this->rotation()->finish($this->alice);
        $this->assertSame(2, (int) $this->principalRow($this->alice)['key_gen']);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rotations'));
        $this->assertSame(1, $this->countRows("SELECT COUNT(*) FROM vault_wraps WHERE user_id = ? AND status = 'active' AND key_gen = 2", [$this->alice]));
        $this->assertAliceReadsEverything($sk2);
    }

    // Spec: "pre-rotation credentials can't decrypt any post-rotation backup". The attacker holds the old
    // passphrase and a pre-rotation dump, so sk1 and every DEK Alice could open then. Against the full
    // post-rotation dump: no wrap opens with the old passphrase, no key row opens with sk1, and no old DEK opens
    // any entry or group ciphertext under any epoch. Kills: re-sealing (not re-keying) objects shared with Alice
    // or owned by her; keeping the old wraps; leaving the bridge; sealing new DEKs to the old key.
    public function testPreRotationCredsCannotDecryptPostRotationDump(): void
    {
        $this->populate();
        $pre = $this->dump();
        $oldWrap = array_values(array_filter($pre['vault_wraps'], fn (array $w): bool => (int) $w['user_id'] === $this->alice))[0];
        $sk1 = Wraps::unwrap($oldWrap, $this->kek($this->alicePassphrase, $oldWrap), base64_decode($this->principalRow($this->alice)['public_key']));
        $deks = [];
        foreach ($pre['vault_keys'] as $k) {
            if ((int) $k['principal_id'] === $this->alice) {
                $deks[$k['object_type'].':'.$k['object_id']] = Sealer::openDek(base64_decode($k['sealed_dek']), $this->keypair($sk1), $k['object_type'], (int) $k['object_id'], (int) $k['key_epoch'], $this->alice);
            }
        }
        $this->assertCount(11, $deks, 'control: the pre-rotation dump opens all 11 objects');

        $this->rotatingPrincipals()->changePassphrase($this->alice, $this->alicePassphrase, self::NEW_PASS, $sk1);
        $post = $this->dump();

        $this->assertSame([], $post['vault_rotations'], 'the bridge is gone');
        foreach ($post['vault_wraps'] as $w) {
            $this->assertFalse($this->wrapOpens($w, $this->alicePassphrase), 'old passphrase opens wrap '.$w['id']);
        }
        foreach ($post['vault_keys'] as $k) {
            try {
                Sealer::openDek(base64_decode($k['sealed_dek']), $this->keypair($sk1), $k['object_type'], (int) $k['object_id'], (int) $k['key_epoch'], (int) $k['principal_id']);
                $this->fail('sk1 opens a post-rotation key row');
            } catch (CryptoException) {
            }
        }
        $opened = 0;
        foreach (['entry' => $post['vault_entries'], 'group' => $post['vault_groups']] as $type => $rows) {
            foreach ($rows as $r) {
                foreach ($deks as $dek) {
                    for ($epoch = 1; $epoch <= (int) $r['key_epoch']; $epoch++) {
                        try {
                            Aead::open(base64_decode($r['nonce']), base64_decode($r['ciphertext']), $dek, ObjectStore::ad($type, (int) $r['id'], (int) $r['owner_id'], $epoch));
                            $opened++;
                        } catch (CryptoException) {
                        }
                    }
                }
            }
        }
        $this->assertSame(0, $opened, 'an old DEK decrypts a post-rotation ciphertext');
        $this->assertCount(11, array_merge($post['vault_entries'], $post['vault_groups']), 'every object was checked');
    }

    // Spec start: "Lock all of the principal's other vault sessions" and "Add enc_sk_next (sk2 under the same
    // session_key) to the current session row"; finish moves enc_sk_next into enc_sk. Kills: leaving other
    // sessions alive (they hold sk1); locking Bob's sessions; the initiating session losing sk2.
    public function testOtherSessionsLockedAtStart(): void
    {
        $this->populate();
        $this->unlockFresh($this->alice, $this->alicePassphrase, 'php-session-B');
        $this->loginAs($this->bob);
        $this->unlockFresh($this->bob, $this->bobPassphrase, 'php-session-Bob');
        $this->loginAs($this->alice);
        $sk1 = $this->unlockFresh($this->alice, $this->alicePassphrase, 'php-session-A');
        $cookieA = $this->container['request']->getCookie($this->session()->cookieName());
        $this->assertSame(3, $this->countRows('SELECT COUNT(*) FROM vault_sessions'));

        $this->crashAt('start');
        $this->thrown(fn () => $this->rotation()->requestManual($this->alice, $sk1, $this->alicePassphrase));
        $this->crashWhen = null;
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->alice]), 'only the initiating session is left');
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_sessions WHERE user_id = ?', [$this->bob]), "bob's session is untouched");
        $a = $this->row('SELECT * FROM vault_sessions WHERE user_id = ?', [$this->alice]);
        $this->assertSame(bin2hex(sodium_crypto_generichash('php-session-A', '', 32)), $a['sid_hash']);
        $this->assertNotNull($a['enc_sk_next']);

        $this->sid = 'php-session-A';
        $this->https([$this->session()->cookieName() => $cookieA]);
        $sk2 = $this->session()->secretKey();
        $rot = $this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]);
        $this->assertSame(base64_decode($rot['new_pk']), $this->pkOf($sk2), 'the initiating session works with sk2');
        $this->assertAliceReadsEverything($sk2);

        $keys = $this->rotation()->resume($this->alice, $sk2);
        $this->rotation()->complete($this->alice, $keys['sk1'], $keys['sk2']);
        $a = $this->row('SELECT * FROM vault_sessions WHERE user_id = ?', [$this->alice]);
        $this->assertNull($a['enc_sk_next']);
        $this->assertSame($sk2, $this->session()->secretKey());
        $this->assertSame(base64_decode($this->principalRow($this->alice)['public_key']), $this->pkOf($sk2));
    }

    // Spec: "the write barrier applies to every object still holding an old-generation row for the principal".
    // An edit by Bob mid-rotation to an object Alice still holds at gen 1 first re-keys it (Alice gets the new
    // key only), so the new payload is never under a DEK sk1 can reach. Kills: beforeWrite without the rotation
    // check; a barrier re-key that seals to both keys.
    public function testWriteBarrierRekeysOldGenerationObjectsBeforeAnEdit(): void
    {
        $this->populate();
        $bobSk = $this->skFor($this->bob, $this->bobPassphrase);
        $eb1 = $this->objs[9][1];
        $sk1 = $this->skFor($this->alice, $this->alicePassphrase);
        $oldDek = Sealer::openDek(base64_decode($this->row("SELECT sealed_dek FROM vault_keys WHERE object_type = 'entry' AND object_id = ? AND principal_id = ?", [$eb1, $this->alice])['sealed_dek']), $this->keypair($sk1), 'entry', $eb1, 1, $this->alice);
        $this->crashAt('start');
        $this->thrown(fn () => $this->rotation()->requestManual($this->alice, $sk1, $this->alicePassphrase));
        $this->crashWhen = null;

        $this->store()->updateEntry($this->bob, $eb1, 1, ['title' => 'b1 edited', 'password' => 'new secret'], $bobSk);
        $r = $this->row('SELECT * FROM vault_entries WHERE id = ?', [$eb1]);
        $this->assertSame(2, (int) $r['key_epoch'], 're-keyed before the edit');
        $this->assertSame([2], array_map('intval', array_column($this->pdo()->query("SELECT principal_key_gen FROM vault_keys WHERE object_type = 'entry' AND object_id = $eb1 AND principal_id = {$this->alice}")->fetchAll(\PDO::FETCH_ASSOC), 'principal_key_gen')));
        $this->expectException(CryptoException::class);
        Aead::open(base64_decode($r['nonce']), base64_decode($r['ciphertext']), $oldDek, ObjectStore::ad('entry', $eb1, $this->bob, 2));
    }

    // The ceremony checks the factor it is about to wrap sk2 under: Rotate my keys with a mistyped passphrase
    // would otherwise lock the user out for good. Kills: requestManual without the current-passphrase check.
    public function testRotateMyKeysRefusesAWrongPassphrase(): void
    {
        $sk1 = $this->skFor($this->alice, $this->alicePassphrase);
        $this->assertVaultError('unlock_failed', fn () => $this->rotation()->requestManual($this->alice, $sk1, 'not the right passphrase'));
        $this->assertVaultError('unlock_failed', fn () => $this->rotatingPrincipals()->changePassphrase($this->alice, 'not the right passphrase', self::NEW_PASS, $sk1));
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_rotations'));
        $this->assertSame('active', $this->principalRow($this->alice)['state']);
        $this->assertSame($sk1, $this->skFor($this->alice, $this->alicePassphrase));
        $this->assertVaultError('passphrase_weak', fn () => $this->rotatingPrincipals()->changePassphrase($this->alice, $this->alicePassphrase, 'short', $sk1));
    }

    // resume checks both keys against old_pk and new_pk before using either. Kills: trusting the bridge
    // plaintext without the old_pk check; accepting an sk2 that isn't the rotation's new key.
    public function testResumeChecksBothPublicKeys(): void
    {
        $sk1 = $this->skFor($this->alice, $this->alicePassphrase);
        $this->crashAt('start');
        $this->thrown(fn () => $this->rotation()->requestManual($this->alice, $sk1, $this->alicePassphrase));
        $this->crashWhen = null;
        $rot = $this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]);
        $pending = $this->row("SELECT * FROM vault_wraps WHERE user_id = ? AND status = 'pending'", [$this->alice]);
        $sk2 = Wraps::unwrap($pending, $this->kek($this->alicePassphrase, $pending), base64_decode($rot['new_pk']));
        $this->assertSame($sk1, $this->rotation()->resume($this->alice, $sk2)['sk1']);

        $this->assertVaultError('not_found', fn () => $this->rotation()->resume($this->alice, $sk1));
        $this->assertVaultError('not_found', fn () => $this->rotation()->resume($this->alice, sodium_crypto_box_secretkey(sodium_crypto_box_keypair())));
        // A bridge that holds some other key (correctly sealed under sk2) fails the old_pk check.
        $other = sodium_crypto_box_secretkey(sodium_crypto_box_keypair());
        $this->assertSame('bridge: key does not match its public key', $this->thrown(fn () => Bridge::seal($other, $sk2, $this->alice, base64_decode($rot['old_pk']), base64_decode($rot['new_pk'])))->getMessage());
        $box = Aead::seal($other, sodium_crypto_generichash(Encoding::enc('bridge'), $sk2, 32), Encoding::enc('bridge', $this->alice, base64_decode($rot['old_pk']), base64_decode($rot['new_pk'])));
        $this->pdo()->prepare('UPDATE vault_rotations SET bridge_nonce = ?, bridge = ? WHERE user_id = ?')
            ->execute([base64_encode($box['nonce']), base64_encode($box['ct']), $this->alice]);
        $this->assertVaultError('not_found', fn () => $this->rotation()->resume($this->alice, $sk2));
    }

    // R12: every sk, KEK, factor list and passphrase parameter of the rotation code is #[\SensitiveParameter],
    // so no secret reaches a logged stack trace. Kills: dropping the attribute from any of them.
    public function testSecretParametersAreSensitive(): void
    {
        $classes = [RotationService::class, Bridge::class, \Kanboard\Plugin\Vault\Model\VaultSession::class, PrincipalModel::class, \Kanboard\Plugin\Vault\Model\Rekeyer::class];
        $checked = 0;
        foreach ($classes as $class) {
            foreach ((new \ReflectionClass($class))->getMethods() as $m) {
                if ($m->getDeclaringClass()->getName() !== $class) {
                    continue;
                }
                foreach ($m->getParameters() as $p) {
                    if (preg_match('/(^sk\d?$|Sk\d?$|^dek$|Dek$|^keypair$|^kek$|Factors$|Passphrase$|^passphrase$|^sessionKey$)/', $p->getName())) {
                        $checked++;
                        $this->assertCount(1, $p->getAttributes(\SensitiveParameter::class), "$class::{$m->getName()} \${$p->getName()}");
                    }
                }
            }
        }
        $this->assertGreaterThan(20, $checked);
    }

    // 10k entries, batches of 100: every batch transaction stays under 2 s on SQLite.
    /** @group slow */
    public function testRotation10kEntriesBatchesUnder2s(): void
    {
        $sk1 = $this->skFor($this->alice, $this->alicePassphrase);
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'bulk']);
        $pk = $this->pkOf($sk1);
        $pdo = $this->pdo();
        $pdo->exec('BEGIN');
        $ins = $pdo->prepare('INSERT INTO vault_entries (group_id, owner_id, created_by, version, key_epoch, nonce, ciphertext, crypto_v, created_at, updated_at) VALUES (?, ?, ?, 1, 1, ?, ?, 1, ?, ?)');
        $upd = $pdo->prepare('UPDATE vault_entries SET nonce = ?, ciphertext = ? WHERE id = ?');
        $key = $pdo->prepare("INSERT INTO vault_keys (object_type, object_id, principal_id, principal_key_gen, key_epoch, sealed_dek) VALUES ('entry', ?, ?, 1, 1, ?)");
        for ($i = 0; $i < 10000; $i++) {
            $ins->execute([$g, $this->alice, $this->alice, '', '', $this->now, $this->now]);
            $id = (int) $pdo->lastInsertId();
            $dek = random_bytes(32);
            $box = Aead::seal('{"title":"bulk '.$i.'","username":"","password":"x","url":"","notes":"","tags":[],"expires_at":null,"otp":"","fields":[]}', $dek, ObjectStore::ad('entry', $id, $this->alice, 1));
            $upd->execute([base64_encode($box['nonce']), base64_encode($box['ct']), $id]);
            $key->execute([$id, $this->alice, base64_encode(Sealer::sealDek($dek, 'entry', $id, 1, $this->alice, $pk))]);
        }
        $pdo->exec('COMMIT');

        $this->rotation(100)->requestManual($this->alice, $sk1, $this->alicePassphrase);
        $batches = array_values(array_filter($this->hookLog, static fn (array $h): bool => $h[0] === 'batch'));
        $this->assertCount(101, $batches);
        foreach ($batches as [, $k, $seconds]) {
            $this->assertLessThan(2.0, $seconds, "batch $k took {$seconds}s");
        }
        $this->assertSame(0, $this->oldGenRows($this->alice, 1));
        $this->assertSame(2, (int) $this->principalRow($this->alice)['key_gen']);
    }
}
