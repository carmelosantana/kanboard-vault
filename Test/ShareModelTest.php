<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';
require_once __DIR__.'/Support/ShareSpyNotifier.php';

use Kanboard\Plugin\Vault\Model\Purger;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\Model\RateLimitAudit;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\ShareModel;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec: One-time shares (reservations, the burn capability, the atomic one-time reveal, expiry, revoke, the list of
// links), Throttling (share reveal: per client IP, 20 per 10 min and 200 per day), Audit (share actions, share_hash)
// and Data model (vault_shares holds no link to an entry). The browser's side (T18) is played by hand: random bytes
// stand in for the AES-GCM ciphertext, and the burn capability b is 16 random bytes in lowercase hex.
class ShareModelTest extends Base
{
    use ServiceFixture;

    private VaultShareSpyNotifier $notifier;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->notifier = new VaultShareSpyNotifier($this->container);
        $this->container['vaultNotifier'] = fn () => $this->notifier;
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function shares(): ShareModel
    {
        return new ShareModel($this->container, $this->clock());
    }

    private function sidHash(string $sid = 'php-session-A'): string
    {
        return bin2hex(sodium_crypto_generichash($sid, '', 32));
    }

    private static function burn(): string
    {
        return bin2hex(random_bytes(16));
    }

    private function body(string $shareId, string $burn, array $over = []): array
    {
        return $over + [
            'share_id' => $shareId,
            'ciphertext' => base64_encode(random_bytes(48)),
            'iv' => base64_encode(random_bytes(ShareModel::IV_BYTES)),
            'salt' => '',
            'has_passphrase' => '0',
            'burn_hash' => ShareModel::burnHash($burn),
            'label' => 'for the client',
        ];
    }

    /** @return array{0:string,1:string,2:int} [share_id, burn, expires_at] */
    private function share(string $expiry = '1d', array $over = [], ?int $creator = null): array
    {
        $creator ??= $this->alice;
        $burn = self::burn();
        $r = $this->shares()->reserve($creator, $this->sidHash(), $expiry);
        $this->shares()->finalize($creator, $this->sidHash(), $this->body($r['share_id'], $burn, $over));
        return [$r['share_id'], $burn, $r['expires_at']];
    }

    private function shareCount(): int
    {
        return $this->countRows('SELECT COUNT(*) FROM vault_shares');
    }

    // Spec: "Knowing only the id, for example from an access log, can't burn the link." The id with no b, an empty b,
    // the id itself as b and another link's b all leave the row in place and audit nothing; the real b then reveals.
    // Kills: the burn_hash comparison dropped, or the row deleted before the comparison.
    public function testIdAloneCannotBurn(): void
    {
        [$id, $burn] = $this->share();
        [, $otherBurn] = $this->share();
        foreach (['' => 'no b', $id => 'the id as b', $otherBurn => "another link's b", strtoupper($burn) => 'b in another case'] as $b => $what) {
            $this->assertNull($this->shares()->reveal($id, (string) $b, self::IP), $what);
        }
        $this->assertSame(2, $this->shareCount(), 'nothing burned');
        $this->assertSame([], $this->auditRows('share_reveal'));
        $this->assertNotNull($this->shares()->reveal($id, $burn, self::IP), 'the link still works with its b');
    }

    // Spec: "A wrong b, an expired row and a missing row all return the same generic 'not available'." Every failure is
    // exactly null (no false, no exception, no partial array): an unknown id, a malformed id or b, a wrong b, an
    // expired row, a revoked link and an already burned one. A wrong b changes nothing. Kills: any branch returning
    // something other than null, or throwing (a distinguishable answer), and a wrong b deleting the row.
    public function testWrongBurnSameGenericNull(): void
    {
        [$id, $burn] = $this->share();
        [$expiredId, $expiredBurn] = $this->share('1h');
        [$revokedId, $revokedBurn] = $this->share();
        [$burnedId, $burnedBurn] = $this->share();
        $this->shares()->revoke($this->alice, ShareModel::idHash($revokedId));
        $this->assertNotNull($this->shares()->reveal($burnedId, $burnedBurn, self::IP));
        $cases = [
            'unknown id' => [bin2hex(random_bytes(16)), $burn],
            'wrong b' => [$id, self::burn()],
            'malformed id' => [$id.'00', $burn],
            'malformed b' => [$id, substr($burn, 1)],
            'non-hex b' => [$id, str_repeat('z', 32)],
            'revoked' => [$revokedId, $revokedBurn],
            'already burned' => [$burnedId, $burnedBurn],
        ];
        foreach ($cases as $what => [$i, $b]) {
            $this->assertNull($this->shares()->reveal($i, $b, self::IP), $what);
        }
        $this->now += 3600;
        $this->assertNull($this->shares()->reveal($expiredId, $expiredBurn, self::IP), 'expired');
        $this->assertSame(2, $this->shareCount(), 'only the revoked and the burned link are gone');
        $this->assertCount(1, $this->auditRows('share_reveal'), 'only the one real reveal is audited');
        $this->assertNotNull($this->shares()->reveal($id, $burn, self::IP), 'a wrong b left the link intact');
    }

    // Spec: expiry 1 h, 1 d or 7 d. At expires_at the link is gone (a reveal one second earlier works); the row is left
    // to the purge, which removes it and audits share_expire for the creator. Kills: the expiry check dropped or made
    // inclusive of expires_at (> instead of >=), and the purge not removing shares the model wrote.
    public function testExpiredNull(): void
    {
        [$late, $lateBurn, $at] = $this->share('1h');
        [$early, $earlyBurn] = $this->share('1h');
        $this->assertSame($this->now + 3600, $at);
        $this->now = $at - 1;
        $this->assertNotNull($this->shares()->reveal($early, $earlyBurn, self::IP), 'one second before expiry');
        $this->now = $at;
        $this->assertNull($this->shares()->reveal($late, $lateBurn, self::IP), 'at expires_at');
        $this->assertSame(1, $this->shareCount(), 'an expired reveal leaves the row to the purge');
        (new Purger($this->container))->run($this->now, true);
        $this->assertSame(0, $this->shareCount(), 'purged');
        $rows = $this->auditRows('share_expire');
        $this->assertSame([[(string) $this->alice, ShareModel::idHash($late)]], array_map(static fn ($r) => [(string) $r['target_user_id'], $r['share_hash']], $rows));
    }

    // Spec: "The sender can revoke an unviewed link at any time." Only the creator can: Bob gets not_found and the link
    // still works until Alice revokes it. A revoked link reveals nothing; revoking it again, or revoking a link that was
    // viewed, is not_found. share_revoke is audited with the id hash only. Kills: the creator check dropped (Bob
    // revokes), the delete missing, a revoke of nothing succeeding, the audit row missing.
    public function testRevokeBeforeView(): void
    {
        [$id, $burn] = $this->share();
        [$viewed, $viewedBurn] = $this->share();
        $hash = ShareModel::idHash($id);
        $this->assertVaultError('not_found', fn () => $this->shares()->revoke($this->bob, $hash));
        $this->assertSame(2, $this->shareCount(), "Bob can't revoke Alice's link");
        $this->shares()->revoke($this->alice, $hash);
        $this->assertNull($this->shares()->reveal($id, $burn, self::IP), 'revoked before view');
        $this->assertVaultError('not_found', fn () => $this->shares()->revoke($this->alice, $hash));
        $this->assertNotNull($this->shares()->reveal($viewed, $viewedBurn, self::IP));
        $this->assertVaultError('not_found', fn () => $this->shares()->revoke($this->alice, ShareModel::idHash($viewed)));
        $this->assertVaultError('not_found', fn () => $this->shares()->revoke($this->alice, $id), 'a raw id is not an id hash');
        $rows = $this->auditRows('share_revoke');
        $this->assertCount(1, $rows);
        $this->assertSame([(string) $this->alice, $hash], [(string) $rows[0]['actor_user_id'], $rows[0]['share_hash']]);
    }

    // Spec: "A reservation is bound to the creator and their session, lasts 10 minutes, and can be finalised once."
    // The server returns a 128-bit share_id and an expires_at that both go into the AD, so the share keeps exactly the
    // reserved expiry. Only hashes of the id are stored. The expiry is 1h, 1d or 7d, at most the admin's maximum.
    // Kills: the creator or session binding dropped, the TTL check dropped or inclusive, a second finalize accepted,
    // the share's expiry taken from anything but the reservation, the raw id stored, the admin maximum ignored.
    public function testReservationSingleUseAndBound(): void
    {
        $r = $this->shares()->reserve($this->alice, $this->sidHash(), '1h');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/D', $r['share_id']);
        $this->assertSame($this->now + 3600, $r['expires_at']);
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_share_reservations WHERE id_hash = ? OR sid_hash = ?', [$r['share_id'], $r['share_id']]), 'the raw id is never stored');
        $this->assertSame(1, $this->countRows('SELECT COUNT(*) FROM vault_share_reservations WHERE id_hash = ?', [ShareModel::idHash($r['share_id'])]));

        $burn = self::burn();
        $body = $this->body($r['share_id'], $burn, ['expires_at' => (string) ($this->now + 604800)]);
        $this->assertVaultError('not_found', fn () => $this->shares()->finalize($this->bob, $this->sidHash(), $body));
        $this->assertVaultError('not_found', fn () => $this->shares()->finalize($this->alice, $this->sidHash('php-session-B'), $body));
        $this->now += 599;
        $this->shares()->finalize($this->alice, $this->sidHash(), $body);
        $this->assertSame([$r['expires_at']], array_map('intval', $this->pdo()->query('SELECT expires_at FROM vault_shares')->fetchAll(\PDO::FETCH_COLUMN)), 'the reserved expiry, not the body\'s');
        $this->assertVaultError('not_found', fn () => $this->shares()->finalize($this->alice, $this->sidHash(), $this->body($r['share_id'], self::burn())));
        $this->assertSame(1, $this->shareCount(), 'finalised once');
        $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM vault_share_reservations'), 'consumed');

        $late = $this->shares()->reserve($this->alice, $this->sidHash(), '1d');
        $this->now += ShareModel::RESERVATION_TTL;
        $this->assertVaultError('not_found', fn () => $this->shares()->finalize($this->alice, $this->sidHash(), $this->body($late['share_id'], self::burn())));

        foreach (['2d', '', '3600', '1H'] as $bad) {
            $this->assertVaultError('payload_invalid', fn () => $this->shares()->reserve($this->alice, $this->sidHash(), $bad));
        }
        $this->assertVaultError('payload_invalid', fn () => $this->shares()->reserve($this->alice, 'not a sid hash', '1d'));
        $this->settings()->set('vault_share_max_expiry', 86400, self::ADMIN);
        $this->assertVaultError('payload_invalid', fn () => $this->shares()->reserve($this->alice, $this->sidHash(), '7d'));
        $this->assertSame($this->now + 86400, $this->shares()->reserve($this->alice, $this->sidHash(), '1d')['expires_at']);
        $this->assertCount(1, $this->auditRows('share_create'));
    }

    // Spec: share reveal is throttled per client IP, 20 per 10 min and 200 per day. Every attempt counts, a bad one
    // too. Another IP has its own buckets. A refusal throws rate_limited (a 429, not the not-available answer), and the
    // refusals are audited once per window (R39), with a count. Kills: no throttle, a shared bucket across IPs, the
    // daily bucket missing, the refusal not audited or audited per request.
    public function testRateLimit(): void
    {
        [$id, $burn] = $this->share();
        $ip = '198.51.100.9';
        for ($i = 0; $i < 20; $i++) {
            $this->assertNull($this->shares()->reveal($id, self::burn(), $ip));
        }
        $this->assertVaultError('rate_limited', fn () => $this->shares()->reveal($id, $burn, $ip));
        $this->assertVaultError('rate_limited', fn () => $this->shares()->reveal($id, $burn, $ip));
        $this->assertSame(1, $this->shareCount(), 'a refused reveal never reaches the share');
        $this->assertNull($this->shares()->reveal(bin2hex(random_bytes(16)), $burn, '198.51.100.10'), 'another IP has its own bucket');

        // The daily bucket: a token bucket of 200 that refills at 200 a day (RateLimiter). Twenty attempts every
        // 10 minutes for 5 hours would be 600 through the 10-minute bucket alone; the daily one holds them to the 200
        // burst plus what refilled meanwhile.
        $day = '192.0.2.44';
        $windows = 30;
        $allowed = 0;
        for ($window = 0; $window < $windows; $window++) {
            for ($i = 0; $i < 20; $i++) {
                try {
                    $this->shares()->reveal(bin2hex(random_bytes(16)), self::burn(), $day);
                    $allowed++;
                } catch (VaultException $e) {
                    $this->assertSame('rate_limited', $e->getMessage());
                }
            }
            $this->now += 600;
        }
        $this->assertGreaterThanOrEqual(200, $allowed, 'the first 200 pass');
        $this->assertLessThanOrEqual(200 + (int) ceil($windows * 600 * 200 / 86400), $allowed, 'held to 200 a day');
        $this->now += 86400;
        $this->assertNull($this->shares()->reveal(bin2hex(random_bytes(16)), self::burn(), $day), 'the next day');

        (new RateLimitAudit($this->container, $this->clock()))->flush();
        $rows = array_values(array_filter($this->auditRows('rate_limited'), static fn ($r) => $r['ip_trunc'] === '198.51.100.0/24'));
        $this->assertSame([[null, '2']], array_map(static fn ($r) => [$r['target_user_id'], (string) $r['count']], $rows), 'one row for the window, counting both refusals');
    }

    // Spec, Data model: vault_shares is id_hash, burn_hash, creator_id, ciphertext, iv, salt, has_passphrase,
    // sealed_label, created_at, expires_at (plus crypto_v), and "It never stores which entry a share came from".
    // Nothing a client sends besides the listed fields is kept: an entry_id in the body goes nowhere, and neither the
    // raw id, b nor the label's plaintext appears in the row. Kills: a column that links a share to an entry or group,
    // the label stored in plaintext, the raw id or b stored.
    public function testNoEntryLinkStored(): void
    {
        $cols = array_column($this->pdo()->query('PRAGMA table_info(vault_shares)')->fetchAll(\PDO::FETCH_ASSOC), 'name');
        sort($cols);
        $this->assertSame(['burn_hash', 'ciphertext', 'created_at', 'creator_id', 'crypto_v', 'expires_at', 'has_passphrase', 'id_hash', 'iv', 'salt', 'sealed_label'], $cols);
        $entry = $this->store()->createEntry($this->alice, $this->store()->createGroup($this->alice, null, ['name' => 'g']), Fixtures::entry('linked'));
        [$id, $burn] = $this->share('1d', ['entry_id' => (string) $entry, 'group_id' => '1', 'label' => 'label-plaintext-Ux7']);
        $row = $this->row('SELECT * FROM vault_shares');
        $flat = implode('|', array_map('strval', $row));
        foreach ([$id, $burn, 'label-plaintext-Ux7', base64_encode('label-plaintext-Ux7')] as $secret) {
            $this->assertStringNotContainsString($secret, $flat);
        }
        $this->assertSame(1, (int) $row['crypto_v']);
        $this->assertSame([ShareModel::idHash($id), ShareModel::burnHash($burn)], [$row['id_hash'], $row['burn_hash']]);
    }

    // The reveal returns what the browser needs to decrypt (ciphertext, iv, salt, has_passphrase and expires_at, which
    // is in the AD) and deletes the row. It audits share_reveal for the creator (share_hash, truncated IP, UA family,
    // actor public), then sends the creator the notice (R19), which carries no secret. Kills: a missing field, the row
    // kept after a reveal, the audit row or the notice missing, a raw id or b in the audit.
    public function testRevealReturnsWhatTheBrowserNeedsAndAudits(): void
    {
        $salt = random_bytes(ShareModel::SALT_BYTES);
        $iv = random_bytes(ShareModel::IV_BYTES);
        $ct = random_bytes(100);
        [$id, $burn, $at] = $this->share('7d', ['ciphertext' => base64_encode($ct), 'iv' => base64_encode($iv), 'salt' => base64_encode($salt), 'has_passphrase' => '1']);
        $this->assertSame([], $this->notifier->revealed);
        $data = $this->shares()->reveal($id, $burn, '203.0.113.7', 'Firefox 140 / Linux');
        $this->assertSame(['ciphertext' => base64_encode($ct), 'iv' => base64_encode($iv), 'salt' => base64_encode($salt), 'has_passphrase' => true, 'expires_at' => $at], $data);
        $this->assertSame(0, $this->shareCount());
        $this->assertSame([$this->alice], $this->notifier->revealed);
        $rows = $this->auditRows('share_reveal');
        $this->assertCount(1, $rows);
        $this->assertSame(
            ['public', null, (string) $this->alice, ShareModel::idHash($id), '203.0.113.0/24', 'Firefox 140 / Linux'],
            [$rows[0]['actor_kind'], $rows[0]['actor_user_id'], (string) $rows[0]['target_user_id'], $rows[0]['share_hash'], $rows[0]['ip_trunc'], $rows[0]['ua_family']]
        );
        $flat = implode('|', array_map('strval', array_merge(...array_map('array_values', $this->auditRows()))));
        $this->assertStringNotContainsString($id, $flat);
        $this->assertStringNotContainsString($burn, $flat);
    }

    // Spec: the payload is at most 64 KB (here: a 64 KiB plaintext plus the 16-byte GCM tag), and every field has the
    // shape the browser produces: base64 ciphertext and a 12-byte IV, a 16-byte salt exactly when there is a
    // passphrase, a 64-hex burn hash and a short label. A refused body leaves the reservation usable. Kills: no size
    // limit or an off-by-one, any shape check dropped, a refused body consuming the reservation.
    public function testPayloadShape(): void
    {
        $r = $this->shares()->reserve($this->alice, $this->sidHash(), '1d');
        $burn = self::burn();
        $bad = [
            'payload_too_large' => [['ciphertext' => base64_encode(random_bytes(ShareModel::MAX_CIPHERTEXT + 1))]],
            'payload_invalid' => [
                ['ciphertext' => ''],
                ['ciphertext' => 'not base64!'],
                ['iv' => base64_encode(random_bytes(11))],
                ['salt' => base64_encode(random_bytes(16))],
                ['has_passphrase' => '1'],
                ['has_passphrase' => '1', 'salt' => base64_encode(random_bytes(15))],
                ['has_passphrase' => 'yes'],
                ['burn_hash' => strtoupper(ShareModel::burnHash($burn))],
                ['burn_hash' => substr(ShareModel::burnHash($burn), 2)],
                ['label' => str_repeat('x', ShareModel::LABEL_MAX + 1)],
                ['label' => "\xff\xfe"],
                ['share_id' => strtoupper($r['share_id'])],
            ],
        ];
        foreach ($bad as $code => $cases) {
            foreach ($cases as $over) {
                $this->assertVaultError($code, fn () => $this->shares()->finalize($this->alice, $this->sidHash(), $this->body($r['share_id'], $burn, $over)));
            }
        }
        $this->assertSame(0, $this->shareCount());
        $this->shares()->finalize($this->alice, $this->sidHash(), $this->body($r['share_id'], $burn, [
            'ciphertext' => base64_encode(random_bytes(ShareModel::MAX_CIPHERTEXT)),
            'label' => str_repeat('é', ShareModel::LABEL_MAX),
            'has_passphrase' => '1',
            'salt' => base64_encode(random_bytes(ShareModel::SALT_BYTES)),
        ]));
        $this->assertSame(1, $this->shareCount(), 'the largest payload and label fit');
    }

    // Spec: "Their list of links shows each link's expiry and a label, sealed to the sender's public key." listMine
    // opens each label with the creator's sk and shows only their live links. A label is bound to its link's id hash, so
    // a sealed label moved onto another row doesn't open (null). Kills: labels stored in plaintext, another user's links
    // listed, expired links listed, the binding to id_hash dropped.
    public function testListMineOpensSealedLabels(): void
    {
        [$a] = $this->share('1h', ['label' => 'db for ACME']);
        [$b] = $this->share('1d', ['label' => '']);
        $this->share('1d', ['label' => 'bob link'], $this->bob);
        $sk = $this->skFor($this->alice, Fixtures::PASSPHRASE);
        $list = $this->shares()->listMine($this->alice, $sk);
        $byHash = array_column($list, null, 'id_hash');
        $expected = [ShareModel::idHash($a), ShareModel::idHash($b)];
        $listed = array_keys($byHash);
        sort($expected);
        sort($listed);
        $this->assertSame($expected, $listed, "only Alice's links");
        $this->assertSame('db for ACME', $byHash[ShareModel::idHash($a)]['label']);
        $this->assertNull($byHash[ShareModel::idHash($b)]['label']);
        $this->assertSame($this->now + 3600, $byHash[ShareModel::idHash($a)]['expires_at']);
        $this->assertFalse($byHash[ShareModel::idHash($a)]['has_passphrase']);

        $sealed = $this->row('SELECT sealed_label FROM vault_shares WHERE id_hash = ?', [ShareModel::idHash($a)])['sealed_label'];
        $this->pdo()->prepare('UPDATE vault_shares SET sealed_label = ? WHERE id_hash = ?')->execute([$sealed, ShareModel::idHash($b)]);
        $moved = array_column($this->shares()->listMine($this->alice, $sk), 'label', 'id_hash');
        $this->assertNull($moved[ShareModel::idHash($b)], 'a label moved to another link does not open');

        $this->now += 3600;
        $this->assertSame([ShareModel::idHash($b)], array_column($this->shares()->listMine($this->alice, $sk), 'id_hash'), 'expired links are not listed');
    }

    // T17 minor M1: has_passphrase is in the AD, so the browser always sends it ('0' or '1'). A body without it is
    // refused rather than defaulted. Kills: validBody's `?? '0'` default restored.
    public function testMissingHasPassphraseIsRefused(): void
    {
        $r = $this->shares()->reserve($this->alice, $this->sidHash(), '1d');
        $burn = self::burn();
        $body = $this->body($r['share_id'], $burn);
        unset($body['has_passphrase']);
        $this->assertVaultError('payload_invalid', fn () => $this->shares()->finalize($this->alice, $this->sidHash(), $body));
        $this->assertSame(0, $this->shareCount());
    }

    // R58: a label sealed to the creator's old public key would stop opening after a key rotation. The rotation sweep
    // re-seals the creator's labels to the new key (after its bridge check, in the batch's transaction), and a link
    // created while a rotation is in progress is sealed to the new key straight away, so a label made between the
    // sweep's last batch and finish isn't stranded. Afterwards the old sk opens none of them. Kills: no re-seal in the
    // sweep (the first label is null), sealLabel ignoring the rotation in progress (the third is null), a re-seal that
    // keeps the old key (the old sk still opens it).
    public function testLabelsFollowAKeyRotation(): void
    {
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'g']);
        $this->store()->createEntry($this->alice, $g, ['title' => 'e', 'password' => 'p']);
        [$before] = $this->share('1d', ['label' => 'made before']);
        $sk1 = $this->skFor($this->alice, Fixtures::PASSPHRASE);

        $crash = new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session(),
            static function (string $point): void {
                if ($point === 'start') {
                    throw new \RuntimeException('injected crash');
                }
            });
        try {
            $crash->requestManual($this->alice, $sk1, Fixtures::PASSPHRASE, self::IP);
            $this->fail('the injected crash');
        } catch (\RuntimeException $e) {
            $this->assertSame('injected crash', $e->getMessage());
        }
        [$during] = $this->share('1d', ['label' => 'made mid-rotation']);
        $pending = $this->row("SELECT * FROM vault_wraps WHERE user_id = ? AND status = 'pending'", [$this->alice]);
        $rot = $this->row('SELECT new_pk FROM vault_rotations WHERE user_id = ?', [$this->alice]);
        $kek = Kdf::kek(($this->argon())(Fixtures::PASSPHRASE, base64_decode($pending['kdf_salt']), (int) $pending['kdf_ops'], (int) $pending['kdf_mem']), 'passphrase');
        $sk2 = Wraps::unwrap($pending, $kek, base64_decode($rot['new_pk']));

        $afterSweep = null;
        $finishing = new RotationService($this->container, $this->slots(), $this->argon(), $this->clock(), $this->session(),
            function (string $point) use (&$afterSweep): void {
                if ($point === 'batch' && $afterSweep === null) {
                    [$afterSweep] = $this->share('1d', ['label' => 'made before finish']);
                }
            });
        $finishing->complete($this->alice, $sk1, $sk2);
        $this->assertNull($this->row('SELECT * FROM vault_rotations WHERE user_id = ?', [$this->alice]), 'the rotation finished');
        $this->assertNotNull($afterSweep);

        $labels = array_column($this->shares()->listMine($this->alice, $sk2), 'label', 'id_hash');
        $this->assertSame('made before', $labels[ShareModel::idHash($before)]);
        $this->assertSame('made mid-rotation', $labels[ShareModel::idHash($during)]);
        $this->assertSame('made before finish', $labels[ShareModel::idHash($afterSweep)]);
        $this->assertSame([null, null, null], array_values(array_column($this->shares()->listMine($this->alice, $sk1), 'label')), 'the old key opens none');
    }
}
