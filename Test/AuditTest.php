<?php
require_once 'tests/units/Base.php';
require_once __DIR__.'/Support/ServiceFixture.php';

use Kanboard\Plugin\Vault\Console\OrgKeygenCommand;
use Kanboard\Plugin\Vault\Model\AuditModel;
use Kanboard\Plugin\Vault\Model\Correlation;
use Kanboard\Plugin\Vault\Model\Purger;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\ShareModel;
use Kanboard\Plugin\Vault\Model\UaFamily;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Model\VaultLock;
use Kanboard\Plugin\Vault\Model\VaultSettings;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

// Spec: Audit. vault_audit is append-only with a per-action allowlist of columns; record() throws on an unknown
// action or a non-null value in a column the action may not use, and never drops a value. Who sees what, retention,
// and every service from Tasks 5–9 recording its actions inside the transaction of the change it records.
class AuditTest extends Base
{
    use ServiceFixture;

    private const COLUMNS = ['actor_user_id', 'object_type', 'object_id', 'share_hash', 'target_user_id', 'ip_trunc', 'ua_family', 'count',
        'consumer', 'field_name', 'entry_version', 'job_ref', 'correlation_id', 'reason', 'consumers', 'fields', 'old_owner_id', 'new_owner_id', 'key_epoch'];

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpVault();
        $this->container['vaultNotifier'] = fn () => new class($this->container) extends \Kanboard\Plugin\Vault\Model\Notifier {
            protected function send(int $userId, string $subject, string $html): bool { return true; }
        };
    }

    protected function tearDown(): void
    {
        $this->tearDownVault();
        parent::tearDown();
    }

    private function audit(?string $actorKind = 'human', ?string $via = 'ui'): AuditModel
    {
        return new AuditModel($this->container, $actorKind, $via, $this->clock());
    }

    // A valid non-null value for each column.
    private static function sample(string $column): int|string
    {
        return match ($column) {
            'object_type' => 'entry',
            'share_hash' => str_repeat('ab', 32),
            'ip_trunc' => '203.0.113.0/24',
            'ua_family' => 'Firefox 140 / Linux',
            'count' => 3,
            'consumer' => 'CveHunter',
            'field_name' => 'password',
            'entry_version', 'key_epoch', 'old_owner_id', 'new_owner_id' => 2,
            'job_ref' => 'scan:2026-11-22',
            'correlation_id' => str_repeat('ab', 16),
            'reason' => 'rate_limited',
            'consumers' => '["CveHunter"]',
            'fields' => '["password"]',
            default => 1, // user and object ids: user 1 is Kanboard's admin
        };
    }

    // The spec's per-action table, copied by hand. Kills: a column added to or dropped from any action's ALLOW.
    public function testAllowMatchesTheSpecTable(): void
    {
        $sessionCols = ['actor_user_id', 'ip_trunc', 'ua_family'];
        $objectCols = ['actor_user_id', 'object_type', 'object_id'];
        $serverRead = ['object_type', 'object_id', 'field_name', 'entry_version', 'consumer', 'job_ref', 'correlation_id'];
        $serverGrant = ['actor_user_id', 'object_type', 'object_id', 'consumers', 'fields', 'correlation_id'];
        $denied = ['actor_user_id', 'object_type', 'object_id', 'reason', 'correlation_id'];
        $expected = [
            'enroll' => ['actor_user_id'], 'lock' => ['actor_user_id'], 'hw_key_add' => ['actor_user_id'],
            'hw_key_remove' => ['actor_user_id'], 'recovery_code_create' => ['actor_user_id'],
            'unlock' => $sessionCols, 'unlock_failed' => $sessionCols, 'recovery_used' => $sessionCols, 'hw_signcount' => $sessionCols,
            'read' => ['actor_user_id', 'object_type', 'object_id', 'ip_trunc'],
            'create' => $objectCols, 'update' => $objectCols, 'delete' => $objectCols, 'rekey' => $objectCols,
            'grant' => [...$objectCols, 'target_user_id'], 'revoke' => [...$objectCols, 'target_user_id'],
            'rotate' => ['actor_user_id', 'count'], 'import' => ['actor_user_id', 'count'], 'export' => ['actor_user_id', 'count'],
            'share_create' => ['actor_user_id', 'share_hash'], 'share_revoke' => ['actor_user_id', 'share_hash'],
            'share_reveal' => ['target_user_id', 'share_hash', 'ip_trunc', 'ua_family'],
            'share_expire' => ['target_user_id', 'share_hash'],
            'rate_limited' => ['target_user_id', 'ip_trunc', 'count'],
            'bad_vault_key' => ['actor_user_id', 'ip_trunc'],
            'org_recovery' => ['target_user_id'],
            'policy_change' => ['actor_user_id'],
            // R37 (spec addendum at T25): an integrity fault the rotation sweep keeps, operator-visible.
            'integrity_error' => $objectCols,
            // R72 (spec addendum at T24b): an unlock refused while a Steward switch-user session is active.
            'unlock_refused' => $sessionCols,
            // Codex security round 1: an agent enrolment refused while the principal owns objects outside its group.
            'enroll_refused' => ['actor_user_id', 'target_user_id', 'count'],
            // The spec's Server and orphan actions and their denied variants (P1). R3: a rate_limited read denial is
            // one row per bucket and window with its count, like R39, so server_read_denied also takes count.
            'server_read' => $serverRead,
            'server_read_denied' => [...$serverRead, 'reason', 'count'],
            'server_grant' => $serverGrant,
            'server_grant_denied' => $denied,
            'server_revoke' => $serverGrant,
            'server_revoke_denied' => $denied,
            'orphan_quarantine' => ['object_type', 'object_id', 'old_owner_id', 'correlation_id'],
            'orphan_claim' => ['actor_user_id', 'object_type', 'object_id', 'old_owner_id', 'new_owner_id', 'key_epoch', 'correlation_id'],
            'orphan_claim_denied' => $denied,
            'orphan_destroy' => ['actor_user_id', 'object_type', 'object_id', 'old_owner_id', 'correlation_id'],
            'orphan_destroy_denied' => $denied,
        ];
        $norm = static function (array $t): array {
            ksort($t);
            return array_map(static function (array $c): array { sort($c); return $c; }, $t);
        };
        $this->assertSame($norm($expected), $norm(AuditModel::ALLOW));
        // The spec's Actions table lists these 27, plus integrity_error (R37), unlock_refused (R72) and enroll_refused,
        // plus the spec's Server and orphan actions and their denied variants (11).
        $this->assertCount(41, AuditModel::ALLOW);
    }

    public static function actions(): array
    {
        $out = [];
        foreach (AuditModel::ALLOW as $action => $allowed) {
            $out[$action] = [$action, $allowed];
        }
        return $out;
    }

    // Table-driven from ALLOW: every allowed column is stored as given and every other column is NULL; filling any
    // disallowed column throws and writes nothing. Kills: the disallowed-column check removed or reduced to a
    // silent drop (the row would be written, or the value lost without a throw), a stored value altered.
    /** @dataProvider actions */
    public function testAllowlistTableDriven(string $action, array $allowed): void
    {
        $cols = [];
        foreach ($allowed as $c) {
            $cols[$c] = self::sample($c);
        }
        $this->audit()->record($action, $cols);
        $rows = $this->auditRows();
        $this->assertCount(1, $rows);
        foreach (self::COLUMNS as $c) {
            if (in_array($c, $allowed, true)) {
                $this->assertEquals(self::sample($c), $rows[0][$c], "$action stores $c");
            } else {
                $this->assertNull($rows[0][$c], "$action leaves $c NULL");
            }
        }
        $this->assertSame([$action, 'human', 'ui'], [$rows[0]['action'], $rows[0]['actor_kind'], $rows[0]['via']]);
        $this->assertEquals($this->now, $rows[0]['created_at']);

        foreach (array_diff(self::COLUMNS, $allowed) as $bad) {
            try {
                $this->audit()->record($action, $cols + [$bad => self::sample($bad)]);
                $this->fail("$action accepted $bad");
            } catch (LogicException $e) {
                // The message names the action, so the action name is cut before looking for the value: reason's
                // sample is 'rate_limited', which is also an action.
                $this->assertStringNotContainsString((string) self::sample($bad), str_replace($action, '', $e->getMessage()), 'the refused value is not echoed');
            }
        }
        if (! in_array('correlation_id', $allowed, true)) {
            try {
                $this->audit()->record($action, $cols + ['correlation_id' => self::sample('correlation_id')]);
                $this->fail("$action accepted correlation_id");
            } catch (LogicException) {
            }
        }
        $this->assertCount(1, $this->auditRows(), 'a refused record writes nothing');
    }

    // Kills: an unknown action accepted (written with an empty allowlist, or with no check at all).
    public function testUnknownActionThrows(): void
    {
        foreach (['', 'reveal', 'move', 'integrity', 'UNLOCK', 'unlock '] as $action) {
            try {
                $this->audit()->record($action, []);
                $this->fail("accepted action '$action'");
            } catch (LogicException) {
            }
        }
        $this->assertSame([], $this->auditRows());
    }

    // No free-form columns (spec: there is no detail_json), and only the enum values for actor_kind and via.
    // Kills: unknown keys ignored instead of refused; the enum checks removed (the DB CHECK would then surface a
    // PDOException rather than a LogicException, and MySQL has no CHECK before 8.0.16).
    public function testUnknownColumnOrBadContextThrows(): void
    {
        $cases = [
            ['detail_json', ['detail_json' => '{}']],
            ['id', ['id' => 5]],
            ['created_at', ['created_at' => 5]],
            ['actor_kind', ['actor_kind' => 'robot']],
            ['via', ['via' => 'cron']],
            ['object_type', ['actor_user_id' => 1, 'object_type' => 'share', 'object_id' => 1]],
            ['object_id type', ['actor_user_id' => 1, 'object_type' => 'entry', 'object_id' => '1']],
            ['ip_trunc shape', ['actor_user_id' => 1, 'ip_trunc' => '203.0.113.7']],
        ];
        foreach ($cases as [$name, $cols]) {
            try {
                $this->audit()->record($name === 'object_type' || $name === 'object_id type' ? 'create' : 'unlock', $cols);
                $this->fail("accepted $name");
            } catch (LogicException) {
            }
        }
        $this->assertSame([], $this->auditRows());
    }

    // actor_kind and via: explicit columns win over the model's context; with neither, a CLI process records cli/cli
    // and an agent principal's action records actor_kind agent. Kills: the context ignored, the explicit column
    // ignored, the agent lookup removed.
    public function testActorKindAndViaDefaults(): void
    {
        $this->audit('human', 'api')->record('lock', ['actor_user_id' => $this->alice]);
        $this->audit('human', 'api')->record('lock', ['actor_user_id' => $this->alice, 'actor_kind' => 'cli', 'via' => 'cli']);
        $this->audit(null, null)->record('lock', ['actor_user_id' => $this->alice]);
        $this->pdo()->prepare("INSERT INTO vault_principals (user_id, kind, public_key, key_gen, state, created_at, live_user_id) VALUES (?, 'agent', 'x', 1, 'active', 0, ?)")
            ->execute([$this->bob, $this->bob]);
        $this->audit(null, 'api')->record('lock', ['actor_user_id' => $this->bob]);
        $this->audit(null, 'api')->record('lock', ['actor_user_id' => $this->alice]);
        // R39: no actor in a web request is the system (a purge's share expiry, a rate-limit summary), not a human.
        $this->audit(null, 'ui')->record('share_expire', ['target_user_id' => $this->alice, 'share_hash' => str_repeat('ab', 32)]);
        $this->audit(null, null)->record('share_expire', ['target_user_id' => $this->alice, 'share_hash' => str_repeat('ab', 32)]);
        $this->audit(null, 'ui')->record('share_expire', ['target_user_id' => $this->alice, 'share_hash' => str_repeat('ab', 32), 'actor_kind' => 'public']);
        $got = array_map(static fn (array $r): array => [$r['actor_kind'], $r['via']], $this->auditRows());
        $this->assertSame([['human', 'api'], ['cli', 'cli'], ['cli', 'cli'], ['agent', 'api'], ['human', 'api'], ['system', 'ui'], ['cli', 'cli'], ['public', 'ui']], $got);
    }

    // Recording inside the vault lock is part of the transaction: a rollback leaves no audit row. Kills: record()
    // writing on a separate connection or committing on its own.
    public function testRecordInRolledBackTransactionLeavesNoRow(): void
    {
        try {
            (new VaultLock($this->container))->exclusive(function (): void {
                $this->audit()->record('lock', ['actor_user_id' => $this->alice]);
                throw new RuntimeException('roll back');
            });
        } catch (RuntimeException) {
        }
        $this->assertSame([], $this->auditRows());
    }

    // Retention: rows older than the given days go, newer stay. Kills: the boundary flipped, days ignored.
    public function testPurge(): void
    {
        $day = 86400;
        foreach ([$this->now - 31 * $day, $this->now - 30 * $day - 1, $this->now - 30 * $day, $this->now] as $at) {
            $this->pdo()->prepare("INSERT INTO vault_audit (created_at, actor_kind, action, via) VALUES (?, 'human', 'lock', 'ui')")->execute([$at]);
        }
        $this->assertSame(2, $this->audit()->purge(30));
        $this->assertSame([$this->now - 30 * $day, $this->now], array_map('intval', array_column($this->auditRows(), 'created_at')));
        $this->expectException(InvalidArgumentException::class);
        $this->audit()->purge(0);
    }

    // Spec "Who sees what": a user sees rows where they are the actor, or where the object or share is theirs;
    // app admins see policy_change, org_recovery and aggregate counts. Bob's group shares its id with Alice's entry,
    // so a filter that ignores object_type shows Alice a row on Bob's group. Kills: each OR branch of the filter
    // removed, object_type ignored, the admin branch granted to everyone, the target branch widened to every action.
    public function testVisibility(): void
    {
        $alice = $this->alice;
        $bob = $this->bob;
        $carol = (int) $this->container['userModel']->create(['username' => 'carol', 'password' => 'carol login password 1']);
        foreach ([$alice, $bob] as $owner) { // v5: an object's owner is a principal
            $this->pdo()->prepare("INSERT INTO vault_principals (user_id, kind, public_key, created_at, live_user_id) VALUES (?, 'human', 'cGs=', 0, ?)")->execute([$owner, $owner]);
        }
        $group = fn (int $owner): int => $this->insertId("INSERT INTO vault_groups (owner_id, parent_id, kind, key_epoch, nonce, ciphertext, crypto_v, position, created_at, updated_at) VALUES (?, NULL, 'normal', 1, '', '', 1, 0, 0, 0)", [$owner]);
        $bobGroup = $group($bob);
        $aliceGroup = $group($alice);
        $aliceEntry = $this->insertId("INSERT INTO vault_entries (group_id, owner_id, created_by, version, key_epoch, nonce, ciphertext, crypto_v, created_at, updated_at) VALUES (?, ?, ?, 1, 1, '', '', 1, 0, 0)", [$aliceGroup, $alice, $alice]);
        $this->assertSame($bobGroup, $aliceEntry, 'the fixture needs the id collision');
        $a = $this->audit();
        $a->record('unlock', ['actor_user_id' => $alice]);                                                                   // 1 alice
        $a->record('update', ['actor_user_id' => $bob, 'object_type' => 'entry', 'object_id' => $aliceEntry]);              // 2 alice (entry), bob (actor)
        $a->record('grant', ['actor_user_id' => $alice, 'object_type' => 'group', 'object_id' => $aliceGroup, 'target_user_id' => $bob]); // 3 alice
        $a->record('unlock', ['actor_user_id' => $bob]);                                                                     // 4 bob
        $a->record('share_reveal', ['target_user_id' => $alice, 'share_hash' => str_repeat('cd', 32)]);                      // 5 alice (share)
        $a->record('policy_change', ['actor_user_id' => self::ADMIN]);                                                       // 6 admin
        $a->record('org_recovery', ['target_user_id' => $bob]);                                                              // 7 admin
        $a->record('update', ['actor_user_id' => $carol, 'object_type' => 'entry', 'object_id' => $aliceEntry + 99]);       // 8 carol
        $a->record('rate_limited', ['target_user_id' => $alice, 'ip_trunc' => '203.0.113.0/24']);                            // 9 alice (her bucket)
        $a->record('create', ['actor_user_id' => $carol, 'object_type' => 'group', 'object_id' => $aliceGroup]);            // 10 alice (group), carol
        $a->record('update', ['actor_user_id' => $carol, 'object_type' => 'group', 'object_id' => $bobGroup]);              // 11 bob (group), carol

        $ids = fn (int $viewer): array => array_map('intval', array_column($a->visibleTo($viewer, 0, 50), 'id'));
        $this->assertSame([10, 9, 5, 3, 2, 1], $ids($alice));
        $this->assertSame([11, 4, 2], $ids($bob), 'a grantee or recovered user sees only their own actions and objects');
        $this->assertSame([11, 10, 8], $ids($carol));
        $this->assertSame([7, 6], $ids(self::ADMIN));
        $this->assertSame([], $ids(9999));
        // Paging, newest first.
        $this->assertSame([5, 3], array_map('intval', array_column($a->visibleTo($alice, 2, 2), 'id')));
        // Aggregate counts are for admins only.
        $this->assertSame([], $a->aggregateCounts($alice));
        $counts = $a->aggregateCounts(self::ADMIN);
        $this->assertSame(3, $counts['update']);
        $this->assertSame(2, $counts['unlock']);
    }

    // "An agent's owner sees that agent's rows" (Agents' roster). Kills: the agent branch removed or not limited to
    // the viewer's own agents.
    public function testVisibilityAgentOwner(): void
    {
        if (! class_exists(\Kanboard\Plugin\Agents\Model\AgentTable::class)) {
            $this->markTestSkipped('Agents is not installed');
        }
        $this->agentsTable();
        $agent = (int) $this->container['userModel']->create(['username' => 'agent-x', 'password' => 'agent login password 1']);
        $other = (int) $this->container['userModel']->create(['username' => 'agent-y', 'password' => 'agent login password 2']);
        $this->adoptAgent($this->alice, $agent);
        $this->adoptAgent($this->bob, $other);
        $a = $this->audit();
        $a->record('bad_vault_key', ['actor_user_id' => $agent, 'ip_trunc' => '203.0.113.0/24']); // 1 alice
        $a->record('bad_vault_key', ['actor_user_id' => $other]);                                   // 2 bob
        $a->record('rate_limited', ['target_user_id' => $agent, 'count' => 1]);                     // 3 alice
        $ids = fn (int $viewer): array => array_map('intval', array_column($a->visibleTo($viewer, 0, 50), 'id'));
        $this->assertSame([3, 1], $ids($this->alice));
        $this->assertSame([2], $ids($this->bob));
        $this->assertSame([3, 1], $ids($agent));
    }

    private function insertId(string $sql, array $params): int
    {
        $this->pdo()->prepare($sql)->execute($params);
        return (int) $this->pdo()->lastInsertId();
    }

    // ---- Wiring: each service records its actions, inside the change's own transaction ----

    // Enrolment, unlock, a failed unlock and a lock (spec: Sessions). Kills: any of the four calls removed; the
    // IP not truncated; a lock with nothing to lock audited.
    public function testSessionActionsAudited(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-1');
        $this->assertVaultError('unlock_failed', fn () => $this->unlockService()->unlock($this->alice, Fixtures::WRONG_PASSPHRASE, '2001:db8:1:2::9'));
        $this->session()->lock($this->alice);
        $this->session()->lock($this->alice); // nothing left to lock: no second row
        $rows = $this->auditRows();
        $this->assertSame(['enroll', 'unlock', 'unlock_failed', 'lock'], array_column($rows, 'action'));
        $this->assertSame([$this->alice], array_unique(array_map('intval', array_column($rows, 'actor_user_id'))));
        $this->assertSame([null, '203.0.113.0/24', '2001:db8:1::/48', null], array_column($rows, 'ip_trunc'));
    }

    // Entries, groups, grants, moves, revokes and re-keys (spec: Entries and groups, Access). A move is an update of
    // the moved object. Kills: any record call removed, the wrong object or target recorded.
    public function testObjectAndAccessActionsAudited(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $sk = $this->skFor($this->alice, Fixtures::PASSPHRASE);
        $s = $this->store();
        $g1 = $s->createGroup($this->alice, null, ['name' => 'g1']);
        $g2 = $s->createGroup($this->alice, null, ['name' => 'g2']);
        $e = $s->createEntry($this->alice, $g1, Fixtures::entry());
        $s->updateEntry($this->alice, $e, 1, ['title' => 'renamed', 'password' => Fixtures::UPDATED_PASSWORD], $sk);
        $this->grants()->grant($this->alice, 'entry', $e, $this->bob, 'read', null, $sk);
        $this->grants()->move($this->alice, 'entry', $e, $g2, $sk);
        $this->grants()->revoke($this->alice, 'entry', $e, $this->bob, $sk);
        $s->deleteObject($this->alice, 'entry', $e, $sk);

        $got = array_map(static fn (array $r): array => [$r['action'], (int) $r['actor_user_id'], $r['object_type'], (int) $r['object_id'], $r['target_user_id'] === null ? null : (int) $r['target_user_id']], $this->auditRows());
        $this->assertSame([
            ['enroll', $this->alice, null, 0, null],
            ['enroll', $this->bob, null, 0, null],
            ['create', $this->alice, 'group', $g1, null],
            ['create', $this->alice, 'group', $g2, null],
            ['create', $this->alice, 'entry', $e, null],
            ['update', $this->alice, 'entry', $e, null],
            ['grant', $this->alice, 'entry', $e, $this->bob],
            ['update', $this->alice, 'entry', $e, null],
            ['revoke', $this->alice, 'entry', $e, $this->bob],
            ['rekey', $this->alice, 'entry', $e, null],
            ['delete', $this->alice, 'entry', $e, null],
        ], $got);
    }

    // An expired grant removed by the purge is a revoke with no actor; a grantee whose Kanboard user was deleted
    // is recorded without a target (the FK would refuse the row). Kills: the expiry path not audited; the deleted
    // user's id recorded (the purge would then fail on the foreign key).
    public function testSystemRevokesAudited(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $carol = (int) $this->container['userModel']->create(['username' => 'carol', 'password' => 'carol login password 1']);
        $this->principals()->enrolHuman($carol, 'carol vault passphrase long');
        $sk = $this->skFor($this->alice, Fixtures::PASSPHRASE);
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'g']);
        $this->grants()->grant($this->alice, 'group', $g, $this->bob, 'read', $this->now + 10, $sk);
        $this->grants()->grant($this->alice, 'group', $g, $carol, 'read', null, $sk);
        $this->container['userModel']->remove($carol);
        $this->now += 20;
        (new Purger($this->container))->run($this->now, true);
        $revokes = array_map(static fn (array $r): array => [$r['actor_user_id'], $r['target_user_id'] === null ? null : (int) $r['target_user_id'], (int) $r['object_id']], $this->auditRows('revoke'));
        $this->assertEqualsCanonicalizing([[null, null, $g], [null, $this->bob, $g]], $revokes);
    }

    // A rotation records rotate with the number of objects it re-keys, in start's transaction; each re-key is a
    // rekey row. Kills: the rotate call removed, the count wrong, the record placed after start's commit (a
    // throwing audit then leaves the rotation committed).
    public function testRotateAudited(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $s = $this->store();
        $g = $s->createGroup($this->alice, null, ['name' => 'g']);
        $s->createEntry($this->alice, $g, Fixtures::entry());
        $sk = $this->skFor($this->alice, Fixtures::PASSPHRASE);
        $this->assertSame(RotationService::ROTATED, $this->principals()->changePassphrase($this->alice, Fixtures::PASSPHRASE, Fixtures::NEW_PASSPHRASE, $sk, self::IP));
        $rotate = $this->auditRows('rotate');
        $this->assertCount(1, $rotate);
        $this->assertSame([$this->alice, 2], [(int) $rotate[0]['actor_user_id'], (int) $rotate[0]['count']]);
        $this->assertCount(2, $this->auditRows('rekey'));
    }

    // If the audit write fails, the action it records does not happen (same transaction). Kills: any of these
    // record calls moved outside its lock.
    public function testAuditFailureRollsBackTheAction(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->principals()->enrolHuman($this->bob, Fixtures::BOB_PASSPHRASE);
        $sk = $this->skFor($this->alice, Fixtures::PASSPHRASE);
        $g = $this->store()->createGroup($this->alice, null, ['name' => 'g']);
        $this->container['vaultAudit'] = fn () => new class($this->container) extends AuditModel {
            public function record(string $action, array $cols): void { throw new RuntimeException('audit down'); }
        };
        $tries = [
            'vault_entries' => fn () => $this->store()->createEntry($this->alice, $g, Fixtures::entry()),
            'vault_grants' => fn () => $this->grants()->grant($this->alice, 'group', $g, $this->bob, 'read', null, $sk),
            'vault_rotations' => fn () => $this->principals()->changePassphrase($this->alice, Fixtures::PASSPHRASE, Fixtures::NEW_PASSPHRASE, $sk, self::IP),
            'vault_sessions' => fn () => $this->unlockService()->unlock($this->alice, Fixtures::PASSPHRASE, self::IP),
        ];
        foreach ($tries as $table => $fn) {
            try {
                $fn();
                $this->fail("$table: the action succeeded without its audit row");
            } catch (RuntimeException $e) {
                $this->assertSame('audit down', $e->getMessage());
            }
            $this->assertSame(0, $this->countRows('SELECT COUNT(*) FROM '.$table), "$table rolled back");
        }
        $this->assertSame(0, $this->countRows("SELECT COUNT(*) FROM vault_rate WHERE bucket LIKE 'unlock:notice:%'"));
    }

    // Recovery: code creation, a code's use (and the hardware keys it removes), org key generation, org recovery
    // and policy changes. The org commands are CLI only and say so. Kills: each record call removed; the
    // hw_key_remove rows missing; the CLI context dropped.
    public function testRecoveryActionsAudited(): void
    {
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->recovery()->setPolicy(VaultSettings::POLICY_CODE_ORG, self::ADMIN);
        $display = $this->recovery()->orgKeygen();
        $sk = $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-1');
        $code = $this->recovery()->createCode($this->alice, $sk);
        $this->addHardwareKey($this->alice, $sk);
        $this->assertSame(RotationService::ROTATED, $this->recovery()->useCode($this->alice, $code, Fixtures::NEW_PASSPHRASE, self::IP));
        $this->settings()->set('vault_idle_timeout', 20, self::ADMIN);
        $this->addHardwareKey($this->alice, $this->skFor($this->alice, Fixtures::NEW_PASSPHRASE));
        $this->assertSame(RotationService::ROTATED, $this->recovery()->orgRecover('alice-the-auditor', $display, Fixtures::PASSPHRASE));

        $rows = array_values(array_filter($this->auditRows(), static fn (array $r): bool => ! in_array($r['action'], ['rekey', 'unlock', 'enroll'], true)));
        $got = array_map(static fn (array $r): array => [$r['action'], $r['actor_kind'], $r['actor_user_id'] === null ? null : (int) $r['actor_user_id'], $r['target_user_id'] === null ? null : (int) $r['target_user_id'], $r['ip_trunc']], $rows);
        $this->assertSame([
            ['policy_change', 'cli', self::ADMIN, null, null],
            ['policy_change', 'cli', null, null, null],
            ['recovery_code_create', 'cli', $this->alice, null, null],
            ['hw_key_remove', 'cli', $this->alice, null, null],
            ['rotate', 'cli', $this->alice, null, null],
            ['recovery_used', 'cli', $this->alice, null, '203.0.113.0/24'],
            ['policy_change', 'cli', self::ADMIN, null, null],
            ['hw_key_remove', 'cli', $this->alice, null, null],
            ['rotate', 'cli', $this->alice, null, null],
            ['org_recovery', 'cli', null, $this->alice, null],
        ], $got);
        $this->assertSame(['cli'], array_values(array_unique(array_column($rows, 'via'))));
    }

    // Org key generation and org recovery set actor_kind and via to cli explicitly, not only by SAPI. Kills: the
    // explicit context removed from either call.
    public function testOrgCommandsAreCliEvenFromAWebContext(): void
    {
        $this->container['vaultAudit'] = fn () => new AuditModel($this->container, 'human', 'ui', $this->clock());
        $this->principals()->enrolHuman($this->alice, Fixtures::PASSPHRASE);
        $this->recovery()->setPolicy(VaultSettings::POLICY_CODE_ORG, self::ADMIN);
        $display = $this->recovery()->orgKeygen();
        $this->unlockAs($this->alice, Fixtures::PASSPHRASE, 'sid-1');
        $this->recovery()->orgRecover('alice-the-auditor', $display, Fixtures::NEW_PASSPHRASE);
        $byAction = [];
        foreach ($this->auditRows() as $r) {
            $byAction[$r['action']][] = $r['actor_kind'].'/'.$r['via'];
        }
        $this->assertSame(['human/ui', 'cli/cli'], $byAction['policy_change']);
        $this->assertSame(['cli/cli'], $byAction['org_recovery']);
    }

    // The purge records each expired share for its creator. Kills: the share_expire call removed.
    public function testShareExpireAudited(): void
    {
        $this->pdo()->prepare("INSERT INTO vault_shares (id_hash, burn_hash, creator_id, ciphertext, iv, salt, has_passphrase, sealed_label, created_at, expires_at) VALUES (?, 'b', ?, 'c', 'i', 's', 0, NULL, 0, ?)")
            ->execute([str_repeat('ef', 32), $this->bob, $this->now - 1]);
        (new Purger($this->container))->run($this->now, true);
        $rows = $this->auditRows('share_expire');
        $this->assertCount(1, $rows);
        $this->assertSame([$this->bob, str_repeat('ef', 32)], [(int) $rows[0]['target_user_id'], $rows[0]['share_hash']]);
    }

    // T10 carry: share_hash is exactly ShareModel's id hash (64 lowercase hex: BLAKE2b-256 of the share id), so a raw
    // share id or burn capability (32 hex), a content key k (base64url) or the whole fragment can never be recorded.
    // Kills: the old loose pattern (it took 32-hex values, so a raw id or b), a case-insensitive pattern.
    public function testShareHashIsAnIdHashOnly(): void
    {
        $id = bin2hex(random_bytes(16));
        $this->audit()->record('share_create', ['actor_user_id' => $this->alice, 'share_hash' => ShareModel::idHash($id)]);
        $refused = [
            'raw share id' => $id,
            'raw burn b' => bin2hex(random_bytes(16)),
            'key k (base64url)' => rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='),
            'fragment k||b' => rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '='),
            'upper-case hash' => strtoupper(ShareModel::idHash($id)),
            '63 hex' => substr(ShareModel::idHash($id), 1),
            '65 hex' => ShareModel::idHash($id).'0',
        ];
        foreach ($refused as $what => $value) {
            try {
                $this->audit()->record('share_create', ['actor_user_id' => $this->alice, 'share_hash' => $value]);
                $this->fail("accepted $what");
            } catch (LogicException) {
            }
        }
        $this->assertCount(1, $this->auditRows());
    }

    // T10 carry: ua_family is exactly what UaFamily builds, "<Browser> <major> / <OS>" from its fixed names, or Other.
    // A raw User-Agent, a full version, an OS version or a free-text value is refused. Kills: the old printable-ASCII
    // check (it took any short string, so a raw UA fragment).
    public function testUaFamilyShape(): void
    {
        $uas = [
            'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
            'curl/8.5.0',
        ];
        foreach ($uas as $ua) {
            $this->audit()->record('unlock', ['actor_user_id' => $this->alice, 'ua_family' => UaFamily::fromUserAgent($ua)]);
        }
        $this->assertSame(['Firefox 140 / Linux', 'Edge 131 / Windows', 'Safari 17 / iOS', 'Other / Other'], array_column($this->auditRows(), 'ua_family'));
        foreach (['Firefox 140.0.1 / Linux', 'Firefox 140 / Linux 6.1', 'Mozilla/5.0 (X11)', 'Netscape 4 / Linux', 'Firefox / Linux', 'Firefox 12345 / Linux', 'firefox 140 / linux', 'Firefox 140 / Linux '] as $bad) {
            try {
                $this->audit()->record('unlock', ['actor_user_id' => $this->alice, 'ua_family' => $bad]);
                $this->fail("accepted $bad");
            } catch (LogicException) {
            }
        }
        $this->assertCount(4, $this->auditRows());
    }

    // T10 carry: ip_trunc is exactly ClientIp::truncate's output: a canonical IPv4 /24 or IPv6 /48 network with its
    // host bits zero. Kills: the old pattern (it took 999.1.1.0/24, an IPv6 with host bits set, a non-canonical IPv6).
    public function testIpTruncShape(): void
    {
        foreach (['203.0.113.0/24', '2001:db8:1::/48'] as $ok) {
            $this->audit()->record('unlock', ['actor_user_id' => $this->alice, 'ip_trunc' => $ok]);
        }
        foreach (['999.1.1.0/24', '203.0.113.7/24', '203.0.113.0/48', '2001:db8:1:2::/48', '2001:0db8:1::/48', '::::/48', '2001:db8:1::/24', '::ffff:203.0.113.0/48', 'fe80::/48 '] as $bad) {
            try {
                $this->audit()->record('unlock', ['actor_user_id' => $this->alice, 'ip_trunc' => $bad]);
                $this->fail("accepted $bad");
            } catch (LogicException) {
            }
        }
        $this->assertCount(2, $this->auditRows());
    }

    // ---- Server reads, grants and orphans (P1) ----

    public static function malformedServerColumns(): array
    {
        $read = ['object_type' => 'entry', 'object_id' => 1, 'consumer' => 'CveHunter', 'field_name' => 'password', 'entry_version' => 1];
        $grant = ['actor_user_id' => 1, 'object_type' => 'entry', 'object_id' => 1, 'consumers' => '["CveHunter"]', 'fields' => '["password"]'];
        $denied = ['actor_user_id' => 1, 'object_type' => 'entry', 'object_id' => 1, 'reason' => 'not_shared'];
        $orphan = ['actor_user_id' => 1, 'object_type' => 'entry', 'object_id' => 1, 'old_owner_id' => 2, 'new_owner_id' => 3, 'key_epoch' => 2];
        return [
            'consumer leading digit' => ['server_read', $read, 'consumer', '9bad'],
            'consumer space' => ['server_read', $read, 'consumer', 'a b'],
            'consumer 65 chars' => ['server_read', $read, 'consumer', 'C'.str_repeat('x', 64)],
            'consumer int' => ['server_read', $read, 'consumer', 7],
            'reason unknown' => ['server_grant_denied', $denied, 'reason', 'nope'],
            'consumers not sorted' => ['server_grant', $grant, 'consumers', '["b","a"]'],
            'consumers empty' => ['server_grant', $grant, 'consumers', '[]'],
            'consumers duplicate' => ['server_grant', $grant, 'consumers', '["a","a"]'],
            'consumers spaced json' => ['server_grant', $grant, 'consumers', '["a", "b"]'],
            'consumers invalid name' => ['server_grant', $grant, 'consumers', '["9bad"]'],
            'consumers not json' => ['server_grant', $grant, 'consumers', 'CveHunter'],
            'fields plain custom name' => ['server_grant', $grant, 'fields', '["api_token"]'],
            'fields not a list' => ['server_grant', $grant, 'fields', '{"a":"password"}'],
            'correlation_id short' => ['server_read', $read, 'correlation_id', 'XYZ'],
            'correlation_id upper hex' => ['server_read', $read, 'correlation_id', str_repeat('AB', 16)],
            'field_name plain custom' => ['server_read', $read, 'field_name', 'api_token'],
            'field_name MAC lower' => ['server_read', $read, 'field_name', 'c:'.str_repeat('a', 26)],
            'field_name MAC short' => ['server_read', $read, 'field_name', 'c:'.str_repeat('A', 25)],
            'field_name MAC non-canonical tail' => ['server_read', $read, 'field_name', 'c:'.str_repeat('A', 25).'B'],
            'entry_version zero' => ['server_read', $read, 'entry_version', 0],
            'entry_version string' => ['server_read', $read, 'entry_version', '1'],
            'job_ref space' => ['server_read', $read, 'job_ref', 'scan 1'],
            'job_ref 65 chars' => ['server_read', $read, 'job_ref', str_repeat('j', 65)],
            'key_epoch zero' => ['orphan_claim', $orphan, 'key_epoch', 0],
            'old_owner_id zero' => ['orphan_claim', $orphan, 'old_owner_id', 0],
            'new_owner_id negative' => ['orphan_claim', $orphan, 'new_owner_id', -1],
            // R3: count on a read denial is a rate_limited window's tally only.
            'count without rate_limited' => ['server_read_denied', $read + ['reason' => 'not_shared'], 'count', 3],
        ];
    }

    // Kills: each column check removed or loosened (any of these would be stored).
    /** @dataProvider malformedServerColumns */
    public function testServerColumnsRefuseMalformedValues(string $action, array $cols, string $column, int|string $bad): void
    {
        $this->audit()->record($action, $cols); // the base row is valid
        try {
            $this->audit()->record($action, array_merge($cols, [$column => $bad]));
            $this->fail("accepted $column");
        } catch (LogicException $e) {
            $this->assertStringContainsString($column, $e->getMessage());
            $this->assertStringNotContainsString((string) $bad, str_replace([$action, $column], '', $e->getMessage()), 'the value is not echoed');
        }
        $this->assertCount(1, $this->auditRows());
    }

    // The valid edges: a MACed custom name (R1), title as a top-level name, the 64-character consumer and job_ref,
    // and R3's rate_limited window row. Kills: a check tightened past the spec.
    public function testServerColumnsAcceptTheirEdges(): void
    {
        $a = $this->audit();
        $a->record('server_read', ['object_type' => 'entry', 'object_id' => 1, 'field_name' => 'c:'.str_repeat('A', 25).'Q', 'consumer' => 'C'.str_repeat('x', 63), 'job_ref' => str_repeat('j', 64)]);
        $a->record('server_read', ['object_type' => 'entry', 'object_id' => 1, 'field_name' => 'title']);
        $a->record('server_grant', ['actor_user_id' => 1, 'consumers' => '["Agents","CveHunter"]', 'fields' => '["c:'.str_repeat('7', 25).'4","password","url"]']);
        $a->record('server_read_denied', ['object_type' => 'entry', 'object_id' => 1, 'consumer' => 'CveHunter', 'reason' => 'rate_limited', 'count' => 12]);
        foreach (AuditModel::REASONS as $reason) {
            $a->record('server_revoke_denied', ['actor_user_id' => 1, 'reason' => $reason]);
        }
        $rows = $this->auditRows();
        $this->assertCount(4 + count(AuditModel::REASONS), $rows);
        $this->assertSame('["Agents","CveHunter"]', $rows[2]['consumers']);
        $this->assertEquals(12, $rows[3]['count']);
    }

    // The frozen reason list. Kills: a reason dropped or added.
    public function testReasonsAreTheRefusalsAndTheGrantFailures(): void
    {
        $this->assertSame(['server_off', 'server_key_unavailable', 'not_shared', 'consumer_not_allowed', 'field_not_allowed',
            'rate_limited', 'revoked', 'not_found', 'orphaned', 'not_allowed', 'payload_invalid', 'not_enrolled'], AuditModel::REASONS);
    }

    // Kills: no auto-fill of correlation_id; a new id per row; the id not following Correlation::begin().
    public function testCorrelationIsFilledAndStable(): void
    {
        $read = ['object_type' => 'entry', 'object_id' => 1, 'consumer' => 'CveHunter', 'field_name' => 'password', 'entry_version' => 1];
        $a = $this->audit();
        $a->record('server_read', $read);
        $a->record('server_read', $read);
        $first = Correlation::id();
        Correlation::begin();
        $a->record('server_read', $read);
        $a->record('lock', ['actor_user_id' => $this->alice]);
        $ids = array_column($this->auditRows(), 'correlation_id');
        $this->assertSame([$first, $first, Correlation::id(), null], $ids);
        $this->assertNotSame($first, Correlation::id());
        $this->assertMatchesRegularExpression(Correlation::PATTERN, $first);
    }

    // Kills: 'server' refused as an actor_kind.
    public function testServerActorKindIsAccepted(): void
    {
        $this->audit(null, 'cli')->record('server_read', ['object_type' => 'entry', 'object_id' => 1, 'consumer' => 'CveHunter', 'actor_kind' => 'server']);
        (new AuditModel($this->container, 'server', 'api', $this->clock()))->record('server_read', ['object_type' => 'entry', 'object_id' => 1]);
        $this->assertSame(['server', 'server'], array_column($this->auditRows(), 'actor_kind'));
    }

    // Spec "Who sees what": the owner sees Server reads of their entries; admins see orphan rows. Kills: orphan
    // actions not in ADMIN_ACTIONS; the Server read hidden from its owner or shown to someone else.
    public function testOwnerSeesServerRowsOnTheirEntriesAndAdminsSeeOrphanRows(): void
    {
        $alice = $this->alice;
        $this->pdo()->prepare("INSERT INTO vault_principals (user_id, kind, public_key, created_at, live_user_id) VALUES (?, 'human', 'cGs=', 0, ?)")->execute([$alice, $alice]);
        $group = $this->insertId("INSERT INTO vault_groups (owner_id, parent_id, kind, key_epoch, nonce, ciphertext, crypto_v, position, created_at, updated_at) VALUES (?, NULL, 'normal', 1, '', '', 1, 0, 0, 0)", [$alice]);
        $entry = $this->insertId("INSERT INTO vault_entries (group_id, owner_id, created_by, version, key_epoch, nonce, ciphertext, crypto_v, created_at, updated_at) VALUES (?, ?, ?, 1, 1, '', '', 1, 0, 0)", [$group, $alice, $alice]);
        $a = $this->audit();
        $a->record('server_read', ['object_type' => 'entry', 'object_id' => $entry, 'consumer' => 'CveHunter', 'field_name' => 'password', 'actor_kind' => 'server']); // 1
        $a->record('orphan_destroy', ['actor_user_id' => self::ADMIN, 'object_type' => 'entry', 'object_id' => $entry + 50, 'old_owner_id' => 7]);          // 2
        $a->record('orphan_quarantine', ['object_type' => 'entry', 'object_id' => $entry + 51, 'old_owner_id' => 7, 'actor_kind' => 'system']);              // 3
        $ids = fn (int $viewer): array => array_map('intval', array_column($a->visibleTo($viewer, 0, 50), 'id'));
        $this->assertSame([1], $ids($alice));
        $this->assertSame([], $ids($this->bob));
        $this->assertSame([3, 2], $ids(self::ADMIN));
        $this->assertSame(['orphan_quarantine', 'orphan_claim', 'orphan_claim_denied', 'orphan_destroy', 'orphan_destroy_denied'],
            array_values(array_filter(AuditModel::ADMIN_ACTIONS, static fn (string $x): bool => str_starts_with($x, 'orphan_'))));
    }
}
