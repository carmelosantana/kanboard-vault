<?php
require_once 'tests/units/Base.php';

use Kanboard\Plugin\Vault\Model\ServerGrant;
use Kanboard\Plugin\Vault\Model\VaultException;
use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;
use PHPUnit\Framework\TestCase;

// Spec amendment: Server grants (validation part). Consumers and fields are canonical lists: unique, sorted, 1..16
// consumers and 1..32 fields. R1: a field is a top-level name (stored plain) or a custom name stored only as
// c: + base32(BLAKE2b-128(field_mac_key, name)); a plain custom name is payload_invalid.
class ServerGrantTest extends TestCase
{
    private function assertInvalid(callable $call, string $what): void
    {
        try {
            $call();
            $this->fail("accepted $what");
        } catch (VaultException $e) {
            $this->assertSame('payload_invalid', $e->errorCode(), $what);
        }
    }

    // Kills: names not trimmed-checked, an empty list accepted, the 16 cap off by one, no dedupe or sort.
    public function testConsumers(): void
    {
        $this->assertInvalid(fn () => ServerGrant::consumers([' CveHunter']), 'a leading space');
        $this->assertInvalid(fn () => ServerGrant::consumers([]), 'no consumers');
        $names = array_map(static fn (int $i): string => 'C'.$i, range(1, 17));
        $this->assertInvalid(fn () => ServerGrant::consumers($names), '17 consumers');
        $this->assertSame(16, count(ServerGrant::consumers(array_slice($names, 0, 16))));
        $this->assertSame(['a', 'b'], ServerGrant::consumers(['b', 'a', 'a']));
        $this->assertSame(['B', 'a'], ServerGrant::consumers(['a', 'B']), 'byte order');
        $this->assertInvalid(fn () => ServerGrant::consumers([7]), 'a non-string');
    }

    public function testValidConsumer(): void
    {
        foreach (['a', 'CveHunter', 'x_1', 'C'.str_repeat('x', 63)] as $ok) {
            $this->assertTrue(ServerGrant::validConsumer($ok), $ok);
        }
        foreach (['', '9bad', '_x', 'a b', 'a-b', 'C'.str_repeat('x', 64), "a\n", null, 1, ['a']] as $bad) {
            $this->assertFalse(ServerGrant::validConsumer($bad), var_export($bad, true));
        }
    }

    // Adapted to R1: the brief's fields(['title']) is a top-level name (EntryPayload::STRING_KEYS), stored plain; a
    // custom name is the c: MAC form only. Kills: a plain custom name accepted; the control-character, empty and
    // length checks on the MAC helper's input removed; the 32 cap off by one.
    public function testFields(): void
    {
        $this->assertSame(['title'], ServerGrant::fields(['title']));
        $this->assertSame(['password', 'title', 'username'], ServerGrant::fields(['username', 'title', 'password', 'title']));
        $mac = 'c:'.str_repeat('A', 25).'Q';
        $this->assertSame([$mac, 'password'], ServerGrant::fields(['password', $mac]));
        $this->assertInvalid(fn () => ServerGrant::fields(['api_token']), 'a plain custom name');
        $this->assertInvalid(fn () => ServerGrant::fields(["x\x01"]), 'a control character');
        $this->assertInvalid(fn () => ServerGrant::fields([]), 'no fields');
        $many = array_map(static fn (int $i): string => ServerGrant::macField(str_repeat('k', 32), 'f'.$i), range(1, 33));
        $this->assertInvalid(fn () => ServerGrant::fields($many), '33 fields');
        $this->assertCount(32, ServerGrant::fields(array_slice($many, 0, 32)));
    }

    public function testValidField(): void
    {
        foreach ([...ServerGrant::TOP_LEVEL, 'c:'.str_repeat('7', 25).'4', 'c:'.str_repeat('A', 26)] as $ok) {
            $this->assertTrue(ServerGrant::validField($ok), $ok);
        }
        foreach (['', 'api_token', str_repeat('é', 65), 'c:'.str_repeat('A', 25).'B', 'c:'.str_repeat('a', 26), 'C:'.str_repeat('A', 26),
            'c:'.str_repeat('A', 26).'=', 'c:'.str_repeat('A', 27), 'Password', 'password ', null, 3] as $bad) {
            $this->assertFalse(ServerGrant::validField($bad), var_export($bad, true));
        }
    }

    // R1's encoding: RFC 4648 base32 (upper case, no padding) of the 16-byte keyed BLAKE2b. The vector is computed
    // independently here. Kills: the wrong hash length, an unkeyed hash, lower case, padding, a top-level name MACed.
    public function testMacField(): void
    {
        $key = str_repeat("\x01", 32);
        $raw = sodium_crypto_generichash('api_token', $key, 16);
        $bits = '';
        foreach (str_split($raw) as $c) {
            $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        $want = 'c:';
        foreach (str_split(str_pad($bits, 130, '0'), 5) as $chunk) {
            $want .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[bindec($chunk)];
        }
        $got = ServerGrant::macField($key, 'api_token');
        $this->assertSame($want, $got);
        $this->assertSame(28, strlen($got));
        $this->assertTrue(ServerGrant::validField($got));
        $this->assertNotSame($got, ServerGrant::macField(str_repeat("\x02", 32), 'api_token'), 'keyed');
        $this->assertSame('password', ServerGrant::macField($key, 'password'), 'a top-level name stays plain');
        $this->assertSame('title', ServerGrant::macField($key, 'title'));
        $this->assertTrue(ServerGrant::validField(ServerGrant::macField($key, str_repeat('é', 64))), '128 bytes');
        foreach (['', "x\x01", "x\x7f", str_repeat('é', 65), "\xff"] as $bad) {
            $this->assertInvalid(fn () => ServerGrant::macField($key, $bad), bin2hex($bad));
        }
        $this->expectException(LogicException::class);
        ServerGrant::macField('short', 'api_token');
    }

    // Kills: a non-canonical list decoded (callers then trust an order or uniqueness that isn't there).
    public function testEncodeAndDecodeList(): void
    {
        $this->assertSame('["CveHunter","é/x"]', ServerGrant::encodeList([1 => 'CveHunter', 5 => 'é/x']));
        $this->assertSame([], ServerGrant::decodeList(null));
        $this->assertSame(['a', 'b'], ServerGrant::decodeList('["a","b"]'));
        foreach (['["b","a"]', '["a","a"]', '["a", "b"]', '{"0":"a"}', '[1]', 'nope', '"a"', '["'.chr(92).'u00e9"]', '[["a"]]'] as $bad) {
            try {
                ServerGrant::decodeList($bad);
                $this->fail("decoded $bad");
            } catch (LogicException) {
            }
        }
    }

    public function testDefaults(): void
    {
        $this->assertSame([16, 32, 128, 60, 10], [ServerGrant::MAX_CONSUMERS, ServerGrant::MAX_FIELDS, ServerGrant::MAX_FIELD_BYTES, ServerGrant::DEFAULT_RATE, ServerGrant::DEFAULT_BURST]);
        $this->assertSame('/^[A-Za-z][A-Za-z0-9_]{0,63}$/D', ServerGrant::CONSUMER_PATTERN);
    }

    // Kills: an unknown reason accepted; the message not the bare reason; a previous exception chained.
    public function testServiceSecretException(): void
    {
        $e = new ServiceSecretException('rate_limited');
        $this->assertSame('rate_limited', $e->getMessage());
        $this->assertSame('rate_limited', $e->reason());
        $this->assertNull($e->getPrevious());
        $this->assertInstanceOf(RuntimeException::class, $e);
        foreach (ServiceSecretException::REASONS as $r) {
            $this->assertSame($r, (new ServiceSecretException($r))->reason());
        }
        $this->assertSame(['server_off', 'server_key_unavailable', 'not_shared', 'consumer_not_allowed', 'field_not_allowed',
            'rate_limited', 'revoked', 'not_found', 'orphaned'], ServiceSecretException::REASONS);
        $this->expectException(LogicException::class);
        new ServiceSecretException('bogus');
    }
}
