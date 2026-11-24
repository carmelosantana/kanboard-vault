<?php
require_once 'tests/units/Base.php';

use Kanboard\Plugin\Vault\Secrets\SecretValue;
use KanboardTests\units\Base;

// Spec amendment: Consumer API, security requirement 9. A SecretValue holds its bytes outside the object (a private
// static WeakMap keyed by the instance), so nothing that walks an object (var_dump, print_r, var_export, json_encode, a
// printed trace argument) can show them; it can't be serialised, cloned or cast to a string. Mutation: the bytes in a
// private property (var_export and get_object_vars bound to the class would show them).
class SecretValueTest extends Base
{
    private const VALUE = 'VaultFixtureSecret-x';

    private string|false $ignoreArgs;

    protected function setUp(): void
    {
        parent::setUp();
        $this->ignoreArgs = ini_get('zend.exception_ignore_args');
        ini_set('zend.exception_ignore_args', '0');
    }

    protected function tearDown(): void
    {
        ini_set('zend.exception_ignore_args', (string) $this->ignoreArgs);
        parent::tearDown();
    }

    public function testRevealReturnsTheValue(): void
    {
        $this->assertSame(self::VALUE, SecretValue::of(self::VALUE)->reveal());
        $a = SecretValue::of('one');
        $b = SecretValue::of('two');
        $this->assertSame(['one', 'two'], [$a->reveal(), $b->reveal()], 'each instance keeps its own bytes');
    }

    // Codex R3-03: Vault's own copy is wiped when the SecretValue goes. sodium_memzero zeroes only a string nothing else
    // holds, so the stored bytes must be a buffer of their own: not the caller's string, and not shared with a revealed
    // copy. debug_zval_dump shows the stored string's refcount (the argument adds one: 2 means sole owner) while the
    // caller's input and a revealed copy are still alive; the revealed copy and the input outlive the wrapper intact.
    // Kills: the bytes kept as a plain WeakMap string shared with the caller (no wipe can zero it); reveal() handing out
    // the stored buffer itself; a wipe that reaches the consumer's copy or the caller's input.
    public function testStoredBytesAreSoleOwnedAndWipedCopiesSurvive(): void
    {
        $input = str_repeat('k', 24).bin2hex(random_bytes(4)); // not interned
        $v = SecretValue::of($input);
        $revealed = $v->reveal();
        $map = (new ReflectionClass(SecretValue::class))->getStaticPropertyValue('bytes');
        $holder = $map[$v];
        $this->assertIsObject($holder, 'the bytes sit in a holder that can wipe them');
        ob_start();
        (fn () => debug_zval_dump($this->bytes))->call($holder);
        $dump = (string) ob_get_clean();
        $this->assertStringContainsString('refcount(2)', $dump, 'sole owner of its buffer: '.trim(preg_replace('/"[^"]*"/', '"…"', $dump)));
        unset($holder, $map, $v);
        gc_collect_cycles();
        $this->assertSame(str_repeat('k', 24), substr($revealed, 0, 24), 'the revealed copy is the consumer\'s');
        $this->assertSame($input, $revealed);
        $this->assertSame(str_repeat('k', 24), substr($input, 0, 24), 'the caller\'s input is untouched');
        $this->assertSame([], (new SecretValueTestShape())->props(SecretValue::of('x')), 'still no properties');
    }

    public function testNothingThatWalksTheObjectShowsTheValue(): void
    {
        $v = SecretValue::of(self::VALUE);
        ob_start();
        var_dump($v);
        $dumped = (string) ob_get_clean();
        $thrower = static function (SecretValue $value): void {
            throw new RuntimeException('consumer failed');
        };
        try {
            $thrower($v);
            $this->fail('expected the throw');
        } catch (RuntimeException $e) {
            $this->assertSame('0', ini_get('zend.exception_ignore_args'), 'trace arguments are recorded');
            $this->assertSame($v, $e->getTrace()[0]['args'][0] ?? null, 'the argument is in the trace');
            $printed = (string) $e;
        }
        $outputs = [
            'var_dump' => $dumped,
            'print_r' => print_r($v, true),
            'var_export' => var_export($v, true),
            'json_encode' => (string) json_encode($v),
            'exception' => $printed,
        ];
        foreach ($outputs as $what => $text) {
            $this->assertStringNotContainsString(self::VALUE, $text, $what);
        }
        $this->assertSame('{}', $outputs['json_encode']);
        $this->assertSame([], \Closure::bind(fn () => get_object_vars($this), $v, SecretValue::class)(), 'no properties');
        $this->assertSame([], (array) $v, 'no properties in an array cast');
    }

    public function testSerializeIsRefused(): void
    {
        $this->expectException(LogicException::class);
        serialize(SecretValue::of(self::VALUE));
    }

    public function testUnserializeIsRefused(): void
    {
        $this->expectException(LogicException::class);
        unserialize('O:'.strlen(SecretValue::class).':"'.SecretValue::class.'":0:{}');
    }

    public function testCloneIsRefused(): void
    {
        $v = SecretValue::of(self::VALUE);
        $this->expectException(LogicException::class);
        $copy = clone $v;
    }

    public function testStringCastIsAnError(): void
    {
        $v = SecretValue::of(self::VALUE);
        $this->expectException(Error::class);
        $s = (string) $v;
    }
}

// Reads an object's properties from inside its class scope (get_object_vars bound to the class).
final class SecretValueTestShape
{
    public function props(object $o): array
    {
        return (fn () => get_object_vars($this))->call($o);
    }
}
