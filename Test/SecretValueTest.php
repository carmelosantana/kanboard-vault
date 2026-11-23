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
