<?php

use Kanboard\Plugin\Vault\WebAuthn\Cbor;
use Kanboard\Plugin\Vault\WebAuthn\CborArray;
use Kanboard\Plugin\Vault\WebAuthn\CborBytes;
use Kanboard\Plugin\Vault\WebAuthn\CborException;
use PHPUnit\Framework\TestCase;

// Spec, Hardware keys: the CBOR decoder fails closed. Each rule has its own test, and each test also
// decodes the nearest valid input so an over-strict decoder is caught too.
class CborTest extends TestCase
{
    private function rejects(string $hex, string $why = ''): void
    {
        try {
            Cbor::decode((string) hex2bin(str_replace(' ', '', $hex)));
            $this->fail("accepted $hex $why");
        } catch (CborException $e) {
            $this->assertSame('cbor_invalid', $e->getMessage());
        }
    }

    private function decodes(string $hex): mixed
    {
        return Cbor::decode((string) hex2bin(str_replace(' ', '', $hex)));
    }

    // Kills a decoder that keeps the last (or first) value of a repeated key.
    public function testDuplicateMapKey(): void
    {
        $this->rejects('a2 01 01 01 02', 'int key twice');
        $this->rejects('a2 6161 01 6161 02', 'text key twice');
        $this->rejects('a2 01 01 6131 02', 'PHP would merge int 1 and text "1"');
        $this->assertSame([1 => 1, 2 => 2], $this->decodes('a2 01 01 02 02'));
    }

    // Kills a decoder that lets a text key PHP turns into an int stand in for a COSE int label.
    public function testNumericTextKeyRejected(): void
    {
        $this->rejects('a1 6131 01', 'text "1"');
        $this->rejects('a1 622d33 01', 'text "-3"');
        $this->assertSame(['01' => 1], $this->decodes('a1 623031 01'));
    }

    // Kills accepting byte-string, array or map keys (they would alias text keys or crash).
    public function testMapKeyTypes(): void
    {
        $this->rejects('a1 4161 01', 'byte-string key');
        $this->rejects('a1 80 01', 'array key');
        $this->rejects('a1 f5 01', 'bool key');
    }

    // Kills a missing minimality check, per argument width and for negative ints.
    public function testNonMinimalInt(): void
    {
        $this->rejects('18 17', '23 in one byte');
        $this->rejects('19 00ff', '255 in two bytes');
        $this->rejects('1a 0000ffff', '65535 in four bytes');
        $this->rejects('1b 00000000ffffffff', '2^32-1 in eight bytes');
        $this->rejects('38 00', '-1 in one byte');
        $this->assertSame(24, $this->decodes('18 18'));
        $this->assertSame(256, $this->decodes('19 0100'));
        $this->assertSame(65536, $this->decodes('1a 00010000'));
        $this->assertSame(4294967296, $this->decodes('1b 0000000100000000'));
        $this->assertSame(-25, $this->decodes('38 18'));
    }

    // Kills a minimality check applied to integers but not to lengths and counts.
    public function testNonMinimalLength(): void
    {
        $this->rejects('58 01 aa', 'byte string');
        $this->rejects('78 01 61', 'text string');
        $this->rejects('98 01 01', 'array');
        $this->rejects('b8 01 01 01', 'map');
    }

    // Kills accepting indefinite lengths and the reserved additional-info values.
    public function testIndefiniteLength(): void
    {
        $this->rejects('5f 41aa ff', 'indefinite bytes');
        $this->rejects('7f 6161 ff', 'indefinite text');
        $this->rejects('9f 01 ff', 'indefinite array');
        $this->rejects('bf 01 01 ff', 'indefinite map');
        $this->rejects('1f', 'uint with ai 31');
        $this->rejects('1c', 'reserved ai 28');
        $this->rejects('1d', 'reserved ai 29');
        $this->rejects('1e', 'reserved ai 30');
    }

    // Kills a decoder that ignores what follows the top-level item.
    public function testTrailingBytes(): void
    {
        $this->rejects('01 00');
        $this->rejects('a0 a0');
        $this->assertSame(1, $this->decodes('01'));
        $this->assertSame([1, 1], Cbor::decodePrefix("\x01\x00"));
    }

    // Kills a missing depth limit, or one off by one: four nested containers decode, five don't.
    public function testDepthOver4(): void
    {
        $this->assertInstanceOf(CborArray::class, $this->decodes('81 81 81 81 01'));
        $this->rejects('81 81 81 81 81 01', 'five arrays');
        $this->assertSame([1 => [1 => [1 => [1 => 1]]]], $this->decodes('a1 01 a1 01 a1 01 a1 01 01'));
        $this->rejects('a1 01 a1 01 a1 01 a1 01 a1 01 01', 'five maps');
    }

    // Kills a missing item limit, or one off by one: 64 items in total decode, 65 don't.
    public function testOver64Items(): void
    {
        $this->assertCount(63, $this->decodes('98 3f'.str_repeat('00', 63))->items);
        $this->rejects('98 40'.str_repeat('00', 64), '65 items');
        $this->rejects('9a 7fffffff 00', 'huge declared count');
        $map = 'b8 1f'.implode('', array_map(fn ($i) => sprintf('18%02x 00', 24 + $i), range(0, 30)));
        $this->assertCount(31, $this->decodes($map));
        $this->rejects('b8 20'.implode('', array_map(fn ($i) => sprintf('18%02x 00', 24 + $i), range(0, 31))), '65 items in a map');
    }

    // Kills a missing UTF-8 check: invalid bytes, overlong forms and surrogates.
    public function testInvalidUtf8(): void
    {
        $this->rejects('62 c328', 'bad continuation');
        $this->rejects('62 c0af', 'overlong');
        $this->rejects('63 eda080', 'surrogate');
        $this->rejects('61 ff');
        $this->assertSame('é', $this->decodes('62 c3a9'));
    }

    // Kills accepting tags.
    public function testTagRejected(): void
    {
        $this->rejects('c0 6161', 'tag 0');
        $this->rejects('d8 18 4100', 'tag 24');
    }

    // Kills accepting floats or simple values other than false, true and null.
    public function testFloatAndSimpleRejected(): void
    {
        $this->rejects('f9 0000', 'half float');
        $this->rejects('fa 00000000', 'single float');
        $this->rejects('fb 0000000000000000', 'double float');
        $this->rejects('f7', 'undefined');
        $this->rejects('f0', 'simple(16)');
        $this->rejects('f8 20', 'simple(32)');
        $this->rejects('ff', 'break');
        $this->assertFalse($this->decodes('f4'));
        $this->assertTrue($this->decodes('f5'));
        $this->assertNull($this->decodes('f6'));
    }

    // Kills a missing input cap, or one off by one: 4096 bytes decode, 4097 don't.
    public function testOver4KB(): void
    {
        $this->assertSame(4093, strlen($this->decodes('59 0ffd'.str_repeat('00', 4093))->bytes));
        $this->rejects('59 0ffe'.str_repeat('00', 4094), '4097 bytes');
    }

    // Kills unpacking a uint64 into a negative PHP int, or wrapping -1 - n.
    public function testIntegerOverflow(): void
    {
        $this->assertSame(PHP_INT_MAX, $this->decodes('1b 7fffffffffffffff'));
        $this->rejects('1b 8000000000000000');
        $this->assertSame(PHP_INT_MIN, $this->decodes('3b 7fffffffffffffff'));
        $this->rejects('3b 8000000000000000');
        $this->rejects('5b ffffffffffffffff 00', 'byte-string length');
    }

    // Kills reading past the end of the input.
    public function testLengthBeyondInput(): void
    {
        $this->rejects('42 00');
        $this->rejects('19 01');
        $this->rejects('82 01');
        $this->rejects('');
    }

    // Byte strings and arrays keep their CBOR type, so a text "none" isn't a byte string and [] isn't {}.
    public function testDecodesTypes(): void
    {
        $v = $this->decodes('a4 01 42 aabb 20 6161 6161 80 6162 a0');
        $this->assertInstanceOf(CborBytes::class, $v[1]);
        $this->assertSame("\xaa\xbb", $v[1]->bytes);
        $this->assertSame('a', $v[-1]);
        $this->assertInstanceOf(CborArray::class, $v['a']);
        $this->assertSame([], $v['a']->items);
        $this->assertSame([], $v['b']);
    }
}
