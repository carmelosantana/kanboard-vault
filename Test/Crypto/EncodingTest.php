<?php

use Kanboard\Plugin\Vault\Crypto\Encoding;
use PHPUnit\Framework\TestCase;

class EncodingTest extends TestCase
{
    // Kills plain concatenation.
    public function testLengthPrefixedNotConcatenated(): void
    {
        $this->assertNotSame(Encoding::enc('ab', 'c'), Encoding::enc('a', 'bc'));
    }

    // Kills a 4-byte int.
    public function testIntIsEightBytes(): void
    {
        $this->assertSame(8 + 4 + 8, strlen(Encoding::enc(1)));
    }

    // Pins the exact wire format: tag, u32 big-endian length, bytes; ints as u64 big-endian.
    public function testExactBytes(): void
    {
        $this->assertSame("vault/v1\x00\x00\x00\x02ab\x00\x00\x00\x00", Encoding::enc('ab', ''));
        $this->assertSame("vault/v1\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x01\x02", Encoding::enc(258));
        $this->assertSame('vault/v1', Encoding::enc());
    }

    // Kills encoding an int as its decimal string.
    public function testIntAndDigitStringDiffer(): void
    {
        $this->assertNotSame(Encoding::enc(1), Encoding::enc('1'));
    }

    // Kills dropping empty fields.
    public function testEmptyFieldCounts(): void
    {
        $this->assertNotSame(Encoding::enc('a', ''), Encoding::enc('a'));
    }
}
