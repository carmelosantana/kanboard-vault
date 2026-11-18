<?php

use Kanboard\Plugin\Vault\Crypto\Aead;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use PHPUnit\Framework\TestCase;

class AeadTest extends TestCase
{
    private const FIELDS = ['entry', 1, 42, 7, 3];

    public function testRoundTrip(): void
    {
        $key = random_bytes(32);
        $ad = Encoding::enc(...self::FIELDS);
        $box = Aead::seal('secret', $key, $ad);
        $this->assertSame(24, strlen($box['nonce']));
        $this->assertNotSame('secret', $box['ct']);
        $this->assertSame('secret', Aead::open($box['nonce'], $box['ct'], $key, $ad));
    }

    // Kills a fixed nonce.
    public function testFreshNoncePerSeal(): void
    {
        $key = random_bytes(32);
        $this->assertNotSame(Aead::seal('x', $key, '')['nonce'], Aead::seal('x', $key, '')['nonce']);
    }

    // Kills ignoring the AD.
    public function testEachAdFieldMatters(): void
    {
        $key = random_bytes(32);
        $box = Aead::seal('secret', $key, Encoding::enc(...self::FIELDS));
        foreach (array_keys(self::FIELDS) as $i) {
            $fields = self::FIELDS;
            $fields[$i] = is_int($fields[$i]) ? $fields[$i] + 1 : $fields[$i].'x';
            try {
                Aead::open($box['nonce'], $box['ct'], $key, Encoding::enc(...$fields));
                $this->fail("AD field $i was not authenticated");
            } catch (CryptoException $e) {
                $this->assertStringNotContainsString('secret', $e->getMessage());
            }
        }
    }

    public function testWrongKeyFails(): void
    {
        $box = Aead::seal('secret', random_bytes(32), 'ad');
        $this->expectException(CryptoException::class);
        Aead::open($box['nonce'], $box['ct'], random_bytes(32), 'ad');
    }

    public function testTamperedCiphertextFails(): void
    {
        $key = random_bytes(32);
        $box = Aead::seal('secret', $key, 'ad');
        $box['ct'][0] = chr(ord($box['ct'][0]) ^ 1);
        $this->expectException(CryptoException::class);
        Aead::open($box['nonce'], $box['ct'], $key, 'ad');
    }

    // A malformed key or nonce is a CryptoException, never a raw SodiumException.
    public function testBadLengthsThrowCryptoException(): void
    {
        foreach ([fn() => Aead::seal('x', 'short', ''), fn() => Aead::open('short', 'ct', random_bytes(32), ''), fn() => Aead::open(random_bytes(24), 'ct', 'short', '')] as $call) {
            try {
                $call();
                $this->fail('expected CryptoException');
            } catch (CryptoException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
