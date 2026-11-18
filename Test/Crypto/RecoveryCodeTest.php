<?php

use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\RecoveryCode;
use PHPUnit\Framework\TestCase;

class RecoveryCodeTest extends TestCase
{
    private const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

    public function testFormat(): void
    {
        $code = RecoveryCode::generate();
        $this->assertSame(20, strlen($code['secret']));
        $this->assertMatchesRegularExpression('/^([0-9A-HJKMNP-TV-Z]{4}-){8}[0-9A-HJKMNP-TV-Z]{2}$/', $code['display']);
        $this->assertSame($code['secret'], RecoveryCode::parse($code['display']));
        $this->assertNotSame($code['secret'], RecoveryCode::generate()['secret']);
    }

    // Pins the Crockford bit order (MSB first) and the check value, independent of generate().
    public function testKnownVector(): void
    {
        $this->assertSame(str_repeat("\x00", 20), RecoveryCode::parse('0000-0000-0000-0000-0000-0000-0000-0000-00'));
        $secret = hex2bin('0123456789abcdef0123456789abcdef01234567');
        $data = '04HMASW9NF6YY0938NKRKAYDXW0J6HB7';
        $this->assertSame('RQ', RecoveryCode::check($secret)); // top 10 bits of CRC 0xC5FF, computed independently
        $this->assertSame($secret, RecoveryCode::parse('04HM-ASW9-NF6Y-Y093-8NKR-KAYD-XW0J-6HB7-RQ'));
        // CRC-16/T10-DIF catalogue check value for "123456789".
        $this->assertSame(0xD0DB, RecoveryCode::crc16('123456789'));
    }

    public function testNormalisesCaseAndSeparators(): void
    {
        $code = RecoveryCode::generate();
        $this->assertSame($code['secret'], RecoveryCode::parse(strtolower(str_replace('-', ' ', $code['display']))));
    }

    public function testConfusablesMapToDigits(): void
    {
        $secret = hex2bin('0123456789abcdef0123456789abcdef01234567');
        $display = '04HMASW9NF6YY0938NKRKAYDXW0J6HB7'.RecoveryCode::check($secret);
        $typed = strtr($display, ['0' => 'O', '1' => 'l']);
        $this->assertSame($secret, RecoveryCode::parse($typed));
        $this->assertSame($secret, RecoveryCode::parse(strtr($display, ['1' => 'I', '0' => 'o'])));
    }

    // One character flipped throws. Exhaustive over every position and substitute, so by CRC
    // linearity no single-character typo is ever accepted for any secret.
    public function testChecksumEnforced(): void
    {
        $display = str_replace('-', '', RecoveryCode::generate()['display']);
        $accepted = 0;
        for ($i = 0; $i < strlen($display); $i++) {
            foreach (str_split(self::ALPHABET) as $c) {
                if ($c === $display[$i]) {
                    continue;
                }
                $typo = $display;
                $typo[$i] = $c;
                try {
                    RecoveryCode::parse($typo);
                    $accepted++;
                } catch (CryptoException $e) {
                }
            }
        }
        $this->assertSame(0, $accepted);
    }

    // Swapping two neighbouring data characters is caught too.
    public function testAdjacentTranspositionCaught(): void
    {
        $display = str_replace('-', '', RecoveryCode::generate()['display']);
        for ($i = 0; $i < 31; $i++) {
            if ($display[$i] === $display[$i + 1]) {
                continue;
            }
            $swap = $display;
            [$swap[$i], $swap[$i + 1]] = [$display[$i + 1], $display[$i]];
            try {
                RecoveryCode::parse($swap);
                $this->fail("transposition at $i accepted");
            } catch (CryptoException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testExactLength(): void
    {
        $display = str_replace('-', '', RecoveryCode::generate()['display']);
        foreach ([substr($display, 0, -1), $display.'0', substr($display, 0, 32), '', $display.$display] as $bad) {
            try {
                RecoveryCode::parse($bad);
                $this->fail('accepted length '.strlen($bad));
            } catch (CryptoException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testRejectsCharactersOutsideTheAlphabet(): void
    {
        $display = RecoveryCode::generate()['display'];
        $this->expectException(CryptoException::class);
        RecoveryCode::parse('U'.substr($display, 1));
    }
}
