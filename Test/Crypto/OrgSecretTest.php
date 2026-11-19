<?php

use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\OrgSecret;
use Kanboard\Plugin\Vault\Crypto\RecoveryCode;
use PHPUnit\Framework\TestCase;

// The org secret display: 32 bytes as 52 Crockford characters (the last one zero-padded) plus RecoveryCode's
// 2 check characters, in groups of 4. Kills: dropping the partial last character, accepting non-zero padding
// (two spellings of one key), skipping the checksum, accepting a short key.
class OrgSecretTest extends TestCase
{
    public function testRoundTripAndNormalisation(): void
    {
        $sk = random_bytes(32);
        $display = OrgSecret::format($sk);
        $this->assertMatchesRegularExpression('/^([0-9A-HJKMNP-TV-Z]{4}-){13}[0-9A-HJKMNP-TV-Z]{2}$/', $display);
        $this->assertSame($sk, OrgSecret::parse($display));
        $this->assertSame($sk, OrgSecret::parse(strtolower(str_replace('-', ' ', $display))));
        $this->assertSame($sk, OrgSecret::parse(strtr($display, ['1' => 'l', '0' => 'o'])));
    }

    public function testKnownVector(): void
    {
        $sk = str_repeat("\xff", 32);
        // 256 one-bits: 51 'Z' (5 bits each), then the last bit padded with four zeros: 10000 = 'G'.
        $this->assertSame(str_repeat('Z', 51).'G'.RecoveryCode::check($sk), str_replace('-', '', OrgSecret::format($sk)));
    }

    public function testRejectsBadInput(): void
    {
        $sk = random_bytes(32);
        $chars = str_replace('-', '', OrgSecret::format($sk));
        $alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
        $nonCanonical = $chars;
        $nonCanonical[51] = $alphabet[strpos($alphabet, $chars[51]) ^ 1]; // a padding bit set: same 32 bytes
        $substituted = $chars;
        $substituted[7] = $chars[7] === 'A' ? 'B' : 'A';
        foreach ([$nonCanonical, $substituted, substr($chars, 0, 53), $chars.'0', str_replace($chars[3], 'U', $chars), ''] as $bad) {
            try {
                OrgSecret::parse($bad);
                $this->fail('accepted: '.$bad);
            } catch (CryptoException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->expectException(CryptoException::class);
        OrgSecret::format(random_bytes(31));
    }
}
