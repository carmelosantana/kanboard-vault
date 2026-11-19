<?php

require_once __DIR__.'/../Support/WebAuthnVectors.php';

use Kanboard\Plugin\Vault\Test\Support\WebAuthnVectors as V;
use Kanboard\Plugin\Vault\WebAuthn\AuthData;
use Kanboard\Plugin\Vault\WebAuthn\Cbor;
use Kanboard\Plugin\Vault\WebAuthn\CborBytes;
use Kanboard\Plugin\Vault\WebAuthn\CoseKey;
use Kanboard\Plugin\Vault\WebAuthn\WebAuthnException;
use PHPUnit\Framework\TestCase;

// Spec, Hardware keys → COSE keys accepted: EC2/ES256/P-256 and OKP/EdDSA/Ed25519 only, exact shapes.
class CoseKeyTest extends TestCase
{
    /** @return array<int,mixed> the recorded credential's COSE key map */
    private static function map(string $name): array
    {
        return Cbor::decode(AuthData::parse(V::regAuthData(V::load($name)), true)->coseKeyCbor);
    }

    private function rejects(array $map, string $why): void
    {
        try {
            CoseKey::fromCbor($map);
            $this->fail("accepted: $why");
        } catch (WebAuthnException $e) {
            $this->assertSame('cose_invalid', $e->getMessage(), $why);
        }
    }

    private static function with(array $map, array $set): array
    {
        foreach ($set as $k => $v) {
            if ($v === null) {
                unset($map[$k]);
            } else {
                $map[$k] = $v;
            }
        }
        return $map;
    }

    public function testRecordedKeysLoad(): void
    {
        $ec = self::map('es256');
        $this->assertSame([1 => 2, 3 => -7, -1 => 1], array_intersect_key($ec, [1 => 0, 3 => 0, -1 => 0]));
        $this->assertSame(-7, CoseKey::fromCbor($ec)->alg);
        $this->assertSame(-8, CoseKey::fromCbor(self::map('eddsa'))->alg);
    }

    // Kills skipping the on-curve check: a flipped bit in y, and the all-zero point, are refused.
    public function testOffCurvePoint(): void
    {
        $ec = self::map('es256');
        $y = $ec[-3]->bytes;
        $y[31] = chr(ord($y[31]) ^ 1);
        $this->rejects(self::with($ec, [-3 => new CborBytes($y)]), 'y off by one bit');
        $zero = new CborBytes(str_repeat("\x00", 32));
        $this->rejects(self::with($ec, [-2 => $zero, -3 => $zero]), 'point (0,0)');
    }

    // Kills a missing or loose length check on x and y (EC2) and x (OKP).
    public function testWrongCoordSize(): void
    {
        $ec = self::map('es256');
        $x = $ec[-2]->bytes;
        $y = $ec[-3]->bytes;
        $this->rejects(self::with($ec, [-2 => new CborBytes(substr($x, 1))]), 'x 31 bytes');
        $this->rejects(self::with($ec, [-2 => new CborBytes("\x00".$x)]), 'x 33 bytes');
        $this->rejects(self::with($ec, [-3 => new CborBytes(substr($y, 1))]), 'y 31 bytes');
        $this->rejects(self::with($ec, [-3 => new CborBytes("\x00".$y)]), 'y 33 bytes');
        $okp = self::map('eddsa');
        $this->rejects(self::with($okp, [-2 => new CborBytes(substr($okp[-2]->bytes, 1))]), 'Ed25519 x 31 bytes');
        $this->rejects(self::with($okp, [-2 => new CborBytes($okp[-2]->bytes."\x00")]), 'Ed25519 x 33 bytes');
    }

    // Kills checking alg alone (or kty alone): every crossed combination is refused.
    public function testAlgKtyMismatch(): void
    {
        $ec = self::map('es256');
        $okp = self::map('eddsa');
        $this->rejects(self::with($ec, [3 => -8]), 'EC2 with EdDSA');
        $this->rejects(self::with($okp, [3 => -7]), 'OKP with ES256');
        $this->rejects(self::with($ec, [-1 => 6]), 'EC2 with Ed25519 curve');
        $this->rejects(self::with($okp, [-1 => 1]), 'OKP with P-256 curve');
        $this->rejects(self::with($ec, [1 => 1]), 'kty OKP with an EC2 body');
        $this->rejects(self::with($okp, [1 => 2]), 'kty EC2 with an OKP body');
        $this->rejects(self::with($ec, [3 => -257]), 'RS256');
        $this->rejects(self::with($ec, [-1 => 2]), 'P-384 curve id');
    }

    // Kills accepting a missing or an extra field.
    public function testExtraOrMissingField(): void
    {
        $ec = self::map('es256');
        $okp = self::map('eddsa');
        $this->rejects(self::with($ec, [-3 => null]), 'EC2 without y');
        $this->rejects(self::with($ec, [3 => null]), 'EC2 without alg');
        $this->rejects(self::with($okp, [-1 => null]), 'OKP without crv');
        $this->rejects(self::with($ec, [2 => new CborBytes('kid')]), 'EC2 with kid');
        $this->rejects(self::with($okp, [-3 => new CborBytes(str_repeat("\x01", 32))]), 'OKP with y');
        $this->rejects(self::with($okp, [-4 => new CborBytes(str_repeat("\x01", 32))]), 'OKP with d');
    }

    // Kills loose comparisons: labels and coordinates have exact CBOR types.
    public function testFieldTypes(): void
    {
        $ec = self::map('es256');
        $this->rejects(self::with($ec, [-2 => $ec[-2]->bytes]), 'x as a text string');
        $this->rejects(self::with($ec, [3 => '-7']), 'alg as text');
        $this->rejects(self::with($ec, [1 => true]), 'kty as bool');
        $this->rejects(self::with($ec, [1 => new CborBytes("\x02")]), 'kty as bytes');
    }

    // Kills a wrong DER prefix: openssl reads back prime256v1 with the same x and y.
    public function testSpki(): void
    {
        $ec = self::map('es256');
        $spki = CoseKey::fromCbor($ec)->spki();
        $this->assertSame('3059301306072a8648ce3d020106082a8648ce3d03010703420004', bin2hex(substr($spki, 0, 27)));
        $d = openssl_pkey_get_details(openssl_pkey_get_public(
            "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($spki), 64, "\n")."-----END PUBLIC KEY-----\n"));
        $this->assertSame('prime256v1', $d['ec']['curve_name']);
        $this->assertSame($ec[-2]->bytes, str_pad($d['ec']['x'], 32, "\x00", STR_PAD_LEFT));
        $okp = self::map('eddsa');
        $this->assertSame('302a300506032b6570032100'.bin2hex($okp[-2]->bytes), bin2hex(CoseKey::fromCbor($okp)->spki()));
    }

    // Kills a verify() that always passes, or one that ignores the data.
    public function testVerifyRecordedSignatures(): void
    {
        foreach (V::NAMES as $name) {
            $f = V::load($name);
            $key = CoseKey::fromCbor(self::map($name));
            $data = V::unb64u($f['assert']['authenticatorData']).hash('sha256', V::unb64u($f['assert']['clientDataJSON']), true);
            $sig = V::unb64u($f['assert']['signature']);
            $this->assertTrue($key->verify($data, $sig), $name);
            $this->assertFalse($key->verify($data."\x00", $sig), "$name, data changed");
            $bad = $sig;
            $bad[10] = chr(ord($bad[10]) ^ 1);
            $this->assertFalse($key->verify($data, $bad), "$name, signature changed");
        }
    }

    // Kills a sodium call reached with a wrong-length signature (it would throw, not return false).
    public function testEd25519SignatureLength(): void
    {
        $f = V::load('eddsa');
        $key = CoseKey::fromCbor(self::map('eddsa'));
        $sig = V::unb64u($f['assert']['signature']);
        $this->assertFalse($key->verify('x', substr($sig, 0, 63)));
        $this->assertFalse($key->verify('x', $sig."\x00"));
        $this->assertFalse($key->verify('x', ''));
    }

    // Kills a loose DER reader: the ECDSA signature must be exactly SEQUENCE { INTEGER r, INTEGER s }, minimal.
    public function testDerSignatureStrict(): void
    {
        $int = fn (string $hex) => '02'.sprintf('%02x', strlen($hex) / 2).$hex;
        $seq = fn (string $body) => '30'.sprintf('%02x', strlen($body) / 2).$body;
        $r = '00'.str_repeat('ff', 32);
        $s = '7f'.str_repeat('ee', 31);
        $ok = fn (string $hex) => CoseKey::isStrictDerSignature((string) hex2bin($hex));
        $this->assertTrue($ok($seq($int($r).$int($s))));
        $this->assertTrue($ok($seq($int('01').$int('01'))));
        $this->assertTrue(CoseKey::isStrictDerSignature(V::unb64u(V::load('es256')['assert']['signature'])));

        $this->assertFalse($ok($seq($int($r).$int($s)).'00'), 'trailing byte');
        $this->assertFalse($ok('3081'.substr($seq($int($r).$int($s)), 2)), 'long-form length');
        $this->assertFalse($ok($seq($int('00'.$s).$int($s))), 'needless leading zero');
        $this->assertFalse($ok($seq($int('ff'.str_repeat('ee', 31)).$int($s))), 'negative r');
        $this->assertFalse($ok($seq($int('00').$int($s))), 'zero r');
        $this->assertFalse($ok($seq($int($s).$int('00'))), 'zero s');
        $this->assertFalse($ok($seq($int('01'.$r).$int($s))), 'r over 33 bytes');
        $this->assertFalse($ok($seq($int($r))), 'no s');
        $this->assertFalse($ok($seq($int('01').$int('01').$int('01'))), 'third integer');
        $this->assertFalse($ok($seq($int('01').$int('01')).'0201'), 'bytes after the SEQUENCE, length kept');
        $this->assertFalse($ok($seq($int('01'.str_repeat('ee', 32)).$int($s))), 'r with 33 value bytes');
        $good = $seq($int($r).$int($s));
        $this->assertFalse($ok(substr($good, 0, 2).sprintf('%02x', hexdec(substr($good, 2, 2)) - 1).substr($good, 4)), 'SEQUENCE length one short');
        $this->assertFalse($ok('3006'.$int('01').'0205'.'00'), 'zero-led INTEGER past the end');
        $this->assertFalse($ok('31'.substr($seq($int($r).$int($s)), 2)), 'SET, not SEQUENCE');
        $this->assertFalse($ok($seq('03'.substr($int($r), 2).$int($s))), 'BIT STRING, not INTEGER');
        $this->assertFalse($ok($seq('0200'.$int($s))), 'empty INTEGER');
        $this->assertFalse($ok('3006'.$int('01').'0205'.'01'), 'INTEGER past the end');
        $this->assertFalse($ok(''), 'empty');
    }
}
