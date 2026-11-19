<?php

require_once __DIR__.'/../Support/WebAuthnVectors.php';

use Kanboard\Plugin\Vault\Test\Support\WebAuthnVectors as V;
use Kanboard\Plugin\Vault\WebAuthn\AuthData;
use Kanboard\Plugin\Vault\WebAuthn\CoseKey;
use Kanboard\Plugin\Vault\WebAuthn\WebAuthnException;
use PHPUnit\Framework\TestCase;

// Spec, Hardware keys → Registration: authData is parsed with exact-length consumption.
class AuthDataTest extends TestCase
{
    private const EXT = "\xa1\x6bhmac-secret\xf5"; // {"hmac-secret": true}

    private function rejects(string $bytes, bool $attested, string $why): void
    {
        try {
            AuthData::parse($bytes, $attested);
            $this->fail("accepted: $why");
        } catch (WebAuthnException $e) {
            $this->assertContains($e->getMessage(), ['authdata_invalid', 'cbor_invalid', 'cose_invalid'], $why);
        }
    }

    private static function withFlags(string $ad, int $set, int $clear = 0): string
    {
        $ad[32] = chr((ord($ad[32]) | $set) & ~$clear);
        return $ad;
    }

    public function testParsesRecordedVectors(): void
    {
        foreach (V::NAMES as $name) {
            $f = V::load($name);
            $reg = AuthData::parse(V::regAuthData($f), true);
            $this->assertSame(hash('sha256', 'localhost', true), $reg->rpIdHash);
            $this->assertSame(AuthData::UP | AuthData::UV | AuthData::AT, $reg->flags);
            $this->assertSame(1, $reg->signCount);
            $this->assertSame(V::unb64u($f['register']['rawId']), $reg->credentialId);
            $this->assertInstanceOf(CoseKey::class, $reg->coseKey);
            $this->assertSame($f['alg'], $reg->coseKey->alg);
            $this->assertNull($reg->extensions);

            $get = AuthData::parse(V::unb64u($f['assert']['authenticatorData']), false);
            $this->assertSame(2, $get->signCount);
            $this->assertSame(AuthData::UP | AuthData::UV, $get->flags);
            $this->assertNull($get->credentialId);
            $this->assertNull($get->coseKey);
        }
    }

    // Kills any missing bounds check: every proper prefix of a valid authData is rejected.
    public function testTruncated(): void
    {
        foreach (V::NAMES as $name) {
            $f = V::load($name);
            $reg = V::regAuthData($f);
            for ($n = 0; $n < strlen($reg); $n++) {
                $this->rejects(substr($reg, 0, $n), true, "$name registration prefix $n");
            }
            $get = V::unb64u($f['assert']['authenticatorData']);
            for ($n = 0; $n < strlen($get); $n++) {
                $this->rejects(substr($get, 0, $n), false, "$name assertion prefix $n");
            }
        }
    }

    // Kills accepting bytes left over after the attested data (or after the fixed header) when ED is clear.
    public function testTrailingBytesWithoutEd(): void
    {
        $f = V::load('es256');
        $this->rejects(V::regAuthData($f)."\x00", true, 'registration + 1 byte');
        $this->rejects(V::regAuthData($f).self::EXT, true, 'registration + a map, ED clear');
        $this->rejects(V::unb64u($f['assert']['authenticatorData'])."\x00", false, 'assertion + 1 byte');
    }

    // Kills ignoring the ED flag or not returning the extensions map.
    public function testEdExtensionsParsed(): void
    {
        $f = V::load('eddsa');
        $reg = AuthData::parse(self::withFlags(V::regAuthData($f), AuthData::ED).self::EXT, true);
        $this->assertSame(['hmac-secret' => true], $reg->extensions);
        $this->assertSame(V::unb64u($f['register']['rawId']), $reg->credentialId);
        $get = AuthData::parse(self::withFlags(V::unb64u($f['assert']['authenticatorData']), AuthData::ED).self::EXT, false);
        $this->assertSame(['hmac-secret' => true], $get->extensions);
    }

    // Kills treating ED as optional: the flag promises a map.
    public function testEdWithoutExtensions(): void
    {
        $f = V::load('es256');
        $this->rejects(self::withFlags(V::regAuthData($f), AuthData::ED), true, 'registration');
        $this->rejects(self::withFlags(V::unb64u($f['assert']['authenticatorData']), AuthData::ED), false, 'assertion');
    }

    // Kills accepting anything but one well-formed text-keyed map after ED, under the same CBOR rules.
    public function testEdExtensionsMalformed(): void
    {
        $get = self::withFlags(V::unb64u(V::load('es256')['assert']['authenticatorData']), AuthData::ED);
        $this->rejects($get."\x81\x01", false, 'an array');
        $this->rejects($get."\xf5", false, 'a bool');
        $this->rejects($get.self::EXT."\x00", false, 'trailing byte after the map');
        $this->rejects($get."\xa1\x01\xf5", false, 'an int key');
        $this->rejects($get."\xa2\x61a\xf5\x61a\xf5", false, 'duplicate key');
        $this->rejects($get."\xa1\x61a\xfa\x00\x00\x00\x00", false, 'a float');
        $this->rejects($get."\xa1\x61a\x81\x81\x81\x81\x01", false, 'depth 5');
    }

    // Kills skipping the AT check either way: registration needs it, an assertion must not have it.
    public function testAtExpectation(): void
    {
        $f = V::load('es256');
        $this->rejects(V::regAuthData($f), false, 'attested data on an assertion');
        $this->rejects(V::unb64u($f['assert']['authenticatorData']), true, 'no attested data on a registration');
        $this->rejects(self::withFlags(V::regAuthData($f), 0, AuthData::AT), true, 'AT cleared');
    }

    // Kills trusting the credential id length: zero, past the end, or over the 1023-byte cap.
    public function testCredentialIdLength(): void
    {
        $reg = V::regAuthData(V::load('es256'));
        $this->rejects(substr($reg, 0, 53)."\x00\x00".substr($reg, 55 + 32), true, 'zero, COSE key right after');
        $this->rejects(substr_replace($reg, "\xff\xff", 53, 2), true, 'past the end');
        $long = substr($reg, 0, 53).pack('n', 1024).str_repeat("\x01", 1024).substr($reg, 55 + 32);
        $this->rejects($long, true, '1024 bytes');
        $ok = substr($reg, 0, 53).pack('n', 1023).str_repeat("\x01", 1023).substr($reg, 55 + 32);
        $this->assertSame(str_repeat("\x01", 1023), AuthData::parse($ok, true)->credentialId);
    }

    // Kills a missing overall cap: authData over 4 KB is rejected before parsing.
    public function testOver4KB(): void
    {
        $get = self::withFlags(V::unb64u(V::load('es256')['assert']['authenticatorData']), AuthData::ED);
        $ext = fn (int $n) => "\xa1\x61a\x59".pack('n', $n).str_repeat("\x00", $n);
        $fits = $get.$ext(4096 - 37 - 6);
        $this->assertSame(4096, strlen($fits));
        $this->assertSame(4096 - 43, strlen(AuthData::parse($fits, false)->extensions['a']->bytes));
        $this->rejects($get.$ext(4096 - 37 - 5), false, '4097 bytes');
    }
}
