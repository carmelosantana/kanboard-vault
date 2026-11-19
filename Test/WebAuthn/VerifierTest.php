<?php

require_once __DIR__.'/../Support/WebAuthnVectors.php';

use Kanboard\Plugin\Vault\Test\Support\WebAuthnVectors as V;
use Kanboard\Plugin\Vault\WebAuthn\AuthData;
use Kanboard\Plugin\Vault\WebAuthn\CborArray;
use Kanboard\Plugin\Vault\WebAuthn\CborBytes;
use Kanboard\Plugin\Vault\WebAuthn\Verifier;
use Kanboard\Plugin\Vault\WebAuthn\WebAuthnException;
use PHPUnit\Framework\TestCase;

// Spec, Hardware keys → Registration and Unlock, end to end on the recorded Chrome vectors. Every
// rejection mutates a valid vector in exactly one way; assertions are re-signed with the recorded
// virtual credential's key, so the signature still verifies and the rule under test is what fails.
class VerifierTest extends TestCase
{
    /** @return array<string,mixed> the registration arguments for a fixture, with overrides */
    private static function regArgs(array $f, array $o = []): array
    {
        return $o + [
            'clientData' => ['clientDataJSON' => V::unb64u($f['register']['clientDataJSON']), 'clientExtensionResults' => $f['register']['clientExtensionResults']],
            'attObj' => V::unb64u($f['register']['attestationObject']),
            'challenge' => V::unb64u($f['register']['challenge']),
            'origin' => $f['origin'],
            'rpId' => $f['rpId'],
        ];
    }

    private static function register(array $f, array $o = []): array
    {
        $a = self::regArgs($f, $o);
        return Verifier::register($a['clientData'], $a['attObj'], $a['challenge'], $a['origin'], $a['rpId']);
    }

    private static function cdReg(array $f, array $replace): array
    {
        return ['clientData' => ['clientDataJSON' => V::clientData($f, 'register', $replace), 'clientExtensionResults' => ['prf' => ['enabled' => true]]]];
    }

    // An assertion call; 'cdj' and 'authData' overrides are re-signed unless 'sig' is given too.
    private static function assertion(array $f, array $o = []): int
    {
        $cred = $o['cred'] ?? self::register($f);
        $cdj = $o['cdj'] ?? V::unb64u($f['assert']['clientDataJSON']);
        $ad = $o['authData'] ?? V::unb64u($f['assert']['authenticatorData']);
        $sig = $o['sig'] ?? (isset($o['cdj']) || isset($o['authData']) ? V::sign($f, $ad, $cdj) : V::unb64u($f['assert']['signature']));
        return Verifier::assert($cred, $cdj, $ad, $sig, $o['challenge'] ?? V::unb64u($f['assert']['challenge']),
            $o['origin'] ?? $f['origin'], $o['rpId'] ?? $f['rpId']);
    }

    private function rejects(callable $call, string $why, string $code = 'webauthn_invalid'): void
    {
        try {
            $call();
            $this->fail("accepted: $why");
        } catch (WebAuthnException $e) {
            $this->assertSame(WebAuthnException::class, $e::class, $why);
            $this->assertSame($code, $e->getMessage(), $why);
            $this->assertNull($e->getPrevious(), $why);
        }
    }

    // Kills a verifier that rejects real browser output (Chrome's random extra clientData key included).
    public function testRecordedVectorsPass(): void
    {
        foreach (V::NAMES as $name) {
            $f = V::load($name);
            $cred = self::register($f);
            $this->assertSame(['credential_id', 'cose_public_key', 'sign_count', 'origin', 'rp_id'], array_keys($cred));
            $this->assertSame(V::unb64u($f['register']['rawId']), $cred['credential_id']);
            $this->assertSame(AuthData::parse(V::regAuthData($f), true)->coseKeyCbor, $cred['cose_public_key']);
            $this->assertSame(1, $cred['sign_count']);
            $this->assertSame($f['origin'], $cred['origin']);
            $this->assertSame('localhost', $cred['rp_id']);
            $this->assertSame(2, self::assertion($f, ['cred' => $cred]), $name);
        }
    }

    // Kills skipping the fmt check, or comparing it loosely (a byte string "none" is not the text "none").
    public function testFmtNotNone(): void
    {
        $f = V::load('es256');
        $ad = V::regAuthData($f);
        $this->rejects(fn () => self::register($f, ['attObj' => V::attObjWith($ad, 'packed')]), 'packed');
        $this->rejects(fn () => self::register($f, ['attObj' => V::attObjWith($ad, new CborBytes('none'))]), 'bytes "none"');
        $this->assertSame(1, self::register($f, ['attObj' => V::attObjWith($ad)])['sign_count']);
    }

    // Kills skipping the attStmt check, or accepting an empty array for the empty map.
    public function testAttStmtNotEmpty(): void
    {
        $f = V::load('es256');
        $ad = V::regAuthData($f);
        $this->rejects(fn () => self::register($f, ['attObj' => V::attObjWith($ad, 'none', ['alg' => -7])]), 'alg in attStmt');
        $this->rejects(fn () => self::register($f, ['attObj' => V::attObjWith($ad, 'none', new CborArray([]))]), 'array attStmt');
        $this->rejects(fn () => self::register($f, ['attObj' => V::attObjWith($ad, 'none', null)]), 'null attStmt');
        $this->rejects(fn () => self::register($f, ['attObj' => V::attObjWith($ad, 'none', false)]), 'false attStmt');
    }

    // Kills a loose attestation-object shape: extra keys, a text authData, a non-map.
    public function testAttObjShape(): void
    {
        $f = V::load('es256');
        $ad = V::regAuthData($f);
        $extra = V::cbor(['fmt' => 'none', 'attStmt' => [], 'authData' => new CborBytes($ad), 'x' => 1]);
        $this->rejects(fn () => self::register($f, ['attObj' => $extra]), 'extra key');
        $this->rejects(fn () => self::register($f, ['attObj' => V::cbor(['fmt' => 'none', 'attStmt' => [], 'authData' => $ad])]), 'text authData');
        $this->rejects(fn () => self::register($f, ['attObj' => V::cbor(new CborArray(['none', [], new CborBytes($ad)]))]), 'array');
        $this->rejects(fn () => self::register($f, ['attObj' => V::unb64u($f['register']['attestationObject'])."\x00"]), 'trailing byte');
    }

    // Kills a missing or loose origin check, on both ceremonies.
    public function testForeignOrigin(): void
    {
        $f = V::load('es256');
        foreach (['http://localhost:1', $f['origin'].'/', strtoupper($f['origin']), 'https://evil.example'] as $o) {
            $this->rejects(fn () => self::register($f, self::cdReg($f, ['origin' => $o])), "register from $o");
            $this->rejects(fn () => self::assertion($f, ['cdj' => V::clientData($f, 'assert', ['origin' => $o])]), "assert from $o");
        }
        $this->rejects(fn () => self::register($f, ['origin' => 'http://localhost:1']), 'pinned origin differs');
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['origin' => '']) + ['origin' => '']), 'empty origin on both sides');
    }

    // Kills ignoring crossOrigin, or treating a non-boolean as false. Absent is fine.
    public function testCrossOriginTrue(): void
    {
        $f = V::load('eddsa');
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['crossOrigin' => true])), 'register');
        $this->rejects(fn () => self::assertion($f, ['cdj' => V::clientData($f, 'assert', ['crossOrigin' => true])]), 'assert');
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['crossOrigin' => 'false'])), 'string "false"');
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['crossOrigin' => 0])), 'int 0');
        $this->assertSame(1, self::register($f, self::cdReg($f, ['crossOrigin' => null]))['sign_count']);
        $this->assertSame(2, self::assertion($f, ['cdj' => V::clientData($f, 'assert', ['crossOrigin' => null])]));
    }

    // Kills accepting a topOrigin, which only a cross-origin (refused) ceremony carries.
    public function testTopOriginRejected(): void
    {
        $f = V::load('es256');
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['topOrigin' => $f['origin']])), 'topOrigin');
    }

    // Kills skipping the rpIdHash comparison, on both ceremonies.
    public function testWrongRpIdHash(): void
    {
        $f = V::load('es256');
        $this->rejects(fn () => self::register($f, ['rpId' => 'evil.example']), 'register for another rp_id');
        $ad = substr_replace(V::unb64u($f['assert']['authenticatorData']), hash('sha256', 'evil.example', true), 0, 32);
        $this->rejects(fn () => self::assertion($f, ['authData' => $ad]), 'assertion hashed for another rp_id');
    }

    // Kills dropping the UP requirement, on both ceremonies.
    public function testUpMissing(): void
    {
        foreach (V::NAMES as $name) {
            $f = V::load($name);
            $reg = V::regAuthData($f);
            $reg[32] = chr(ord($reg[32]) & ~AuthData::UP);
            $this->rejects(fn () => self::register($f, ['attObj' => V::attObjWith($reg)]), "$name register");
            $this->rejects(fn () => self::assertion($f, ['authData' => V::assertAuthData($f, AuthData::UV)]), "$name assert");
        }
    }

    // Kills requiring UV: the passphrase is the knowledge factor, so a key PIN is optional.
    public function testUvAbsentAccepted(): void
    {
        foreach (V::NAMES as $name) {
            $f = V::load($name);
            $reg = V::regAuthData($f);
            $reg[32] = chr(AuthData::UP | AuthData::AT);
            $this->assertSame(1, self::register($f, ['attObj' => V::attObjWith($reg)])['sign_count'], $name);
            $this->assertSame(2, self::assertion($f, ['authData' => V::assertAuthData($f, AuthData::UP)]), $name);
        }
    }

    // Kills dropping or weakening the signCount rule: when either value is non-zero, the new one must be greater.
    public function testSignCountRegression(): void
    {
        $f = V::load('es256');
        $cred = self::register($f);
        foreach ([[2, 2], [3, 2], [5, 0], [PHP_INT_MAX, 7]] as [$stored, $new]) {
            $this->rejects(fn () => self::assertion($f, ['cred' => ['sign_count' => $stored] + $cred, 'authData' => V::assertAuthData($f, null, $new)]),
                "stored $stored, new $new", 'signcount_regression');
        }
        $this->assertSame(0, self::assertion($f, ['cred' => ['sign_count' => 0] + $cred, 'authData' => V::assertAuthData($f, null, 0)]), 'both zero');
        $this->assertSame(3, self::assertion($f, ['cred' => ['sign_count' => 2] + $cred, 'authData' => V::assertAuthData($f, null, 3)]), 'one more');
        $this->assertSame(0xffffffff, self::assertion($f, ['cred' => ['sign_count' => 0] + $cred, 'authData' => V::assertAuthData($f, null, 0xffffffff)]), 'unsigned 32-bit');
    }

    // Kills a regression check that runs before the signature: a forged assertion is just invalid, never hw_signcount.
    public function testSignCountCheckedAfterSignature(): void
    {
        $f = V::load('es256');
        $ad = V::assertAuthData($f, null, 0);
        $this->rejects(fn () => self::assertion($f, ['cred' => ['sign_count' => 5] + self::register($f), 'authData' => $ad,
            'sig' => V::unb64u($f['assert']['signature'])]), 'forged regression');
    }

    // Kills skipping the type check, or swapping create and get.
    public function testWrongType(): void
    {
        $f = V::load('eddsa');
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['type' => 'webauthn.get'])), 'get on register');
        $this->rejects(fn () => self::assertion($f, ['cdj' => V::clientData($f, 'assert', ['type' => 'webauthn.create'])]), 'create on assert');
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['type' => null])), 'no type');
    }

    // Kills a missing or loose challenge comparison: another value, padding, standard base64, non-canonical bits, short.
    public function testWrongChallenge(): void
    {
        $f = V::load('es256');
        $c = $f['register']['challenge'];
        $this->rejects(fn () => self::register($f, ['challenge' => random_bytes(32)]), 'another challenge');
        $this->rejects(fn () => self::assertion($f, ['challenge' => V::unb64u($c)]), 'the registration challenge on assert');
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['challenge' => $c.'='])), 'padded');
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['challenge' => strtr($c, '-_', '+/')])), 'standard alphabet');
        $last = strpos('AEIMQUYcgkosw048', $c[42]) !== false ? chr(ord($c[42]) + 1) : $c[42];
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['challenge' => substr($c, 0, 42).$last])), 'non-zero trailing bits');
        $short = random_bytes(16);
        $this->rejects(fn () => self::register($f, self::cdReg($f, ['challenge' => V::b64u($short)]) + ['challenge' => $short]), '16-byte challenge');
        $this->rejects(fn () => self::register($f, ['challenge' => '']), 'empty expected challenge');
    }

    // Kills trusting json_decode on duplicate keys (it keeps the last one): any repeated key, at any depth, is refused.
    public function testDuplicateJsonKey(): void
    {
        $f = V::load('es256');
        $good = V::clientData($f, 'register');
        $dup = fn (string $extra) => ['clientDataJSON' => substr($good, 0, -1).','.$extra.'}', 'clientExtensionResults' => ['prf' => ['enabled' => true]]];
        $this->rejects(fn () => self::register($f, ['clientData' => $dup('"origin":"'.$f['origin'].'"')]), 'origin twice, same value');
        $this->rejects(fn () => self::register($f, ['clientData' => $dup('"'.chr(92).'u006frigin":"'.$f['origin'].'"')]), 'escaped duplicate');
        $this->rejects(fn () => self::register($f, ['clientData' => $dup('"x":{"a":1,"a":2}')]), 'nested duplicate');
        $this->rejects(fn () => self::register($f, ['clientData' => $dup('"x":[{"a":1,"a":2}]')]), 'duplicate inside an array');
        $this->assertSame(1, self::register($f, ['clientData' => $dup('"x":[{"a":1},{"a":2}],"y":{"a":{}},"z":["a","a","a"]')])['sign_count'], 'same key in sibling objects');
    }

    // Kills accepting malformed client data.
    public function testClientDataMalformed(): void
    {
        $f = V::load('es256');
        foreach (['not json', '[]', '"s"', '{"type":1}', V::clientData($f, 'register').' x', V::clientData($f, 'register', ['pad' => str_repeat('a', 4096)])] as $i => $cdj) {
            $this->rejects(fn () => self::register($f, ['clientData' => ['clientDataJSON' => $cdj, 'clientExtensionResults' => ['prf' => ['enabled' => true]]]]), "case $i");
        }
        $this->rejects(fn () => self::register($f, ['clientData' => []]), 'no clientDataJSON');
        $this->rejects(fn () => self::register($f, ['clientData' => ['clientDataJSON' => 1]]), 'non-string clientDataJSON');
    }

    // Kills dropping the prf.enabled requirement, or accepting a truthy non-boolean.
    public function testPrfNotEnabled(): void
    {
        $f = V::load('eddsa');
        $cdj = V::unb64u($f['register']['clientDataJSON']);
        foreach ([[], ['prf' => []], ['prf' => ['enabled' => false]], ['prf' => ['enabled' => 'true']], ['prf' => ['enabled' => 1]]] as $i => $ext) {
            $this->rejects(fn () => self::register($f, ['clientData' => ['clientDataJSON' => $cdj, 'clientExtensionResults' => $ext]]), "case $i");
        }
    }

    // Kills skipping the signature, or verifying it over the wrong bytes or key.
    public function testBadSignature(): void
    {
        $es = V::load('es256');
        $ed = V::load('eddsa');
        $sig = V::unb64u($es['assert']['signature']);
        $sig[20] = chr(ord($sig[20]) ^ 1);
        $this->rejects(fn () => self::assertion($es, ['sig' => $sig]), 'flipped bit');
        $this->rejects(fn () => self::assertion($es, ['cdj' => V::clientData($es, 'assert', ['x' => 'y']), 'sig' => V::unb64u($es['assert']['signature'])]), 'client data changed after signing');
        $this->rejects(fn () => self::assertion($es, ['authData' => V::assertAuthData($es, null, 3), 'sig' => V::unb64u($es['assert']['signature'])]), 'authData changed after signing');
        $this->rejects(fn () => self::assertion($es, ['cred' => self::register($ed) + ['origin' => $es['origin']]]), 'another credential');
        $this->rejects(fn () => self::assertion($ed, ['sig' => '']), 'empty signature');
    }

    // Kills ignoring the origin and rp_id pinned on the credential.
    public function testCredentialBinding(): void
    {
        $f = V::load('es256');
        $cred = self::register($f);
        $this->rejects(fn () => self::assertion($f, ['cred' => ['origin' => 'https://other.example'] + $cred]), 'origin');
        $this->rejects(fn () => self::assertion($f, ['cred' => ['rp_id' => 'other.example'] + $cred]), 'rp_id');
        $this->rejects(fn () => self::assertion($f, ['cred' => ['cose_public_key' => 'x'] + $cred]), 'unreadable key');
        $this->rejects(fn () => self::assertion($f, ['cred' => ['sign_count' => -1] + $cred]), 'negative stored count');
        $this->rejects(fn () => self::assertion($f, ['cred' => array_diff_key($cred, ['sign_count' => 0])]), 'no stored count');
    }

    // Kills an assertion path that accepts attested credential data (an AT flag).
    public function testAssertionWithAttestedData(): void
    {
        $f = V::load('es256');
        $this->rejects(fn () => self::assertion($f, ['authData' => V::regAuthData($f)]), 'registration authData on assert');
    }

    // Kills leaking input into errors: one exception type, fixed codes, no chained cause, no input bytes.
    public function testErrorsAreOneGenericType(): void
    {
        $f = V::load('es256');
        $marker = 'VaultWebAuthnMarker-Zq9';
        $calls = [
            fn () => self::register($f, self::cdReg($f, ['origin' => $marker])),
            fn () => self::register($f, ['attObj' => V::attObjWith(V::regAuthData($f), $marker)]),
            fn () => self::register($f, ['attObj' => $marker]),
            fn () => self::register($f, ['clientData' => ['clientDataJSON' => '{"'.$marker.'":']]),
            fn () => self::assertion($f, ['cred' => ['cose_public_key' => $marker] + self::register($f)]),
            fn () => self::assertion($f, ['sig' => $marker]),
        ];
        foreach ($calls as $i => $call) {
            try {
                $call();
                $this->fail("case $i accepted");
            } catch (\Throwable $e) {
                $this->assertSame(WebAuthnException::class, $e::class, "case $i");
                $this->assertSame('webauthn_invalid', $e->getMessage(), "case $i");
                $this->assertNull($e->getPrevious(), "case $i");
                $this->assertStringNotContainsString($marker, (string) $e, "case $i");
            }
        }
    }
}
