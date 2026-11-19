<?php
namespace Kanboard\Plugin\Vault\Test\Support;

use Kanboard\Plugin\Vault\WebAuthn\CborArray;
use Kanboard\Plugin\Vault\WebAuthn\CborBytes;

// The recorded Chrome virtual-authenticator vectors (Test/fixtures/webauthn/*.json, written by
// scripts/e2e/record-webauthn.mjs) plus what the tests need to mutate them: a test-only CBOR
// encoder, base64url, and re-signing with the recorded (virtual, test-only) private key, so a
// mutated assertion still carries a valid signature and the rule under test is what rejects it.
final class WebAuthnVectors
{
    public const NAMES = ['es256', 'eddsa'];

    /** @return array<string,mixed> */
    public static function load(string $name): array
    {
        return json_decode((string) file_get_contents(__DIR__.'/../fixtures/webauthn/'.$name.'.json'), true, 16, JSON_THROW_ON_ERROR);
    }

    public static function unb64u(string $s): string
    {
        return (string) base64_decode(strtr($s, '-_', '+/'), true);
    }

    public static function b64u(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    // Minimal-length CBOR encoder for test inputs. PHP arrays are maps; CborArray is a CBOR array.
    public static function cbor(mixed $v): string
    {
        return match (true) {
            is_int($v) && $v >= 0 => self::head(0, $v),
            is_int($v) => self::head(1, -1 - $v),
            $v instanceof CborBytes => self::head(2, strlen($v->bytes)).$v->bytes,
            is_string($v) => self::head(3, strlen($v)).$v,
            $v instanceof CborArray => self::head(4, count($v->items)).implode('', array_map(self::cbor(...), $v->items)),
            is_array($v) => self::head(5, count($v)).implode('', array_map(
                fn ($k) => self::cbor($k).self::cbor($v[$k]), array_keys($v))),
            $v === false => "\xf4",
            $v === true => "\xf5",
            $v === null => "\xf6",
        };
    }

    private static function head(int $major, int $n): string
    {
        $m = $major << 5;
        return match (true) {
            $n < 24 => chr($m | $n),
            $n < 0x100 => chr($m | 24).chr($n),
            $n < 0x10000 => chr($m | 25).pack('n', $n),
            $n < 0x100000000 => chr($m | 26).pack('N', $n),
            default => chr($m | 27).pack('J', $n),
        };
    }

    /** @return array{fmt:string, attStmt:array, authData:CborBytes} the decoded attestation object */
    public static function attObj(array $f): array
    {
        return \Kanboard\Plugin\Vault\WebAuthn\Cbor::decode(self::unb64u($f['register']['attestationObject']));
    }

    public static function regAuthData(array $f): string
    {
        return self::attObj($f)['authData']->bytes;
    }

    // An attestation object with the given authData (fmt none, empty attStmt).
    public static function attObjWith(string $authData, mixed $fmt = 'none', mixed $attStmt = []): string
    {
        return self::cbor(['fmt' => $fmt, 'attStmt' => $attStmt, 'authData' => new CborBytes($authData)]);
    }

    // The client data JSON of a ceremony, with fields replaced (null removes) and re-serialised like Chrome does.
    public static function clientData(array $f, string $ceremony, array $replace = []): string
    {
        $cd = json_decode(self::unb64u($f[$ceremony]['clientDataJSON']), true, 8, JSON_THROW_ON_ERROR);
        foreach ($replace as $k => $v) {
            if ($v === null) {
                unset($cd[$k]);
            } else {
                $cd[$k] = $v;
            }
        }
        return json_encode($cd, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    // Signs authData ‖ SHA-256(clientDataJSON) with the recorded virtual credential's key.
    public static function sign(array $f, string $authData, string $clientDataJson): string
    {
        $data = $authData.hash('sha256', $clientDataJson, true);
        $pkcs8 = self::unb64u($f['privateKey']);
        if ($f['alg'] === -8) {
            $kp = sodium_crypto_sign_seed_keypair(substr($pkcs8, -32));
            return sodium_crypto_sign_detached($data, sodium_crypto_sign_secretkey($kp));
        }
        $pem = "-----BEGIN PRIVATE KEY-----\n".chunk_split(base64_encode($pkcs8), 64, "\n")."-----END PRIVATE KEY-----\n";
        if (! openssl_sign($data, $sig, $pem, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('test signing failed');
        }
        return $sig;
    }

    // The recorded assertion authData with its flags and signCount replaced.
    public static function assertAuthData(array $f, ?int $flags = null, ?int $signCount = null): string
    {
        $ad = self::unb64u($f['assert']['authenticatorData']);
        if ($flags !== null) {
            $ad[32] = chr($flags);
        }
        if ($signCount !== null) {
            $ad = substr_replace($ad, pack('N', $signCount), 33, 4);
        }
        return $ad;
    }
}
