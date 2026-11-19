<?php

namespace Kanboard\Plugin\Vault\WebAuthn;

/**
 * A credential public key in COSE form (spec: Hardware keys → COSE keys accepted). Exactly two shapes:
 *   EC2: {1: 2, 3: -7, -1: 1, -2: x(32 bytes), -3: y(32 bytes)}  (ES256, P-256)
 *   OKP: {1: 1, 3: -8, -1: 6, -2: x(32 bytes)}                    (EdDSA, Ed25519)
 * Any other combination, missing field, extra field or wrong CBOR type is refused with 'cose_invalid'.
 * An EC2 point must load through openssl from the fixed SPKI prefix and read back as prime256v1 with the
 * same x and y, which refuses off-curve points.
 */
final class CoseKey
{
    public const ES256 = -7;
    public const EDDSA = -8;

    // SubjectPublicKeyInfo { AlgorithmIdentifier { id-ecPublicKey, prime256v1 }, BIT STRING { 0x04 ‖ x ‖ y } }.
    private const P256_SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d03010703420004';
    // SubjectPublicKeyInfo { AlgorithmIdentifier { id-Ed25519 }, BIT STRING { x } }.
    private const ED25519_SPKI_PREFIX = '302a300506032b6570032100';

    private function __construct(public readonly int $alg, private readonly string $x, private readonly string $y)
    {
    }

    /** @param array<int|string,mixed> $map a decoded COSE_Key map */
    public static function fromCbor(array $map): self
    {
        $bytes32 = static fn (mixed $v): ?string => $v instanceof CborBytes && strlen($v->bytes) === 32 ? $v->bytes : null;
        $keys = array_keys($map);
        sort($keys);

        if ($keys === [-3, -2, -1, 1, 3] && $map[1] === 2 && $map[3] === self::ES256 && $map[-1] === 1) {
            $x = $bytes32($map[-2]);
            $y = $bytes32($map[-3]);
            if ($x !== null && $y !== null) {
                $key = new self(self::ES256, $x, $y);
                $key->checkP256Point();
                return $key;
            }
        } elseif ($keys === [-2, -1, 1, 3] && $map[1] === 1 && $map[3] === self::EDDSA && $map[-1] === 6) {
            $x = $bytes32($map[-2]);
            if ($x !== null) {
                return new self(self::EDDSA, $x, '');
            }
        }
        throw new WebAuthnException('cose_invalid');
    }

    // The DER SubjectPublicKeyInfo of this key.
    public function spki(): string
    {
        return $this->alg === self::ES256
            ? hex2bin(self::P256_SPKI_PREFIX).$this->x.$this->y
            : hex2bin(self::ED25519_SPKI_PREFIX).$this->x;
    }

    // True only for a valid signature over $data: ES256 as a strict DER ECDSA signature with SHA-256,
    // EdDSA as a 64-byte Ed25519 signature.
    public function verify(string $data, string $sig): bool
    {
        if ($this->alg === self::EDDSA) {
            return strlen($sig) === SODIUM_CRYPTO_SIGN_BYTES && sodium_crypto_sign_verify_detached($sig, $data, $this->x);
        }
        if (! self::isStrictDerSignature($sig)) {
            return false;
        }
        $key = openssl_pkey_get_public($this->pem());
        return $key !== false && openssl_verify($data, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
    }

    // Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } in strict DER: short-form lengths, both integers
    // positive, non-zero and minimally encoded, at most 32 value bytes each (33 with the sign byte), nothing after.
    public static function isStrictDerSignature(string $sig): bool
    {
        $n = strlen($sig);
        if ($n < 8 || $n > 72 || ord($sig[0]) !== 0x30 || ord($sig[1]) !== $n - 2) {
            return false;
        }
        $pos = 2;
        for ($i = 0; $i < 2; $i++) {
            if ($pos + 2 > $n || ord($sig[$pos]) !== 0x02) {
                return false;
            }
            $len = ord($sig[$pos + 1]);
            $pos += 2;
            if ($len < 1 || $len > 33 || $pos + $len > $n) {
                return false;
            }
            $first = ord($sig[$pos]);
            if ($first & 0x80) {
                return false; // negative
            }
            if ($first === 0 && ($len === 1 || (ord($sig[$pos + 1]) & 0x80) === 0)) {
                return false; // zero, or a needless leading zero
            }
            if ($len === 33 && $first !== 0) {
                return false; // more than 32 value bytes
            }
            $pos += $len;
        }
        return $pos === $n;
    }

    private function pem(): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($this->spki()), 64, "\n")."-----END PUBLIC KEY-----\n";
    }

    private function checkP256Point(): void
    {
        $key = openssl_pkey_get_public($this->pem());
        $d = $key === false ? false : openssl_pkey_get_details($key);
        if (! is_array($d) || ($d['type'] ?? null) !== OPENSSL_KEYTYPE_EC
            || ($d['ec']['curve_name'] ?? null) !== 'prime256v1'
            || ! hash_equals($this->x, str_pad((string) ($d['ec']['x'] ?? ''), 32, "\x00", STR_PAD_LEFT))
            || ! hash_equals($this->y, str_pad((string) ($d['ec']['y'] ?? ''), 32, "\x00", STR_PAD_LEFT))) {
            throw new WebAuthnException('cose_invalid');
        }
    }
}
