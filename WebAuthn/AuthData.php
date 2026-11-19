<?php

namespace Kanboard\Plugin\Vault\WebAuthn;

/**
 * Authenticator data, parsed with exact-length consumption (spec: Hardware keys → Registration):
 * rpIdHash (32) ‖ flags (1) ‖ signCount (4, big-endian) ‖ [attested credential data] ‖ [extensions].
 * Attested credential data is AAGUID (16) ‖ id length (2) ‖ id (1..1023) ‖ COSE key, present exactly when
 * the caller expects it (registration) and the AT flag says so. With ED set, one text-keyed CBOR map must
 * follow; without it, nothing may. Policy (UP, rpIdHash) is the Verifier's; this class only parses.
 */
final class AuthData
{
    public const UP = 0x01;
    public const UV = 0x04;
    public const AT = 0x40;
    public const ED = 0x80;
    public const MAX_BYTES = 4096;
    private const MAX_CREDENTIAL_ID = 1023;

    /** @param array<string,mixed>|null $extensions */
    private function __construct(
        public readonly string $rpIdHash,
        public readonly int $flags,
        public readonly int $signCount,
        public readonly ?string $credentialId,
        public readonly ?CoseKey $coseKey,
        public readonly ?string $coseKeyCbor,
        public readonly ?array $extensions,
    ) {
    }

    public static function parse(string $bytes, bool $expectAttested): self
    {
        $n = strlen($bytes);
        if ($n < 37 || $n > self::MAX_BYTES) {
            throw new WebAuthnException('authdata_invalid');
        }
        $flags = ord($bytes[32]);
        if ((bool) ($flags & self::AT) !== $expectAttested) {
            throw new WebAuthnException('authdata_invalid');
        }
        $pos = 37;

        $credentialId = $coseKey = $coseKeyCbor = null;
        if ($expectAttested) {
            if ($n < $pos + 18) {
                throw new WebAuthnException('authdata_invalid');
            }
            $idLen = unpack('n', $bytes, $pos + 16)[1];
            $pos += 18;
            if ($idLen < 1 || $idLen > self::MAX_CREDENTIAL_ID || $n - $pos <= $idLen) {
                throw new WebAuthnException('authdata_invalid'); // the COSE key must follow the id
            }
            $credentialId = substr($bytes, $pos, $idLen);
            $pos += $idLen;
            [$map, $used] = Cbor::decodePrefix(substr($bytes, $pos));
            if (! is_array($map)) {
                throw new WebAuthnException('authdata_invalid');
            }
            $coseKey = CoseKey::fromCbor($map);
            $coseKeyCbor = substr($bytes, $pos, $used);
            $pos += $used;
        }

        $extensions = null;
        if ($flags & self::ED) { // decodePrefix refuses an empty remainder: ED promises a map
            [$extensions, $used] = Cbor::decodePrefix(substr($bytes, $pos));
            if (! is_array($extensions) || array_filter(array_keys($extensions), 'is_int') !== []) {
                throw new WebAuthnException('authdata_invalid');
            }
            $pos += $used;
        }

        if ($pos !== $n) {
            throw new WebAuthnException('authdata_invalid');
        }
        return new self(substr($bytes, 0, 32), $flags, unpack('N', $bytes, 33)[1], $credentialId, $coseKey, $coseKeyCbor, $extensions);
    }
}
