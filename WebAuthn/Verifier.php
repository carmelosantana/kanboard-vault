<?php

namespace Kanboard\Plugin\Vault\WebAuthn;

/**
 * In-house WebAuthn verification, fail closed (spec: Hardware keys → Registration, Unlock).
 * Policy: attestation "none" only; UP required, UV optional; ES256 and EdDSA only.
 *
 * Every failure throws WebAuthnException('webauthn_invalid'), with no chained cause and no input bytes,
 * except one: a valid assertion whose signCount didn't advance throws 'signcount_regression', which the
 * caller audits as hw_signcount. Challenge freshness and single use, and credential ownership, are the
 * caller's (HardwareKeys, T20): pass the stored challenge and the stored credential record.
 *
 * clientDataJSON policy: at most 4096 bytes; a JSON object; no key repeated in any object at any depth
 * (compared after unescaping), since json_decode would keep the last one silently; type, challenge and
 * origin are strings; crossOrigin is absent or false; topOrigin is absent.
 */
final class Verifier
{
    private const MAX_CLIENT_DATA = 4096;
    private const CHALLENGE_BYTES = 32;

    /**
     * Verifies a registration ceremony and returns the credential record to store.
     *
     * @param array{clientDataJSON:string, clientExtensionResults:array} $clientData the raw clientDataJSON
     *        bytes and the client extension results, which must report prf.enabled === true
     * @param string $attObj the raw attestation object (CBOR)
     * @return array{credential_id:string, cose_public_key:string, sign_count:int, origin:string, rp_id:string}
     *         credential_id and cose_public_key are raw bytes (the id from authData, not from the client)
     */
    public static function register(array $clientData, string $attObj, string $challenge, string $origin, string $rpId): array
    {
        try {
            $json = $clientData['clientDataJSON'] ?? null;
            $prf = $clientData['clientExtensionResults']['prf']['enabled'] ?? null;
            if (! is_string($json) || $prf !== true) {
                throw new WebAuthnException('webauthn_invalid');
            }
            self::checkClientData($json, 'webauthn.create', $challenge, $origin);

            $att = Cbor::decode($attObj);
            if (! is_array($att) || count($att) !== 3
                || ($att['fmt'] ?? null) !== 'none'
                || ($att['attStmt'] ?? null) !== []
                || ! (($att['authData'] ?? null) instanceof CborBytes)) {
                throw new WebAuthnException('webauthn_invalid');
            }
            $authData = AuthData::parse($att['authData']->bytes, true);
            self::checkAuthData($authData, $rpId);

            return [
                'credential_id' => (string) $authData->credentialId,
                'cose_public_key' => (string) $authData->coseKeyCbor,
                'sign_count' => $authData->signCount,
                'origin' => $origin,
                'rp_id' => $rpId,
            ];
        } catch (\Throwable) {
            throw new WebAuthnException('webauthn_invalid');
        }
    }

    /**
     * Verifies an assertion against a stored credential record (as register() returned it, with the stored
     * sign_count) and returns the new signCount to store.
     *
     * @param array{cose_public_key:string, sign_count:int, origin:string, rp_id:string} $cred
     */
    public static function assert(array $cred, string $clientDataJson, string $authData, string $sig, string $challenge, string $origin, string $rpId): int
    {
        try {
            $stored = $cred['sign_count'] ?? null;
            if (! is_int($stored) || $stored < 0 || ($cred['origin'] ?? null) !== $origin || ($cred['rp_id'] ?? null) !== $rpId
                || ! is_string($cred['cose_public_key'] ?? null)) {
                throw new WebAuthnException('webauthn_invalid');
            }
            self::checkClientData($clientDataJson, 'webauthn.get', $challenge, $origin);
            $parsed = AuthData::parse($authData, false);
            self::checkAuthData($parsed, $rpId);

            $map = Cbor::decode($cred['cose_public_key']);
            if (! is_array($map) || ! CoseKey::fromCbor($map)->verify($authData.hash('sha256', $clientDataJson, true), $sig)) {
                throw new WebAuthnException('webauthn_invalid');
            }

            // Spec: signCount. Checked only after the signature, so only a genuine assertion can raise it.
            // If either value is non-zero, the new one must be greater; both zero means a counterless key.
            $new = $parsed->signCount;
            $advanced = ($stored === 0 && $new === 0) || $new > $stored;
        } catch (\Throwable) {
            throw new WebAuthnException('webauthn_invalid');
        }
        if (! $advanced) {
            throw new WebAuthnException('signcount_regression');
        }
        return $new;
    }

    private static function checkAuthData(AuthData $authData, string $rpId): void
    {
        if ($rpId === '' || ! hash_equals(hash('sha256', $rpId, true), $authData->rpIdHash) || ! ($authData->flags & AuthData::UP)) {
            throw new WebAuthnException('webauthn_invalid');
        }
    }

    private static function checkClientData(string $json, string $type, string $challenge, string $origin): void
    {
        if (strlen($json) > self::MAX_CLIENT_DATA || strlen($challenge) !== self::CHALLENGE_BYTES || $origin === '') {
            throw new WebAuthnException('webauthn_invalid');
        }
        $cd = json_decode($json, false, 8, JSON_THROW_ON_ERROR);
        if (! $cd instanceof \stdClass) {
            throw new WebAuthnException('webauthn_invalid');
        }
        self::rejectDuplicateKeys($json);
        $cd = get_object_vars($cd);

        if (($cd['type'] ?? null) !== $type || ! is_string($cd['challenge'] ?? null) || ($cd['origin'] ?? null) !== $origin
            || array_key_exists('topOrigin', $cd)
            || (array_key_exists('crossOrigin', $cd) && $cd['crossOrigin'] !== false)) {
            throw new WebAuthnException('webauthn_invalid');
        }
        $got = self::base64url($cd['challenge']);
        if (! hash_equals($challenge, $got)) {
            throw new WebAuthnException('webauthn_invalid');
        }
    }

    // Strict base64url: re-encoding the decoded bytes must give back the same text, which refuses the standard
    // alphabet, padding, whitespace and non-zero trailing bits.
    private static function base64url(string $s): string
    {
        $raw = base64_decode(strtr($s, '-_', '+/'), true);
        if ($raw === false || rtrim(strtr(base64_encode($raw), '+/', '-_'), '=') !== $s) {
            throw new WebAuthnException('webauthn_invalid');
        }
        return $raw;
    }

    // $json is already known to be valid JSON. Walks it once, keeping a key set per open object, and refuses a
    // key seen before in the same object (compared decoded, so "origin" repeats "origin").
    private static function rejectDuplicateKeys(string $json): void
    {
        $stack = [];      // one entry per open container: a key set for an object, null for an array
        $expectKey = false;
        $n = strlen($json);
        for ($i = 0; $i < $n; $i++) {
            $c = $json[$i];
            if ($c === '"') {
                $j = $i + 1;
                while ($json[$j] !== '"') {
                    $j += $json[$j] === '\\' ? 2 : 1;
                }
                if ($expectKey) {
                    $key = 'k'.json_decode(substr($json, $i, $j - $i + 1), false, 1, JSON_THROW_ON_ERROR);
                    $top = array_key_last($stack);
                    if (isset($stack[$top][$key])) {
                        throw new WebAuthnException('webauthn_invalid');
                    }
                    $stack[$top][$key] = true;
                    $expectKey = false;
                }
                $i = $j;
            } elseif ($c === '{') {
                $stack[] = [];
                $expectKey = true;
            } elseif ($c === '[') {
                $stack[] = null;
                $expectKey = false;
            } elseif ($c === '}' || $c === ']') {
                array_pop($stack);
                $expectKey = false;
            } elseif ($c === ',') {
                $expectKey = $stack !== [] && is_array($stack[array_key_last($stack)]);
            }
        }
    }
}
