<?php
namespace Kanboard\Plugin\Vault\Test\Support;

use Kanboard\Plugin\Vault\WebAuthn\CborBytes;

// A test-only software authenticator for the hardware-key tests (T20). It answers navigator.credentials.create and
// .get the way the browser hands them to Vault: real CBOR attestation objects ("none"), real authData, real ES256 or
// EdDSA signatures over authData ‖ SHA-256(clientDataJSON), and a PRF output that depends only on this key and the
// salt (as CTAP2 hmac-secret does). The challenge, origin and rp_id come from the test, so every rule the server
// checks can be exercised against challenges the server itself issued.
final class SoftAuthenticator
{
    public string $rawId;
    public int $signCount = 0;
    private string $prfSecret;
    private string $edSecret = '';
    private string $ecPem = '';
    private array $cose;

    public function __construct(public readonly int $alg = -8)
    {
        $this->rawId = random_bytes(32);
        $this->prfSecret = random_bytes(32);
        if ($alg === -8) {
            $kp = sodium_crypto_sign_keypair();
            $this->edSecret = sodium_crypto_sign_secretkey($kp);
            $this->cose = [1 => 1, 3 => -8, -1 => 6, -2 => new CborBytes(sodium_crypto_sign_publickey($kp))];
        } else {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            openssl_pkey_export($key, $this->ecPem);
            $d = openssl_pkey_get_details($key)['ec'];
            $this->cose = [1 => 2, 3 => -7, -1 => 1, -2 => new CborBytes(str_pad($d['x'], 32, "\0", STR_PAD_LEFT)), -3 => new CborBytes(str_pad($d['y'], 32, "\0", STR_PAD_LEFT))];
        }
    }

    public function id(): string
    {
        return WebAuthnVectors::b64u($this->rawId);
    }

    // Replaces the COSE public key this authenticator reports at create (a bad key test).
    public function withCose(array $cose): self
    {
        $this->cose = $cose;
        return $this;
    }

    // The registration as the controller decodes it: raw clientDataJSON and attestation object, the extension results.
    public function create(string $challenge, string $origin, string $rpId, bool $prfEnabled = true, int $flags = 0x45): array
    {
        $cd = self::clientData('webauthn.create', $challenge, $origin);
        $authData = hash('sha256', $rpId, true).chr($flags).pack('N', $this->signCount)
            .str_repeat("\0", 16).pack('n', strlen($this->rawId)).$this->rawId.WebAuthnVectors::cbor($this->cose);
        return [
            'clientDataJSON' => $cd,
            'attestationObject' => WebAuthnVectors::attObjWith($authData),
            'clientExtensionResults' => $prfEnabled ? ['prf' => ['enabled' => true]] : [],
        ];
    }

    // The assertion as the controller decodes it, with the PRF output for $salt.
    public function get(string $challenge, string $origin, string $rpId, string $salt, int $flags = 0x05): array
    {
        $this->signCount++;
        $cd = self::clientData('webauthn.get', $challenge, $origin);
        $authData = hash('sha256', $rpId, true).chr($flags).pack('N', $this->signCount);
        return [
            'credential_id' => $this->id(),
            'clientDataJSON' => $cd,
            'authenticatorData' => $authData,
            'signature' => $this->sign($authData.hash('sha256', $cd, true)),
            'prf' => $this->prf($salt),
        ];
    }

    public function prf(string $salt): string
    {
        return hash_hmac('sha256', "WebAuthn PRF\0".$salt, $this->prfSecret, true);
    }

    public function sign(string $data): string
    {
        if ($this->alg === -8) {
            return sodium_crypto_sign_detached($data, $this->edSecret);
        }
        openssl_sign($data, $sig, $this->ecPem, OPENSSL_ALGO_SHA256);
        return $sig;
    }

    public static function clientData(string $type, string $challenge, string $origin): string
    {
        return json_encode(['type' => $type, 'challenge' => WebAuthnVectors::b64u($challenge), 'origin' => $origin, 'crossOrigin' => false], JSON_UNESCAPED_SLASHES);
    }
}
