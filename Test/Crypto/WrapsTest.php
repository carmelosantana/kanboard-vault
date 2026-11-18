<?php

use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use PHPUnit\Framework\TestCase;

class WrapsTest extends TestCase
{
    private const PID = 5;
    private const WRAP_ID = 11;

    private string $keypair;
    private string $sk;
    private string $pk;

    protected function setUp(): void
    {
        $this->keypair = sodium_crypto_box_keypair();
        $this->sk = sodium_crypto_box_secretkey($this->keypair);
        $this->pk = sodium_crypto_box_publickey($this->keypair);
    }

    /** method => [credential_id, KEK] built the way the spec's KEK table says. */
    private function kekPerMethod(): array
    {
        $argon = Kdf::argon2id('a long enough passphrase', random_bytes(16), 1, 8388608);
        $recovery = random_bytes(20);
        $vaultKey = random_bytes(32);
        return [
            'passphrase' => ['', Kdf::kek($argon, 'passphrase')],
            'passphrase+prf' => ['cred-AbC_9', Kdf::kek($argon, 'prf', 'cred-AbC_9', random_bytes(32))],
            'recovery' => ['', Kdf::kek($recovery, 'recovery')],
            'agent' => ['', Kdf::kek($vaultKey, 'agent', self::PID)],
        ];
    }

    public function testRoundTripPerMethod(): void
    {
        foreach ($this->kekPerMethod() as $method => [$cred, $kek]) {
            $row = Wraps::wrap($this->sk, $kek, self::PID, $method, $cred, self::WRAP_ID);
            $this->assertSame(self::WRAP_ID, $row['id'], $method);
            $this->assertSame(self::PID, $row['user_id'], $method);
            $this->assertSame($method, $row['method']);
            $this->assertSame($cred === '' ? null : $cred, $row['credential_id'], $method);
            $this->assertSame(1, $row['crypto_v'], $method);
            $this->assertSame($this->sk, Wraps::unwrap($row, $kek, $this->pk), $method);
        }
    }

    // Pins the AD to the spec table: enc("wrap", crypto_v, principal_id, method, credential_id or "", wrap_id).
    public function testAdMatchesSpec(): void
    {
        $kek = random_bytes(32);
        $row = Wraps::wrap($this->sk, $kek, self::PID, 'passphrase+prf', 'cred-1', self::WRAP_ID);
        $ad = Encoding::enc('wrap', 1, self::PID, 'passphrase+prf', 'cred-1', self::WRAP_ID);
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(base64_decode($row['wrapped_sk']), $ad, base64_decode($row['nonce']), $kek);
        $this->assertSame($this->sk, $plain);
    }

    public function testWrongKekFails(): void
    {
        $row = Wraps::wrap($this->sk, random_bytes(32), self::PID, 'passphrase', '', self::WRAP_ID);
        $this->expectException(CryptoException::class);
        Wraps::unwrap($row, random_bytes(32), $this->pk);
    }

    // Unwrap succeeds cryptographically but the stored pk differs. Kills a missing pk check.
    public function testPublicKeyMismatchFails(): void
    {
        $kek = random_bytes(32);
        $row = Wraps::wrap($this->sk, $kek, self::PID, 'passphrase', '', self::WRAP_ID);
        $otherPk = sodium_crypto_box_publickey(sodium_crypto_box_keypair());
        try {
            Wraps::unwrap($row, $kek, $otherPk);
            $this->fail('pk mismatch accepted');
        } catch (CryptoException $e) {
            foreach ([$this->sk, $kek, bin2hex($this->sk), base64_encode($this->sk), bin2hex($kek)] as $secret) {
                $this->assertStringNotContainsString($secret, $e->getMessage());
            }
        }
    }

    // Kills dropping any one AD field: moving the row to another principal, method, credential or id fails.
    public function testRowFieldsAreBound(): void
    {
        $kek = random_bytes(32);
        $row = Wraps::wrap($this->sk, $kek, self::PID, 'passphrase+prf', 'cred-1', self::WRAP_ID);
        foreach (['user_id' => self::PID + 1, 'id' => self::WRAP_ID + 1, 'credential_id' => 'cred-2', 'method' => 'passphrase'] as $field => $value) {
            $moved = array_replace($row, [$field => $value]);
            if ($field === 'method') {
                $moved['credential_id'] = null;
            }
            try {
                Wraps::unwrap($moved, $kek, $this->pk);
                $this->fail("$field is not bound");
            } catch (CryptoException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testUnknownCryptoVersionRefused(): void
    {
        $kek = random_bytes(32);
        $row = Wraps::wrap($this->sk, $kek, self::PID, 'passphrase', '', self::WRAP_ID);
        $row['crypto_v'] = 2;
        $this->expectException(CryptoException::class);
        Wraps::unwrap($row, $kek, $this->pk);
    }

    // credential_id belongs to passphrase+prf and only to it; org is a sealed box, not an AEAD wrap.
    public function testMethodAndCredentialAreValidated(): void
    {
        foreach ([['passphrase+prf', ''], ['passphrase', 'cred-1'], ['org', ''], ['bogus', '']] as [$method, $cred]) {
            try {
                Wraps::wrap($this->sk, random_bytes(32), self::PID, $method, $cred, self::WRAP_ID);
                $this->fail("accepted $method/$cred");
            } catch (CryptoException $e) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testOrgRoundTrip(): void
    {
        $org = sodium_crypto_box_keypair();
        $sealed = Wraps::sealOrg($this->sk, self::PID, sodium_crypto_box_publickey($org));
        $this->assertSame($this->sk, Wraps::openOrg($sealed, $org, self::PID, $this->pk));
    }

    // Pins the sealed plaintext to enc("orgwrap", principal_id, sk).
    public function testOrgPlaintextMatchesSpec(): void
    {
        $org = sodium_crypto_box_keypair();
        $sealed = Wraps::sealOrg($this->sk, self::PID, sodium_crypto_box_publickey($org));
        $this->assertSame(Encoding::enc('orgwrap', self::PID, $this->sk), sodium_crypto_box_seal_open($sealed, $org));
    }

    // Kills skipping the principal check: user 5's org wrap cannot restore user 6.
    public function testOrgForeignPrincipalRejected(): void
    {
        $org = sodium_crypto_box_keypair();
        $sealed = Wraps::sealOrg($this->sk, self::PID, sodium_crypto_box_publickey($org));
        $this->expectException(CryptoException::class);
        Wraps::openOrg($sealed, $org, self::PID + 1, $this->pk);
    }

    public function testOrgPublicKeyMismatchFails(): void
    {
        $org = sodium_crypto_box_keypair();
        $sealed = Wraps::sealOrg($this->sk, self::PID, sodium_crypto_box_publickey($org));
        $this->expectException(CryptoException::class);
        Wraps::openOrg($sealed, $org, self::PID, sodium_crypto_box_publickey(sodium_crypto_box_keypair()));
    }

    public function testOrgWrongKeypairFails(): void
    {
        $sealed = Wraps::sealOrg($this->sk, self::PID, sodium_crypto_box_publickey(sodium_crypto_box_keypair()));
        $this->expectException(CryptoException::class);
        Wraps::openOrg($sealed, sodium_crypto_box_keypair(), self::PID, $this->pk);
    }
}
