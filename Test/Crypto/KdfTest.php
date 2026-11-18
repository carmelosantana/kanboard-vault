<?php

use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use PHPUnit\Framework\TestCase;

class KdfTest extends TestCase
{
    public function testDefaults(): void
    {
        $this->assertSame(3, Kdf::DEFAULT_OPS);
        $this->assertSame(67108864, Kdf::DEFAULT_MEM);
    }

    // Pins Argon2id (not Argon2i or the libsodium default) and a 32-byte output.
    public function testArgon2idMatchesSodium(): void
    {
        $salt = str_repeat("\x01", 16);
        $out = Kdf::argon2id('correct horse battery', $salt, 1, 8388608);
        $this->assertSame(32, strlen($out));
        $this->assertSame(sodium_crypto_pwhash(32, 'correct horse battery', $salt, 1, 8388608, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13), $out);
        $this->assertNotSame($out, Kdf::argon2id('correct horse battery', str_repeat("\x02", 16), 1, 8388608));
    }

    public function testArgon2idRejectsBadSalt(): void
    {
        $this->expectException(CryptoException::class);
        Kdf::argon2id('pw', 'short', 1, 8388608);
    }

    // Pins the spec: BLAKE2b-256 keyed by the IKM over enc("kek", ...context).
    public function testKekIsKeyedBlake2bOverEncodedContext(): void
    {
        $ikm = random_bytes(32);
        $this->assertSame(
            sodium_crypto_generichash(Encoding::enc('kek', 'prf', 'cred-1', 'prf-out'), $ikm, 32),
            Kdf::kek($ikm, 'prf', 'cred-1', 'prf-out')
        );
        $this->assertSame(
            sodium_crypto_generichash(Encoding::enc('kek', 'agent', 9), $ikm, 32),
            Kdf::kek($ikm, 'agent', 9)
        );
    }

    // Kills dropping or concatenating context fields.
    public function testEveryContextFieldMatters(): void
    {
        $ikm = random_bytes(32);
        $base = Kdf::kek($ikm, 'prf', 'cred-1', 'prf-out');
        $this->assertNotSame($base, Kdf::kek($ikm, 'prf', 'cred-2', 'prf-out'));
        $this->assertNotSame($base, Kdf::kek($ikm, 'prf', 'cred-1', 'prf-ouT'));
        $this->assertNotSame($base, Kdf::kek($ikm, 'prf', 'cred-1prf-out', ''));
        $this->assertNotSame(Kdf::kek($ikm, 'passphrase'), Kdf::kek($ikm, 'recovery'));
        $this->assertNotSame(Kdf::kek($ikm, 'agent', 9), Kdf::kek($ikm, 'agent', 10));
        $this->assertNotSame($base, Kdf::kek(random_bytes(32), 'prf', 'cred-1', 'prf-out'));
    }
}
