<?php

use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Sealer;
use PHPUnit\Framework\TestCase;

class SealerTest extends TestCase
{
    private string $keypair;
    private string $pk;
    private string $dek;

    protected function setUp(): void
    {
        $this->keypair = sodium_crypto_box_keypair();
        $this->pk = sodium_crypto_box_publickey($this->keypair);
        $this->dek = random_bytes(32);
    }

    private function sealed(): string
    {
        return Sealer::sealDek($this->dek, 'entry', 1, 3, 5, $this->pk);
    }

    private function assertRejected(callable $open, string $why): void
    {
        try {
            $open();
            $this->fail($why);
        } catch (CryptoException $e) {
            $this->assertStringNotContainsString(bin2hex($this->dek), $e->getMessage());
        }
    }

    public function testRoundTrip(): void
    {
        $this->assertSame($this->dek, Sealer::openDek($this->sealed(), $this->keypair, 'entry', 1, 3, 5));
    }

    // Pins the sealed plaintext to enc("dek", object_type, object_id, key_epoch, principal_id, DEK).
    public function testPlaintextMatchesSpec(): void
    {
        $this->assertSame(Encoding::enc('dek', 'entry', 1, 3, 5, $this->dek), sodium_crypto_box_seal_open($this->sealed(), $this->keypair));
    }

    // Seal for entry 1, open as entry 2. Kills skipping the field check.
    public function testForeignObjectRejected(): void
    {
        $sealed = $this->sealed();
        $this->assertRejected(fn() => Sealer::openDek($sealed, $this->keypair, 'entry', 2, 3, 5), 'object id not checked');
        $this->assertRejected(fn() => Sealer::openDek($sealed, $this->keypair, 'group', 1, 3, 5), 'object type not checked');
    }

    public function testEpochBound(): void
    {
        $sealed = $this->sealed();
        $this->assertRejected(fn() => Sealer::openDek($sealed, $this->keypair, 'entry', 1, 2, 5), 'older epoch accepted');
        $this->assertRejected(fn() => Sealer::openDek($sealed, $this->keypair, 'entry', 1, 4, 5), 'newer epoch accepted');
    }

    public function testPrincipalBound(): void
    {
        $sealed = $this->sealed();
        $this->assertRejected(fn() => Sealer::openDek($sealed, $this->keypair, 'entry', 1, 3, 6), 'principal not checked');
    }

    public function testWrongKeypairFails(): void
    {
        $sealed = $this->sealed();
        $this->assertRejected(fn() => Sealer::openDek($sealed, sodium_crypto_box_keypair(), 'entry', 1, 3, 5), 'wrong keypair opened');
    }

    // A sealed blob whose DEK is not 32 bytes (forged by anyone holding the pk) is refused.
    public function testWrongDekLengthRejected(): void
    {
        $forged = sodium_crypto_box_seal(Encoding::enc('dek', 'entry', 1, 3, 5, random_bytes(31)), $this->pk);
        $this->assertRejected(fn() => Sealer::openDek($forged, $this->keypair, 'entry', 1, 3, 5), 'short DEK accepted');
        $trailing = sodium_crypto_box_seal(Encoding::enc('dek', 'entry', 1, 3, 5, $this->dek, 'x'), $this->pk);
        $this->assertRejected(fn() => Sealer::openDek($trailing, $this->keypair, 'entry', 1, 3, 5), 'trailing field accepted');
        $this->expectException(CryptoException::class);
        Sealer::sealDek(random_bytes(16), 'entry', 1, 3, 5, $this->pk);
    }
}
