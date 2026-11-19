<?php

use PHPUnit\Framework\TestCase;

// The committed Test/fixtures/enc-vectors.json is what PHP produces today (T18). The JS side checks itself against the
// same file in Test/js/vault-onetime.test.mjs, so PHP and JS agree byte for byte through it.
class EncVectorsTest extends TestCase
{
    // Kills a stale fixture: a change to Encoding::enc, the burn hash or the share KDF that isn't regenerated.
    public function testCommittedFixtureIsWhatPhpProduces(): void
    {
        $dir = __DIR__.'/../fixtures';
        $committed = json_decode((string) file_get_contents($dir.'/enc-vectors.json'), true, 512, JSON_THROW_ON_ERROR);
        $this->assertSame(require $dir.'/enc-vectors.php', $committed);
    }
}
