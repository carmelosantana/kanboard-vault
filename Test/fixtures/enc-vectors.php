<?php
// The PHP side of the one-time share's byte-for-byte contract with the browser (T18). Including this file returns the
// vectors; running it prints them as JSON, which is how Test/fixtures/enc-vectors.json is made:
//
//   php Vault/Test/fixtures/enc-vectors.php > Vault/Test/fixtures/enc-vectors.json
//
// Test/Crypto/EncVectorsTest.php checks the committed JSON still equals this output, and
// Test/js/vault-onetime.test.mjs checks the JS against the JSON. Every value comes from PHP and ext-sodium:
//   enc      Encoding::enc for the share AD and for mixed fields (UTF-8, empty, 0, a large int64).
//   burn     ShareModel::burnHash's BLAKE2b-256 of the 16 raw bytes of b.
//   argon2id libsodium's Argon2id v1.3 with the share's parameters: t = 3, m = 64 MiB, p = 1 (libsodium has one
//            lane), 32 bytes.
//   key      the share key with a passphrase: HKDF-SHA256(k ‖ argon2id, salt = '', info = "vault/share/v1", 32).

use Kanboard\Plugin\Vault\Crypto\Encoding;

require_once __DIR__.'/../../Crypto/Encoding.php';

$vectors = (static function (): array {
    $hex = static fn (string $s): string => bin2hex($s);
    $ad = static fn (string $id, int $exp, int $has): array => [
        'fields' => [['s', 'share'], ['i', 1], ['s', $id], ['i', $exp], ['i', $has]],
        'hex' => $hex(Encoding::enc('share', 1, $id, $exp, $has)),
    ];
    $password = "correct horse battery staple \u{00e9}";
    $salt = hex2bin('000102030405060708090a0b0c0d0e0f');
    $argon = sodium_crypto_pwhash(32, $password, $salt, 3, 64 * 1024 * 1024, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
    $k = hex2bin(str_repeat('a5', 32));
    $burn = 'f0e1d2c3b4a5968778695a4b3c2d1e0f';
    return [
        'share_ad' => [
            $ad('00112233445566778899aabbccddeeff', 1795000000, 0),
            $ad('ffeeddccbbaa99887766554433221100', 1795086400, 1),
        ],
        'enc' => [
            [
                'fields' => [['s', 'share_label'], ['s', "\u{00e9}t\u{00e9} \u{1F511}"], ['s', ''], ['i', 0], ['i', 9007199254740991]],
                'hex' => $hex(Encoding::enc('share_label', "\u{00e9}t\u{00e9} \u{1F511}", '', 0, 9007199254740991)),
            ],
            ['fields' => [], 'hex' => $hex(Encoding::enc())],
        ],
        'burn' => ['b' => $burn, 'burn_hash' => bin2hex(sodium_crypto_generichash(hex2bin($burn), '', 32))],
        'argon2id' => [
            'password' => $password,
            'salt' => $hex($salt),
            't' => 3,
            'm' => 65536,
            'p' => 1,
            'dkLen' => 32,
            'hash' => $hex($argon),
        ],
        'key' => [
            'k' => $hex($k),
            'argon2id' => $hex($argon),
            'key' => $hex(hash_hkdf('sha256', $k.$argon, 32, 'vault/share/v1', '')),
        ],
    ];
})();

// Run directly: print the JSON.
if (PHP_SAPI === 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    echo json_encode($vectors, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
}
return $vectors;
