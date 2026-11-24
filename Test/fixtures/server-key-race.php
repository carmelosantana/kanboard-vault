<?php
// Child for ServerKeyFileTest. With no mode: create the key file (or keep the one a sibling made) and print the bytes
// read back as hex (testConcurrentCreateKeepsOneKey). With `read`: print the hex, or the failure message
// (testReadWalksBeforeTheLock). ServerKeyFile depends only on PHP and posix, so no autoloader is needed.
require __DIR__.'/../../Model/ServerKeyUnavailable.php';
require __DIR__.'/../../Model/ServerKeyFile.php';

use Kanboard\Plugin\Vault\Model\ServerKeyFile;
use Kanboard\Plugin\Vault\Model\ServerKeyUnavailable;

$file = new ServerKeyFile($argv[1]);
if (($argv[2] ?? '') === 'read') {
    try {
        echo bin2hex($file->read()), "\n";
    } catch (ServerKeyUnavailable $e) {
        echo $e->getMessage(), "\n";
    }
    exit(0);
}
$file->create();
echo bin2hex($file->read()), "\n";
