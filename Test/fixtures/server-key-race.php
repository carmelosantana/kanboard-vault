<?php
// Child for ServerKeyFileTest::testConcurrentCreateKeepsOneKey: create the key file (or keep the one a sibling made)
// and print the bytes read back as hex. ServerKeyFile depends only on PHP and posix, so no autoloader is needed.
require __DIR__.'/../../Model/ServerKeyUnavailable.php';
require __DIR__.'/../../Model/ServerKeyFile.php';

use Kanboard\Plugin\Vault\Model\ServerKeyFile;

$file = new ServerKeyFile($argv[1]);
$file->create();
echo bin2hex($file->read()), "\n";
