<?php

namespace Kanboard\Plugin\Vault\Crypto;

/**
 * A crypto operation failed. Messages are fixed, generic strings: they never carry
 * keys, plaintexts, ciphertexts or any value derived from them.
 */
class CryptoException extends \RuntimeException
{
}
