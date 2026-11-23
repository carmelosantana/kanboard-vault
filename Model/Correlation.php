<?php
namespace Kanboard\Plugin\Vault\Model;

// The 128-bit correlation id that ties one request's (or one job's) audit rows together. One per process, made on
// first use; a long-running worker calls begin() at the start of each job.
final class Correlation
{
    public const PATTERN = '/^[0-9a-f]{32}$/D';

    private static ?string $id = null;

    public static function id(): string
    {
        return self::$id ??= bin2hex(random_bytes(16));
    }

    public static function begin(): string
    {
        return self::$id = bin2hex(random_bytes(16));
    }
}
