<?php
namespace Kanboard\Plugin\Vault\Model;

use InvalidArgumentException;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Throwable;

// How a failure reaches the browser (T6 minor, R28, R33). Only a VaultException's fixed code is ever shown; every
// other exception (a CryptoException on a write, an unknown object type, a database error) is the one generic
// 'failed', with no message, class or stack. The status codes follow the spec's throttling rules: a principal's
// second concurrent Argon2 run gets 429, all slots busy gets 503 with Retry-After: 2.
final class VaultFailure
{
    public const RETRY_AFTER = 2;

    // A VaultException code → [HTTP status, the reason the client sees].
    public const MAP = [
        'unlock_failed' => [401, 'unlock_failed'],
        'rate_limited' => [429, 'rate_limited'],
        'busy' => [429, 'rate_limited'],
        'busy_global' => [503, 'busy'],
        'https_required' => [403, 'https_required'],
        'locked' => [401, 'locked'],
        'passphrase_weak' => [422, 'passphrase_weak'],
        'passphrase_reuse' => [422, 'passphrase_reuse'],
        'passphrase_mismatch' => [422, 'passphrase_mismatch'],
        'already_enrolled' => [409, 'already_enrolled'],
        'not_enrolled' => [409, 'not_enrolled'],
        'not_found' => [404, 'not_found'],
        'conflict' => [409, 'conflict'],
        'payload_invalid' => [400, 'payload_invalid'],
        'payload_too_large' => [413, 'payload_too_large'],
        'invalid_move' => [400, 'invalid_move'],
        'integrity_error' => [409, 'integrity_error'],
        'rotation_in_progress' => [409, 'rotation_in_progress'],
        'rotation_needs_factors' => [409, 'rotation_needs_factors'],
        'rotation_incomplete' => [409, 'rotation_incomplete'],
        'policy_forbids' => [403, 'policy_forbids'],
        'agent_read_only' => [422, 'agent_read_only'],
    ];

    /** @return array{0:int,1:string} [status, reason] */
    public static function map(Throwable $e): array
    {
        if ($e instanceof VaultException && isset(self::MAP[$e->errorCode()])) {
            return self::MAP[$e->errorCode()];
        }
        if ($e instanceof VaultException || $e instanceof InvalidArgumentException || $e instanceof CryptoException) {
            return [400, 'failed'];
        }
        return [500, 'failed'];
    }

    // R33: a passphrase ceremony that started has taken effect whether or not its rotation finished, so PENDING is
    // a success ("finishes at next unlock"). A passphrase change drops the personal recovery code (R36): when the
    // policy allows codes, offer_recovery_code asks the UI to offer a new one (the hook T13 builds on).
    /** @return array<string,mixed> */
    public static function rotationResult(string $result, string $policy): array
    {
        $pending = $result === RotationService::PENDING;
        $out = ['ok' => true, 'rotation' => $pending ? 'pending' : 'done'];
        if ($pending) {
            $out['message'] = t('Your passphrase is changed. Re-encrypting your vault finishes at your next unlock.');
        }
        $out['offer_recovery_code'] = $policy !== VaultSettings::POLICY_NONE;
        return $out;
    }
}
