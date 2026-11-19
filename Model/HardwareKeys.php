<?php
namespace Kanboard\Plugin\Vault\Model;

use Closure;
use InvalidArgumentException;
use Kanboard\Core\Base;
use Kanboard\Plugin\Vault\Crypto\CryptoException;
use Kanboard\Plugin\Vault\Crypto\Encoding;
use Kanboard\Plugin\Vault\Crypto\Kdf;
use Kanboard\Plugin\Vault\Crypto\Wraps;
use Kanboard\Plugin\Vault\WebAuthn\Verifier;
use Kanboard\Plugin\Vault\WebAuthn\WebAuthnException;
use SodiumException;
use Throwable;
use ValueError;

// Hardware keys, WebAuthn with the PRF extension (spec: Hardware keys, Key rotation, Throttling). The verifier
// (WebAuthn/Verifier, T19) checks the bytes; this class owns everything around it:
//
//   challenges   32 random bytes, stored as a hash in vault_challenges bound to the user and a purpose (register,
//                ceremony, unlock), valid for CHALLENGE_TTL seconds and consumed by the one DELETE that finds them.
//                The challenge a client answered is read from its clientDataJSON, consumed, then handed to the
//                verifier, which compares it strictly. A failed verification still consumes it (the DELETE commits
//                on its own), so nothing is ever verified twice against one challenge.
//   binding      rpBinding(): the normalised origin and rp_id from Kanboard's Application URL (https, or the
//                opted-in http://localhost dev stack, R20), refused when the browser's Host isn't that host. Each
//                credential pins the binding it registered under; a different binding later is rp_id_mismatch.
//   credentials  vault_webauthn rows: credential_id (base64url of the id in authData, never the client's rawId), the
//                COSE key (base64), sign_count, prf_salt (base64, derived from the server's own registration
//                challenge: prfSaltFor), the label and the binding. An assertion is checked against the row that
//                has the presented id AND belongs to the user.
//   wraps        one passphrase+prf wrap per key: KEK = BLAKE2b(key = Argon2id(passphrase, the wrap's own salt),
//                msg = enc("kek", "prf", raw credential id, PRF output)); the wrap's AD carries the base64url id.
//
// Every ceremony that proves the passphrase runs in the principal's Argon2 slot, after its back-off and the per-IP
// bucket (R15, the unlock buckets). A wrong passphrase is a failed guess (unlock_failed, the streak); a right one
// resets both. Failed assertions are hw_key_invalid (no guess: the challenge is the logged-in user's and an assertion
// has nothing to guess). Writes run under the exclusive lock through VaultDb (R13); a wrap row is inserted first and
// sealed with its own id (R10). Ceremonies:
//
//   registerKey  the first key adds a wrap of the current key; the second deletes the bare passphrase wrap and
//                rotates with every key's factor (R30); later ones add a wrap. Each key presents a fresh assertion.
//   removeKey    another key's fresh assertion; never below two while keys are required; dropping to one restores
//                a passphrase wrap after the passphrase is proved with the remaining key; the last key goes with the
//                passphrase alone.
//   rotate       Rotate my keys (and a passphrase change) for key users: every key presents an assertion, each gets
//                a new wrap of sk2, plus the passphrase wrap while only one key exists. Runs a queued rotation too.
//   confirm      R54: a fresh assertion plus the passphrase before a recovery code is made.
//
// After a rotation's start commits the change has happened: the rest runs outside the slot, bounded, and is never
// reported as a failure (R33). Callers wipe their own copies (R12); this class wipes its own.
class HardwareKeys extends Base
{
    public const CHALLENGE_TTL = 120;
    public const PURPOSES = ['register', 'ceremony', 'unlock'];
    public const MAX_KEYS = 10;
    public const REQUIRED_KEYS = 2;
    private const OPEN_CHALLENGES = self::MAX_KEYS + 2;
    private const LABEL_CHARS = 64;
    private const PRF_BYTES = 32;
    private const CREDENTIAL_ID_BYTES = 1023;

    private ArgonSlots $slots;
    private Closure $argon2;
    private Closure $clock;
    private ?RotationService $rotation;
    private ?FailedGuess $guess = null;
    private int $streak = 0;

    public function __construct($container, ?ArgonSlots $slots = null, ?callable $argon2 = null, ?callable $clock = null, ?RotationService $rotation = null)
    {
        parent::__construct($container);
        $this->slots = $slots ?? new ArgonSlots($container);
        $this->argon2 = Closure::fromCallable($argon2 ?? [Kdf::class, 'argon2id']);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
        $this->rotation = $rotation;
    }

    // A new single-use challenge (raw 32 bytes) for the user and purpose, valid for CHALLENGE_TTL seconds. Refused
    // without a relying party, so no ceremony starts that can't finish.
    public function challenge(int $userId, string $purpose): string
    {
        if ($userId <= 0 || ! in_array($purpose, self::PURPOSES, true)) {
            throw new InvalidArgumentException('Vault: unknown challenge purpose');
        }
        $this->rpBinding();
        $challenge = random_bytes(32);
        $now = $this->now();
        $this->lock()->exclusive(function () use ($userId, $purpose, $challenge, $now): void {
            $db = $this->vdb();
            $db->execute('DELETE FROM vault_challenges WHERE user_id = ? AND expires_at <= ?', [$userId, $now]);
            // At most OPEN_CHALLENGES open per user and purpose (a rotation needs one per key at once).
            $open = array_column($db->fetchAll('SELECT id FROM vault_challenges WHERE user_id = ? AND purpose = ? ORDER BY id DESC', [$userId, $purpose]), 'id');
            foreach (array_slice($open, self::OPEN_CHALLENGES - 1) as $id) {
                $db->execute('DELETE FROM vault_challenges WHERE id = ?', [(int) $id]);
            }
            $db->insert('vault_challenges', [
                'user_id' => $userId,
                'purpose' => $purpose,
                'challenge_hash' => self::challengeHash($challenge),
                'expires_at' => $now + self::CHALLENGE_TTL,
            ]);
        });
        return $challenge;
    }

    // A new key's PRF salt: derived from the server's registration challenge, so the server chose it and needs to
    // keep nothing between the challenge and the registration. Not secret (the PRF output is).
    public static function prfSaltFor(string $registerChallenge): string
    {
        return sodium_crypto_generichash(Encoding::enc('prf_salt', $registerChallenge), '', 32);
    }

    // Spec: the relying party is Kanboard's Application URL, a non-empty https:// URL or the opted-in http://localhost
    // dev stack (R20): application_url_required otherwise. A request whose Host isn't that host can't finish a
    // ceremony (the browser binds the rp_id to its own address): rp_id_mismatch, said plainly.
    /** @return array{origin:string, rp_id:string} */
    public function rpBinding(): array
    {
        $session = isset($this->container['vaultSession']) ? $this->container['vaultSession'] : new VaultSession($this->container);
        $rp = VaultSettings::relyingParty((string) $this->configModel->get('application_url'), $session->devLocalhost());
        if ($rp === null) {
            throw new VaultException('application_url_required');
        }
        $host = strtolower((string) preg_replace('/:\d+$/D', '', $this->request->getServerVariable('HTTP_HOST')));
        if ($host !== $rp['rp_id']) {
            throw new VaultException('rp_id_mismatch');
        }
        return $rp;
    }

    // The user's keys, oldest first: base64url credential id, label, prf_salt (base64), times. No secret.
    /** @return list<array{credential_id:string,label:string,prf_salt:string,created_at:int,last_used_at:?int}> */
    public function keys(int $userId): array
    {
        return array_map(static fn (array $r): array => [
            'credential_id' => (string) $r['credential_id'],
            'label' => (string) $r['label'],
            'prf_salt' => (string) $r['prf_salt'],
            'created_at' => (int) $r['created_at'],
            'last_used_at' => $r['last_used_at'] === null ? null : (int) $r['last_used_at'],
        ], $this->vdb()->fetchAll('SELECT credential_id, label, prf_salt, created_at, last_used_at FROM vault_webauthn WHERE user_id = ? ORDER BY id', [$userId]));
    }

    public function count(int $userId): int
    {
        $r = $this->vdb()->fetchOne('SELECT COUNT(*) AS n FROM vault_webauthn WHERE user_id = ?', [$userId]);
        return (int) ($r['n'] ?? 0);
    }

    // A rotation queued for a key user (a lowered policy, T9): only the ceremony with every key can run it (R30), so
    // the page asks for it.
    public function rotationQueued(int $userId): bool
    {
        $p = $this->vdb()->fetchOne('SELECT rotate_requested FROM vault_principals WHERE user_id = ?', [$userId]);
        return $p !== null && (int) $p['rotate_requested'] === 1 && $this->count($userId) > 0;
    }

    // Spec: when an admin requires hardware keys, an enrolled human with fewer than two is sent to enrolment and can't
    // view entries until they finish.
    public function enrolmentRequired(int $userId): bool
    {
        if ((int) (new VaultSettings($this->container))->get('vault_hw_required') !== 1) {
            return false;
        }
        $p = $this->vdb()->fetchOne('SELECT kind FROM vault_principals WHERE user_id = ?', [$userId]);
        if ($p === null || $p['kind'] !== 'human' || AgentRoster::of($this->container)->isAgent($userId)) {
            return false;
        }
        return $this->count($userId) < self::REQUIRED_KEYS;
    }

    // Verifies an assertion for $purpose in its own exclusive transaction (the challenge's consumption and a
    // signCount regression's hw_signcount audit commit whatever the outcome). Returns the credential row, its raw id
    // and the PRF output. hw_key_invalid for any failure; rp_id_mismatch when the key is pinned to another binding.
    /** @return array{row:array,raw_id:string,prf:string} */
    public function verifyAssertion(int $userId, string $purpose, #[\SensitiveParameter] array $assertion, string $ip = ''): array
    {
        $rp = $this->rpBinding();
        $a = self::assertionShape($assertion);
        $out = $this->lock()->exclusive(fn (): array => $this->checkAssertion($this->vdb(), $userId, $purpose, $a, $rp, $ip));
        self::raise($out);
        return ['row' => $out['row'], 'raw_id' => $out['raw_id'], 'prf' => $a['prf']];
    }

    // Spec: Enrolment, two keys required. $response: {label, create: {clientDataJSON, attestationObject,
    // clientExtensionResults}, assert: the new key's assertion (its PRF for the salt prfSaltFor gives), others: a fresh
    // assertion from each key the user already has}. The passphrase must be the current one; $sk the session's key.
    public function registerKey(int $userId, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] array $response, #[\SensitiveParameter] string $passphrase, string $ip = ''): void
    {
        $rp = $this->rpBinding();
        $label = self::label($response['label'] ?? '');
        $create = self::registrationShape($response['create'] ?? null);
        $assert = self::assertionShape($response['assert'] ?? null);
        $others = self::assertionList($response['others'] ?? []);
        $sk2 = '';
        $kek = '';
        $factors = [];
        try {
            $this->inSlot($userId, $ip, function (RateLimiter $limiter) use ($userId, $sk, $rp, $label, $create, $assert, $others, $passphrase, $ip, &$sk2, &$kek, &$factors): void {
                $v = $this->lock()->exclusive(function () use ($userId, $sk, $rp, $create, $assert, $others, $ip): array {
                    $db = $this->vdb();
                    $p = $this->principal($db, $userId, $sk);
                    $n = $this->countIn($db, $userId);
                    if ($n >= self::MAX_KEYS) {
                        throw new VaultException('hw_key_limit');
                    }
                    $reg = $this->checkRegistration($db, $userId, $create, $rp);
                    if ($reg['status'] !== 'ok') {
                        return $reg;
                    }
                    $new = $this->checkAssertion($db, $userId, 'ceremony', $assert, $rp, $ip, $reg['cred']);
                    if ($new['status'] !== 'ok') {
                        return $new;
                    }
                    $checked = $this->checkAll($db, $userId, $others, $rp, $ip);
                    if ($checked['status'] !== 'ok') {
                        return $checked;
                    }
                    // Every existing key takes part once the second key rotates (R30); later ones need one to prove the
                    // passphrase with.
                    if (($n === 1 && count($checked['keys']) !== 1) || ($n > 1 && $checked['keys'] === [])) {
                        return ['status' => 'needs_factors'];
                    }
                    return ['status' => 'ok', 'n' => $n, 'ids' => $this->idsIn($db, $userId), 'p' => $p, 'reg' => $reg, 'new_count' => $new['count'], 'new_prf' => $assert['prf'], 'others' => $checked['keys']];
                });
                self::raise($v);
                $n = $v['n'];
                $ids = $v['ids'];
                $p = $v['p'];
                $rawId = $v['reg']['cred']['credential_id'];
                $credId = self::b64u($rawId);
                // Prove the passphrase: the bare passphrase wrap for the first key; else with an existing key's own
                // wrap, which proves that key's PRF output too (review I1: the second key's rotation deletes the bare
                // wrap and re-wraps under the first key's PRF, so a wrong one must be refused before anything changes).
                if ($v['others'] === []) {
                    $this->proveFactor($userId, $ip, $limiter, $this->wrapOf($userId, 'passphrase', '', $p['key_gen']), $passphrase, ['passphrase'], $sk, $p['public_key']);
                } else {
                    $this->proveKey($userId, $ip, $limiter, $v['others'][0], $passphrase, $sk, $p);
                }
                $row = [
                    'user_id' => $userId,
                    'credential_id' => $credId,
                    'cose_public_key' => base64_encode($v['reg']['cred']['cose_public_key']),
                    'sign_count' => $v['new_count'],
                    'prf_salt' => base64_encode($v['reg']['prf_salt']),
                    'label' => $label,
                    'origin' => $rp['origin'],
                    'rp_id' => $rp['rp_id'],
                    'created_at' => $this->now(),
                    'last_used_at' => $this->now(),
                ];
                if ($n === 1) {
                    // Spec / R30: the second key deletes the bare passphrase wrap (start deletes every old wrap) and
                    // rotates; the surviving factors are both keys, each with the passphrase.
                    $factors[] = $this->prfFactor($passphrase, $v['others'][0]['credential_id'], $v['others'][0]['raw_id'], $v['others'][0]['prf']);
                    $factors[] = $this->prfFactor($passphrase, $credId, $rawId, $v['new_prf']);
                    $sk2 = $this->lock()->exclusive(function () use ($userId, $sk, $p, $ids, $row, $factors): string {
                        $db = $this->vdb();
                        $this->recheck($db, $userId, $sk, $p['key_gen'], $ids, $row['credential_id']);
                        $db->insert('vault_webauthn', $row);
                        AuditModel::of($this->container, $this->clock)->record('hw_key_add', ['actor_user_id' => $userId]);
                        return $this->rotation()->start($userId, $sk, $factors);
                    });
                    return;
                }
                $kek = $this->prfFactor($passphrase, $credId, $rawId, $v['new_prf']);
                $this->lock()->exclusive(function () use ($userId, $sk, $p, $ids, $row, $kek, $credId): void {
                    $db = $this->vdb();
                    $this->recheck($db, $userId, $sk, $p['key_gen'], $ids, $credId);
                    $db->insert('vault_webauthn', $row);
                    $this->insertWrap($db, $userId, $sk, $kek, $p['key_gen']);
                    AuditModel::of($this->container, $this->clock)->record('hw_key_add', ['actor_user_id' => $userId]);
                });
            });
        } catch (Throwable $e) {
            sodium_memzero($sk2);
            throw $e;
        } finally {
            self::wipeFactors($factors);
            if (is_array($kek)) {
                sodium_memzero($kek['kek']);
            }
        }
        if ($sk2 !== '') {
            try {
                // R33: the change has happened; the rest of the rotation is contained and bounded.
                $this->rotation()->advanceContained($userId, $sk, $sk2);
            } finally {
                sodium_memzero($sk2);
            }
        }
    }

    // Spec: Removing a key. $otherKeyAssertion: a fresh 'ceremony' assertion by another of the user's keys (not needed
    // for the last key). Dropping to one key restores a passphrase wrap, so it needs $sk and the passphrase, proved
    // with the remaining key; removing the last key needs them too, proved with the passphrase wrap.
    public function removeKey(int $userId, string $credentialId, #[\SensitiveParameter] array $otherKeyAssertion, #[\SensitiveParameter] ?string $sk = null, #[\SensitiveParameter] ?string $passphrase = null, string $ip = ''): void
    {
        $rp = $this->rpBinding();
        $db = $this->vdb();
        $keys = array_column($this->keys($userId), 'credential_id');
        sort($keys);
        $n = count($keys);
        if (! in_array($credentialId, $keys, true)) {
            throw new VaultException('not_found');
        }
        if ((int) (new VaultSettings($this->container))->get('vault_hw_required') === 1 && $n - 1 < self::REQUIRED_KEYS) {
            throw new VaultException('hw_keys_required');
        }
        $other = null;
        if ($n > 1) {
            $a = self::assertionShape($otherKeyAssertion);
            if (hash_equals($credentialId, $a['credential_id'])) {
                throw new VaultException('hw_key_invalid');
            }
            $out = $this->lock()->exclusive(fn (): array => $this->checkAssertion($this->vdb(), $userId, 'ceremony', $a, $rp, $ip));
            self::raise($out);
            $other = ['credential_id' => $a['credential_id'], 'raw_id' => $out['raw_id'], 'prf' => $a['prf']];
        }
        if ($n - 1 >= self::REQUIRED_KEYS) {
            $this->lock()->exclusive(function () use ($userId, $credentialId, $keys): void {
                $db = $this->vdb();
                $this->requireState($db, $userId, $keys);
                $this->deleteKey($db, $userId, $credentialId);
            });
            return;
        }
        if ($sk === null || $passphrase === null) {
            throw new VaultException('unlock_failed');
        }
        $kek = '';
        try {
            $this->inSlot($userId, $ip, function (RateLimiter $limiter) use ($userId, $credentialId, $sk, $passphrase, $ip, $keys, $other, &$kek): void {
                $p = $this->lock()->shared(fn (): array => $this->principal($this->vdb(), $userId, $sk));
                if ($other !== null) {
                    // One key stays: prove the passphrase with it, then give the passphrase its own wrap back.
                    $this->proveKey($userId, $ip, $limiter, $other, $passphrase, $sk, $p);
                    $kek = $this->passphraseFactor($passphrase);
                } else {
                    $this->proveFactor($userId, $ip, $limiter, $this->wrapOf($userId, 'passphrase', '', $p['key_gen']), $passphrase, ['passphrase'], $sk, $p['public_key']);
                }
                $this->lock()->exclusive(function () use ($userId, $credentialId, $sk, $p, $keys, $kek): void {
                    $db = $this->vdb();
                    $this->recheck($db, $userId, $sk, $p['key_gen'], $keys, null);
                    if (is_array($kek) && $this->wrapIn($db, $userId, 'passphrase', '', $p['key_gen']) === null) {
                        $this->insertWrap($db, $userId, $sk, $kek, $p['key_gen']);
                    }
                    $this->deleteKey($db, $userId, $credentialId);
                });
            });
        } finally {
            if (is_array($kek)) {
                sodium_memzero($kek['kek']);
            }
        }
    }

    // Rotate my keys for a key user, optionally with a new passphrase ('' keeps it): every key presents a fresh
    // 'ceremony' assertion (rotation_needs_factors otherwise: a key isn't dropped silently), the current passphrase is
    // proved, and the rotation starts with a new wrap per key (plus the passphrase wrap while only one key exists).
    // A queued rotation (a lowered policy) is satisfied by it. Returns ROTATED or PENDING (R33).
    public function rotate(int $userId, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] string $passphrase, #[\SensitiveParameter] string $newPassphrase, #[\SensitiveParameter] array $assertions, string $ip = ''): string
    {
        $rp = $this->rpBinding();
        $list = self::assertionList($assertions);
        $sk2 = '';
        $factors = [];
        try {
            $this->inSlot($userId, $ip, function (RateLimiter $limiter) use ($userId, $sk, $passphrase, $newPassphrase, $list, $rp, $ip, &$sk2, &$factors): void {
                $v = $this->lock()->exclusive(function () use ($userId, $sk, $list, $rp, $ip): array {
                    $db = $this->vdb();
                    $p = $this->principal($db, $userId, $sk);
                    $all = array_column($db->fetchAll('SELECT credential_id FROM vault_webauthn WHERE user_id = ?', [$userId]), 'credential_id');
                    $checked = $this->checkAll($db, $userId, $list, $rp, $ip);
                    if ($checked['status'] !== 'ok') {
                        return $checked;
                    }
                    $presented = array_column($checked['keys'], 'credential_id');
                    sort($presented);
                    sort($all);
                    if ($all === [] || $presented !== $all) {
                        return ['status' => 'needs_factors'];
                    }
                    return ['status' => 'ok', 'p' => $p, 'ids' => $all, 'keys' => $checked['keys']];
                });
                self::raise($v);
                $p = $v['p'];
                // Review I1: start() replaces every wrap, so each key's PRF output is proved against that key's own
                // wrap first (each proof also proves the passphrase). A wrong one refuses before anything changes.
                foreach ($v['keys'] as $k) {
                    $this->proveKey($userId, $ip, $limiter, $k, $passphrase, $sk, $p);
                }
                $next = $newPassphrase === '' ? $passphrase : $newPassphrase;
                if ($newPassphrase !== '') {
                    (new PrincipalModel($this->container, $this->slots, $this->argon2, $this->clock))->validateNewPassphrase($userId, $newPassphrase);
                }
                foreach ($v['keys'] as $k) {
                    $factors[] = $this->prfFactor($next, $k['credential_id'], $k['raw_id'], $k['prf']);
                }
                if (count($v['keys']) < self::REQUIRED_KEYS) {
                    $factors[] = $this->passphraseFactor($next);
                }
                $sk2 = $this->lock()->exclusive(function () use ($userId, $sk, $p, $v, $factors): string {
                    $this->recheck($this->vdb(), $userId, $sk, $p['key_gen'], $v['ids'], null);
                    return $this->rotation()->start($userId, $sk, $factors);
                });
            });
        } catch (Throwable $e) {
            sodium_memzero($sk2);
            throw $e;
        } finally {
            self::wipeFactors($factors);
        }
        try {
            return $this->rotation()->advanceContained($userId, $sk, $sk2);
        } finally {
            sodium_memzero($sk2);
        }
    }

    // R54: before an unlocked session mints a lasting factor (a recovery code), a user with keys presents a fresh
    // 'ceremony' assertion and the passphrase, which together must open that key's wrap to exactly $sk. Throttled
    // as the passphrase check is.
    public function confirm(int $userId, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] string $passphrase, #[\SensitiveParameter] array $assertion, string $ip = ''): void
    {
        $rp = $this->rpBinding();
        $a = self::assertionShape($assertion);
        $this->inSlot($userId, $ip, function (RateLimiter $limiter) use ($userId, $sk, $passphrase, $a, $rp, $ip): void {
            $v = $this->lock()->exclusive(function () use ($userId, $sk, $a, $rp, $ip): array {
                $db = $this->vdb();
                $p = $this->principal($db, $userId, $sk);
                $out = $this->checkAssertion($db, $userId, 'ceremony', $a, $rp, $ip);
                return $out + ['p' => $p];
            });
            self::raise($v);
            $p = $v['p'];
            $this->proveFactor($userId, $ip, $limiter, $this->wrapOf($userId, 'passphrase+prf', $a['credential_id'], $p['key_gen']), $passphrase, ['prf', $v['raw_id'], $a['prf']], $sk, $p['public_key']);
        });
    }

    // ── Wire shapes ──────────────────────────────────────────────────────────────────────────────────────────────
    // The browser posts JSON with every binary field base64url. These decode it strictly: payload_invalid otherwise.

    /** @return array{credential_id:string,clientDataJSON:string,authenticatorData:string,signature:string,prf:string} */
    public static function parseAssertion(mixed $json): array
    {
        $a = is_string($json) ? self::json($json) : $json;
        if (! is_array($a)) {
            throw new VaultException('payload_invalid');
        }
        $out = ['credential_id' => is_string($a['credential_id'] ?? null) ? $a['credential_id'] : ''];
        foreach (['clientDataJSON', 'authenticatorData', 'signature', 'prf'] as $k) {
            $out[$k] = self::unb64u($a[$k] ?? null);
        }
        return self::assertionShape($out);
    }

    /** @return list<array> */
    public static function parseAssertions(mixed $json): array
    {
        $list = is_string($json) ? ($json === '' ? [] : self::json($json)) : $json;
        if (! is_array($list) || ! array_is_list($list) || count($list) > self::MAX_KEYS) {
            throw new VaultException('payload_invalid');
        }
        return array_map([self::class, 'parseAssertion'], $list);
    }

    /** @return array{clientDataJSON:string,attestationObject:string,clientExtensionResults:array} */
    public static function parseRegistration(mixed $json): array
    {
        $r = is_string($json) ? self::json($json) : $json;
        if (! is_array($r) || ! is_array($r['clientExtensionResults'] ?? null)) {
            throw new VaultException('payload_invalid');
        }
        return self::registrationShape([
            'clientDataJSON' => self::unb64u($r['clientDataJSON'] ?? null),
            'attestationObject' => self::unb64u($r['attestationObject'] ?? null),
            'clientExtensionResults' => $r['clientExtensionResults'],
        ]);
    }

    public static function b64u(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    // ── Internals ────────────────────────────────────────────────────────────────────────────────────────────────

    // R15 order, as at unlock: the principal's Argon2 slot, its back-off, the per-IP bucket, then $work($limiter). A
    // failed guess recorded by proveFactor is emailed (when due) once the slot is free (R39).
    private function inSlot(int $userId, string $ip, callable $work): void
    {
        if ($userId <= 0) {
            throw new VaultException('unlock_failed');
        }
        $slot = $this->slots->acquire($userId);
        if ($slot === null) {
            throw new VaultException($this->slots->lastBusy() === ArgonSlots::BUSY_GLOBAL ? 'busy_global' : 'busy');
        }
        $limiter = new RateLimiter($this->container, null, $this->clock);
        $this->guess = null;
        $this->streak = 0;
        try {
            if ($limiter->backoffSeconds(UnlockService::userBucket($userId)) > 0) {
                (new RateLimitAudit($this->container, $this->clock))->note($userId, $ip);
                throw new VaultException('rate_limited');
            }
            if (! $limiter->consume(UnlockService::ipBucket($ip), UnlockService::IP_FAILURES, UnlockService::IP_FAILURES / UnlockService::IP_WINDOW)) {
                (new RateLimitAudit($this->container, $this->clock))->note(null, $ip);
                throw new VaultException('rate_limited');
            }
            $work($limiter);
        } finally {
            $slot->release();
            $this->guess?->notifyIfDue($userId, $this->streak);
        }
    }

    // The passphrase (with a key's PRF output for a prf wrap: $context) must open $wrap to exactly $sk. A wrong one is
    // a failed guess (unlock_failed); a missing wrap costs the same Argon2. A right one resets the back-off and streak
    // and gives the IP token back.
    private function proveFactor(int $userId, string $ip, RateLimiter $limiter, ?array $wrap, #[\SensitiveParameter] string $passphrase, #[\SensitiveParameter] array $context, #[\SensitiveParameter] string $sk, string $pk): void
    {
        $ikm = $kek = $opened = '';
        try {
            $salt = $wrap === null ? false : base64_decode((string) $wrap['kdf_salt'], true);
            if ($passphrase === '' || $salt === false || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
                if ($passphrase !== '') {
                    ($this->argon2)($passphrase, random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES), Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM);
                }
            } else {
                try {
                    $ikm = ($this->argon2)($passphrase, $salt, (int) $wrap['kdf_ops'], (int) $wrap['kdf_mem']);
                    $kek = Kdf::kek($ikm, ...$context);
                    $opened = Wraps::unwrap(self::wrapRow($wrap), $kek, $pk);
                } catch (CryptoException) {
                    $opened = '';
                }
            }
            if ($opened === '' || ! hash_equals($opened, $sk)) {
                $this->guess = new FailedGuess($this->container, $limiter, $this->clock);
                $this->streak = $this->guess->record($userId, UnlockService::userBucket($userId), $ip);
                throw new VaultException('unlock_failed');
            }
            $this->lock()->exclusive(function () use ($limiter, $userId): void {
                $limiter->recordSuccess(UnlockService::userBucket($userId));
                FailedGuess::resetStreak($this->vdb(), $userId);
            });
            $limiter->refund(UnlockService::ipBucket($ip), UnlockService::IP_FAILURES, UnlockService::IP_FAILURES / UnlockService::IP_WINDOW);
        } finally {
            sodium_memzero($ikm);
            sodium_memzero($kek);
            sodium_memzero($opened);
        }
    }

    // Inside an exclusive transaction: the registration's challenge is consumed and the attestation verified. The new
    // credential id (from authData) must be unused by anyone.
    private function checkRegistration(VaultDb $db, int $userId, array $create, array $rp): array
    {
        $challenge = $this->consume($db, $userId, 'register', $create['clientDataJSON']);
        if ($challenge === null) {
            return ['status' => 'invalid'];
        }
        try {
            $cred = Verifier::register(['clientDataJSON' => $create['clientDataJSON'], 'clientExtensionResults' => $create['clientExtensionResults']], $create['attestationObject'], $challenge, $rp['origin'], $rp['rp_id']);
        } catch (WebAuthnException) {
            return ['status' => 'invalid'];
        }
        if ($db->fetchOne('SELECT id FROM vault_webauthn WHERE credential_id = ?', [self::b64u($cred['credential_id'])]) !== null) {
            return ['status' => 'invalid'];
        }
        return ['status' => 'ok', 'cred' => $cred, 'sign_count' => $cred['sign_count'], 'prf_salt' => self::prfSaltFor($challenge)];
    }

    // Inside an exclusive transaction: consumes the assertion's challenge for $purpose, then verifies it against $cred
    // (a credential just registered, in memory) or the user's own stored credential with that id, whose stored
    // signCount then advances. A regression is audited hw_signcount here, so the row commits with the consumption.
    private function checkAssertion(VaultDb $db, int $userId, string $purpose, array $a, array $rp, string $ip, ?array $cred = null): array
    {
        $challenge = $this->consume($db, $userId, $purpose, $a['clientDataJSON']);
        if ($challenge === null || strlen($a['prf']) !== self::PRF_BYTES) {
            return ['status' => 'invalid'];
        }
        $row = null;
        if ($cred !== null) {
            if (! hash_equals(self::b64u($cred['credential_id']), $a['credential_id'])) {
                return ['status' => 'invalid'];
            }
            $stored = ['cose_public_key' => $cred['cose_public_key'], 'sign_count' => $cred['sign_count'], 'origin' => $cred['origin'], 'rp_id' => $cred['rp_id']];
            $rawId = $cred['credential_id'];
        } else {
            $row = $db->fetchOne('SELECT * FROM vault_webauthn WHERE user_id = ? AND credential_id = ?', [$userId, $a['credential_id']]);
            if ($row === null) {
                return ['status' => 'invalid'];
            }
            if ($row['origin'] !== $rp['origin'] || $row['rp_id'] !== $rp['rp_id']) {
                return ['status' => 'rp_id_mismatch'];
            }
            $cose = base64_decode((string) $row['cose_public_key'], true);
            $rawId = self::unb64u($row['credential_id']);
            $stored = ['cose_public_key' => $cose === false ? '' : $cose, 'sign_count' => (int) $row['sign_count'], 'origin' => (string) $row['origin'], 'rp_id' => (string) $row['rp_id']];
        }
        try {
            $count = Verifier::assert($stored, $a['clientDataJSON'], $a['authenticatorData'], $a['signature'], $challenge, $rp['origin'], $rp['rp_id']);
        } catch (WebAuthnException $e) {
            if ($e->getMessage() === 'signcount_regression') {
                $ipTrunc = (new ClientIp($this->container))->truncate($ip);
                AuditModel::of($this->container, $this->clock)->record('hw_signcount', [
                    'actor_user_id' => $userId,
                    'ip_trunc' => $ipTrunc === '' ? null : $ipTrunc,
                    'ua_family' => UaFamily::fromRequest($this->request),
                ]);
            }
            return ['status' => 'invalid'];
        }
        if ($row !== null) {
            $db->execute('UPDATE vault_webauthn SET sign_count = ?, last_used_at = ? WHERE id = ?', [$count, $this->now(), (int) $row['id']]);
        }
        return ['status' => 'ok', 'row' => $row, 'raw_id' => $rawId, 'count' => $count];
    }

    // Each assertion checked; each must be a different one of the user's keys.
    private function checkAll(VaultDb $db, int $userId, array $list, array $rp, string $ip): array
    {
        $keys = [];
        foreach ($list as $a) {
            if (isset($keys[$a['credential_id']])) {
                return ['status' => 'invalid'];
            }
            $out = $this->checkAssertion($db, $userId, 'ceremony', $a, $rp, $ip);
            if ($out['status'] !== 'ok') {
                return $out;
            }
            $keys[$a['credential_id']] = ['credential_id' => $a['credential_id'], 'raw_id' => $out['raw_id'], 'prf' => $a['prf']];
        }
        return ['status' => 'ok', 'keys' => array_values($keys)];
    }

    // The challenge named in clientDataJSON, consumed (one DELETE) if it is open for this user and purpose; null
    // otherwise. The verifier then compares it strictly with what the client signed.
    private function consume(VaultDb $db, int $userId, string $purpose, string $clientDataJson): ?string
    {
        try {
            $cd = json_decode($clientDataJson, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        $raw = is_array($cd) && is_string($cd['challenge'] ?? null) ? self::unb64uOrNull($cd['challenge']) : null;
        if ($raw === null || strlen($raw) !== 32) {
            return null;
        }
        $n = $db->execute(
            'DELETE FROM vault_challenges WHERE user_id = ? AND purpose = ? AND challenge_hash = ? AND expires_at > ?',
            [$userId, $purpose, self::challengeHash($raw), $this->now()]
        );
        return $n === 1 ? $raw : null;
    }

    // The live human principal whose key $sk is, not an agent and not rotating.
    /** @return array{public_key:string,key_gen:int} public_key raw */
    private function principal(VaultDb $db, int $userId, #[\SensitiveParameter] string $sk): array
    {
        $row = $db->fetchOne(
            'SELECT p.kind, p.public_key, p.key_gen, p.state FROM vault_principals p JOIN users u ON u.id = p.user_id WHERE p.user_id = ? AND u.is_active = 1 AND p.live_user_id IS NOT NULL',
            [$userId]
        );
        $pk = $row === null ? false : base64_decode((string) $row['public_key'], true);
        if ($pk === false || $row['kind'] !== 'human' || AgentRoster::of($this->container)->isAgent($userId) || ! self::keyMatches($sk, $pk)) {
            throw new VaultException('not_found');
        }
        if ($row['state'] !== 'active' || $db->fetchOne('SELECT user_id FROM vault_rotations WHERE user_id = ?', [$userId]) !== null) {
            throw new VaultException('rotation_in_progress');
        }
        return ['public_key' => $pk, 'key_gen' => (int) $row['key_gen']];
    }

    // Before a write: nothing changed since the checks (same key generation, the same set of credentials, the new id
    // unused). The set, not the count: a concurrent remove plus add keeps the count (review M3).
    /** @param list<string> $ids sorted */
    private function recheck(VaultDb $db, int $userId, #[\SensitiveParameter] string $sk, int $keyGen, array $ids, ?string $newCredentialId): void
    {
        $p = $this->principal($db, $userId, $sk);
        if ($p['key_gen'] !== $keyGen || $this->idsIn($db, $userId) !== $ids
            || ($newCredentialId !== null && $db->fetchOne('SELECT id FROM vault_webauthn WHERE credential_id = ?', [$newCredentialId]) !== null)) {
            throw new VaultException('conflict');
        }
    }

    /** @param list<string> $ids sorted */
    private function requireState(VaultDb $db, int $userId, array $ids): void
    {
        if ($this->idsIn($db, $userId) !== $ids) {
            throw new VaultException('conflict');
        }
        if ($db->fetchOne('SELECT user_id FROM vault_rotations WHERE user_id = ?', [$userId]) !== null) {
            throw new VaultException('rotation_in_progress');
        }
    }

    /** @return list<string> the user's credential ids, sorted */
    private function idsIn(VaultDb $db, int $userId): array
    {
        $ids = array_map('strval', array_column($db->fetchAll('SELECT credential_id FROM vault_webauthn WHERE user_id = ?', [$userId]), 'credential_id'));
        sort($ids);
        return $ids;
    }

    // The passphrase and this key's PRF output together open this key's own wrap to exactly $sk (one Argon2).
    /** @param array{credential_id:string,raw_id:string,prf:string} $key @param array{public_key:string,key_gen:int} $p */
    private function proveKey(int $userId, string $ip, RateLimiter $limiter, #[\SensitiveParameter] array $key, #[\SensitiveParameter] string $passphrase, #[\SensitiveParameter] string $sk, array $p): void
    {
        $this->proveFactor($userId, $ip, $limiter, $this->wrapOf($userId, 'passphrase+prf', $key['credential_id'], $p['key_gen']), $passphrase, ['prf', $key['raw_id'], $key['prf']], $sk, $p['public_key']);
    }

    private function deleteKey(VaultDb $db, int $userId, string $credentialId): void
    {
        $db->execute("DELETE FROM vault_wraps WHERE user_id = ? AND method = 'passphrase+prf' AND credential_id = ?", [$userId, $credentialId]);
        $db->execute('DELETE FROM vault_webauthn WHERE user_id = ? AND credential_id = ?', [$userId, $credentialId]);
        AuditModel::of($this->container, $this->clock)->record('hw_key_remove', ['actor_user_id' => $userId]);
    }

    // An active wrap of the current key (R10: the row first, then sealed with its id in the AD, in the caller's
    // exclusive transaction). $f: a factor from prfFactor or passphraseFactor.
    private function insertWrap(VaultDb $db, int $userId, #[\SensitiveParameter] string $sk, #[\SensitiveParameter] array $f, int $keyGen): void
    {
        $wrapId = $db->insert('vault_wraps', [
            'user_id' => $userId,
            'method' => $f['method'],
            'credential_id' => $f['credential_id'] === '' ? null : $f['credential_id'],
            'kdf_salt' => base64_encode($f['kdf_salt']),
            'kdf_ops' => $f['kdf_ops'],
            'kdf_mem' => $f['kdf_mem'],
            'status' => 'active',
            'key_gen' => $keyGen,
            'nonce' => '',
            'wrapped_sk' => '',
            'crypto_v' => Wraps::CRYPTO_V,
            'created_at' => $this->now(),
        ]);
        $w = Wraps::wrap($sk, $f['kek'], $userId, $f['method'], $f['credential_id'], $wrapId);
        $db->execute('UPDATE vault_wraps SET nonce = ?, wrapped_sk = ? WHERE id = ?', [$w['nonce'], $w['wrapped_sk'], $wrapId]);
    }

    // A passphrase+prf factor (RotationService's shape) under a fresh salt at the default KDF parameters.
    private function prfFactor(#[\SensitiveParameter] string $passphrase, string $credentialId, string $rawId, #[\SensitiveParameter] string $prf): array
    {
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $ikm = ($this->argon2)($passphrase, $salt, Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM);
        try {
            $kek = Kdf::kek($ikm, 'prf', $rawId, $prf);
        } finally {
            sodium_memzero($ikm);
        }
        return ['method' => 'passphrase+prf', 'kek' => $kek, 'credential_id' => $credentialId, 'kdf_salt' => $salt, 'kdf_ops' => Kdf::DEFAULT_OPS, 'kdf_mem' => Kdf::DEFAULT_MEM];
    }

    private function passphraseFactor(#[\SensitiveParameter] string $passphrase): array
    {
        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $ikm = ($this->argon2)($passphrase, $salt, Kdf::DEFAULT_OPS, Kdf::DEFAULT_MEM);
        try {
            $kek = Kdf::kek($ikm, 'passphrase');
        } finally {
            sodium_memzero($ikm);
        }
        return ['method' => 'passphrase', 'kek' => $kek, 'credential_id' => '', 'kdf_salt' => $salt, 'kdf_ops' => Kdf::DEFAULT_OPS, 'kdf_mem' => Kdf::DEFAULT_MEM];
    }

    private static function wipeFactors(#[\SensitiveParameter] array &$factors): void
    {
        foreach (array_keys($factors) as $i) {
            if (is_array($factors[$i]) && is_string($factors[$i]['kek'] ?? null)) {
                sodium_memzero($factors[$i]['kek']);
            }
        }
    }

    private function wrapOf(int $userId, string $method, string $credentialId, int $keyGen): ?array
    {
        return $this->lock()->shared(fn (): ?array => $this->wrapIn($this->vdb(), $userId, $method, $credentialId, $keyGen));
    }

    private function wrapIn(VaultDb $db, int $userId, string $method, string $credentialId, int $keyGen): ?array
    {
        return $credentialId === ''
            ? $db->fetchOne("SELECT * FROM vault_wraps WHERE user_id = ? AND method = ? AND status = 'active' AND key_gen = ? ORDER BY id LIMIT 1", [$userId, $method, $keyGen])
            : $db->fetchOne("SELECT * FROM vault_wraps WHERE user_id = ? AND method = ? AND credential_id = ? AND status = 'active' AND key_gen = ? ORDER BY id LIMIT 1", [$userId, $method, $credentialId, $keyGen]);
    }

    private function countIn(VaultDb $db, int $userId): int
    {
        $r = $db->fetchOne('SELECT COUNT(*) AS n FROM vault_webauthn WHERE user_id = ?', [$userId]);
        return (int) ($r['n'] ?? 0);
    }

    // A check's outcome as the caller's error: rp_id_mismatch, rotation_needs_factors, or hw_key_invalid.
    private static function raise(array $out): void
    {
        match ($out['status']) {
            'ok' => null,
            'rp_id_mismatch' => throw new VaultException('rp_id_mismatch'),
            'needs_factors' => throw new VaultException('rotation_needs_factors'),
            default => throw new VaultException('hw_key_invalid'),
        };
    }

    private static function assertionShape(mixed $a): array
    {
        if (! is_array($a)) {
            throw new VaultException('hw_key_invalid');
        }
        $id = $a['credential_id'] ?? null;
        $out = ['credential_id' => is_string($id) ? $id : ''];
        foreach (['clientDataJSON', 'authenticatorData', 'signature', 'prf'] as $k) {
            $out[$k] = is_string($a[$k] ?? null) ? $a[$k] : '';
        }
        $raw = self::unb64uOrNull($out['credential_id']);
        if ($raw === null || $raw === '' || strlen($raw) > self::CREDENTIAL_ID_BYTES || $out['clientDataJSON'] === '' || $out['authenticatorData'] === '' || $out['signature'] === '') {
            throw new VaultException('hw_key_invalid');
        }
        return $out;
    }

    private static function assertionList(mixed $list): array
    {
        if (! is_array($list) || ! array_is_list($list) || count($list) > self::MAX_KEYS) {
            throw new VaultException('hw_key_invalid');
        }
        return array_map([self::class, 'assertionShape'], $list);
    }

    private static function registrationShape(mixed $r): array
    {
        if (! is_array($r) || ! is_string($r['clientDataJSON'] ?? null) || ! is_string($r['attestationObject'] ?? null) || ! is_array($r['clientExtensionResults'] ?? null)) {
            throw new VaultException('hw_key_invalid');
        }
        return ['clientDataJSON' => $r['clientDataJSON'], 'attestationObject' => $r['attestationObject'], 'clientExtensionResults' => $r['clientExtensionResults']];
    }

    private static function label(mixed $label): string
    {
        $label = is_string($label) ? trim($label) : '';
        if ($label === '' || ! mb_check_encoding($label, 'UTF-8') || mb_strlen($label) > self::LABEL_CHARS || preg_match('/[\x00-\x1f\x7f]/', $label)) {
            throw new VaultException('payload_invalid');
        }
        return $label;
    }

    private static function json(string $json): mixed
    {
        try {
            return json_decode($json, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new VaultException('payload_invalid');
        }
    }

    private static function unb64u(mixed $s): string
    {
        $raw = is_string($s) ? self::unb64uOrNull($s) : null;
        if ($raw === null) {
            throw new VaultException('payload_invalid');
        }
        return $raw;
    }

    // Strict base64url without padding: re-encoding must give back the same text.
    private static function unb64uOrNull(string $s): ?string
    {
        if (strlen($s) > 8192 || ! preg_match('/^[A-Za-z0-9_-]*$/D', $s)) {
            return null;
        }
        $raw = base64_decode(strtr($s, '-_', '+/'), true);
        return $raw === false || self::b64u($raw) !== $s ? null : $raw;
    }

    private static function challengeHash(string $challenge): string
    {
        return bin2hex(sodium_crypto_generichash($challenge, '', 32));
    }

    private static function keyMatches(#[\SensitiveParameter] string $sk, string $pk): bool
    {
        try {
            return strlen($sk) === SODIUM_CRYPTO_BOX_SECRETKEYBYTES && hash_equals($pk, sodium_crypto_box_publickey_from_secretkey($sk));
        } catch (SodiumException|ValueError) {
            return false;
        }
    }

    // The vault_wraps columns Wraps::unwrap reads, with ids as ints (R12).
    private static function wrapRow(array $wrap): array
    {
        return [
            'id' => (int) $wrap['id'],
            'user_id' => (int) $wrap['user_id'],
            'method' => (string) $wrap['method'],
            'credential_id' => $wrap['credential_id'],
            'nonce' => (string) $wrap['nonce'],
            'wrapped_sk' => (string) $wrap['wrapped_sk'],
            'crypto_v' => (int) $wrap['crypto_v'],
        ];
    }

    private function rotation(): RotationService
    {
        return $this->rotation ??= new RotationService($this->container, $this->slots, $this->argon2, $this->clock);
    }

    private function vdb(): VaultDb
    {
        return new VaultDb($this->container);
    }

    private function lock(): VaultLock
    {
        return new VaultLock($this->container);
    }

    private function now(): int
    {
        return (int) ($this->clock)();
    }
}
