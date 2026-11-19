<?php
namespace Kanboard\Plugin\Vault\Test\Support;

// Plaintext markers for every secret a fixture hands Vault: passphrases, entry values and custom fields. Each is
// unique, so a log or audit grep for it can't match anything else (spec: Audit, logging rules). Tests that need a
// passphrase, password, note, OTP seed or field value take it from here, and the log hygiene test greps every
// captured log for every one of them.
final class Fixtures
{
    public const PASSPHRASE = 'VaultFixtureSecret-passphrase-Qm4rT8';
    public const BOB_PASSPHRASE = 'VaultFixtureSecret-bobphrase-Lw2xK9';
    public const NEW_PASSPHRASE = 'VaultFixtureSecret-newphrase-Hs7vB1';
    public const WRONG_PASSPHRASE = 'VaultFixtureSecret-wrongguess-Zc3nP6';
    public const ENTRY_PASSWORD = 'VaultFixtureSecret-entrypw-Ty5gM2';
    public const ENTRY_NOTES = 'VaultFixtureSecret-notes-Pd8kR4';
    public const ENTRY_OTP = 'VaultFixtureSecret-otpseed-Xb6jW3';
    public const FIELD_VALUE = 'VaultFixtureSecret-fieldvalue-Nf1qS7';
    public const UPDATED_PASSWORD = 'VaultFixtureSecret-updatedpw-Gv9hE5';

    public const SECRETS = [
        self::PASSPHRASE,
        self::BOB_PASSPHRASE,
        self::NEW_PASSPHRASE,
        self::WRONG_PASSPHRASE,
        self::ENTRY_PASSWORD,
        self::ENTRY_NOTES,
        self::ENTRY_OTP,
        self::FIELD_VALUE,
        self::UPDATED_PASSWORD,
    ];

    // An entry payload carrying every entry-level marker.
    public static function entry(string $title = 'fixture entry'): array
    {
        return [
            'title' => $title,
            'username' => 'fixture-user',
            'password' => self::ENTRY_PASSWORD,
            'url' => 'https://example.test/login',
            'notes' => self::ENTRY_NOTES,
            'otp' => self::ENTRY_OTP,
            'fields' => [['name' => 'api key', 'value' => self::FIELD_VALUE, 'protected' => true]],
        ];
    }
}
