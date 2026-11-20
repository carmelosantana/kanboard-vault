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
    // The rest of an entry or group's plaintext (spec: Testing, backup theft: titles, usernames, group names too).
    public const ENTRY_TITLE = 'VaultFixtureSecret-title-Jr4wC8';
    public const ENTRY_USERNAME = 'VaultFixtureSecret-username-Ue7yA3';
    public const ENTRY_URL = 'https://VaultFixtureSecret-url-Kp2dF6.example/login';
    public const ENTRY_TAG = 'VaultFixtureSecret-tag-Wm8sN1';
    public const FIELD_NAME = 'VaultFixtureSecret-fieldname-Oa5tH9';
    public const GROUP_NAME = 'VaultFixtureSecret-groupname-Ib3qL7';
    public const GROUP_NOTES = 'VaultFixtureSecret-groupnotes-Ec6zV2';
    public const SHARE_SECRET = 'VaultFixtureSecret-onetime-Rh1mX4';
    public const SHARE_PASSPHRASE = 'VaultFixtureSecret-sharephrase-Dn9pG5';
    public const SHARE_LABEL = 'VaultFixtureSecret-sharelabel-Fy3bJ8';
    public const AGENT_SECRET = 'VaultFixtureSecret-agentpw-Sk7cQ1';
    public const IMPORT_PASSWORD = 'VaultFixtureSecret-importpw-Lt4eB6';
    public const IMPORT_GROUP = 'VaultFixtureSecret-importgroup-Mz2uW9';

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
        self::ENTRY_TITLE,
        self::ENTRY_USERNAME,
        self::ENTRY_URL,
        self::ENTRY_TAG,
        self::FIELD_NAME,
        self::GROUP_NAME,
        self::GROUP_NOTES,
        self::SHARE_SECRET,
        self::SHARE_PASSPHRASE,
        self::SHARE_LABEL,
        self::AGENT_SECRET,
        self::IMPORT_PASSWORD,
        self::IMPORT_GROUP,
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

    // An entry payload with a marker in every plaintext slot: title, username, url, notes, tags, OTP seed, a custom
    // field's name and value.
    public static function fullEntry(): array
    {
        return [
            'title' => self::ENTRY_TITLE,
            'username' => self::ENTRY_USERNAME,
            'password' => self::ENTRY_PASSWORD,
            'url' => self::ENTRY_URL,
            'notes' => self::ENTRY_NOTES,
            'tags' => [self::ENTRY_TAG],
            'otp' => self::ENTRY_OTP,
            'fields' => [['name' => self::FIELD_NAME, 'value' => self::FIELD_VALUE, 'protected' => true]],
        ];
    }
}
