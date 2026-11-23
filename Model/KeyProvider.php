<?php
namespace Kanboard\Plugin\Vault\Model;

// Where the Server principal's secret key comes from (spec amendment: Server key file; Joist in phase 3). Kept minimal
// so another provider can implement it: every failure is ServerKeyUnavailable, and nothing secret leaves except the
// opened key, which the caller wipes.
interface KeyProvider
{
    /** 'file' (FileKeyProvider); 'joist' arrives in phase 3. */
    public function id(): string;

    /** The DEK sealed to Server under $ctx (raw sealed bytes in). ServerKeyUnavailable on any failure. */
    public function openSealedDek(string $sealed, DekContext $ctx): string;

    /** Whether the key opens now (a FileKeyProvider reads the key file afresh). Never throws. */
    public function healthy(): bool;

    /** R1: the 32-byte field-MAC key, sealed to Server in vault_meta. ServerKeyUnavailable on any failure. */
    public function openFieldMacKey(): string;
}
