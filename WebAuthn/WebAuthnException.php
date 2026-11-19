<?php

namespace Kanboard\Plugin\Vault\WebAuthn;

/**
 * Every WebAuthn verification failure. Messages are fixed codes and never carry input bytes.
 * Verifier normalises everything it throws to 'webauthn_invalid', except 'signcount_regression'
 * (a valid signature with a counter that didn't advance), which the caller audits as hw_signcount.
 */
class WebAuthnException extends \RuntimeException
{
}
