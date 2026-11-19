<?php

namespace Kanboard\Plugin\Vault\WebAuthn;

// A CBOR input broke one of the decoder's fail-closed rules. The message is always 'cbor_invalid'.
class CborException extends WebAuthnException
{
}
