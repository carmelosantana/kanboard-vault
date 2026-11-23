<?php
namespace Kanboard\Plugin\Vault\Model;

// The Server key file is missing, unsafe or unreadable. The message is always the frozen refusal reason and never
// carries a path or key bytes; nothing is chained as `previous`, since a PHP warning or error could name the path.
final class ServerKeyUnavailable extends \RuntimeException
{
    public const REASON = 'server_key_unavailable';

    public function __construct()
    {
        parent::__construct(self::REASON);
    }
}
