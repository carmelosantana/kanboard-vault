<?php
namespace Kanboard\Plugin\Vault\Secrets;

use Kanboard\Plugin\Vault\Model\ServerGrant;

// A ref (spec amendment: Consumer API): vault://<entry_id>/<field>. The id has 1 to 18 digits and no leading zero; the
// field is percent-encoded and decodes to a top-level key or a custom name (ServerGrant::validName). P1 has no versions,
// so a ref with '@' (or anything else outside the pattern) doesn't parse.
final class SecretRef
{
    private const PATTERN = '#^vault://([1-9][0-9]{0,17})/([^/@?\#\s]{1,384})$#D';

    public function __construct(public readonly int $entryId, public readonly string $field)
    {
    }

    public static function parse(#[\SensitiveParameter] string $ref): ?self
    {
        if (preg_match(self::PATTERN, $ref, $m) !== 1) {
            return null;
        }
        $field = rawurldecode($m[2]);
        return ServerGrant::validName($field) ? new self((int) $m[1], $field) : null;
    }

    // A top-level key (title included, R5), which wins over a custom field with the same name.
    public function isTopLevel(): bool
    {
        return in_array($this->field, ServerGrant::TOP_LEVEL, true);
    }
}
