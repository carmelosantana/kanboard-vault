<?php
namespace Kanboard\Plugin\Vault\Secrets;

// ServiceSecrets::describe's answer: ok, or the refusal a read would get before decryption (rate limits aside). It never
// holds a title or a value; $entryId and $field are the ref's own parts (null when the ref doesn't parse).
final class RefStatus
{
    public function __construct(
        public readonly bool $ok,
        public readonly ?string $reason,
        public readonly ?int $entryId,
        public readonly ?string $field,
    ) {
    }
}
