<?php
namespace Kanboard\Plugin\Vault\Model;

// What a sealed DEK is bound to (Sealer: enc("dek", object_type, object_id, key_epoch, principal_id, DEK)).
final class DekContext
{
    public function __construct(
        public readonly string $objectType,
        public readonly int $objectId,
        public readonly int $keyEpoch,
        public readonly int $principalId,
    ) {
    }
}
