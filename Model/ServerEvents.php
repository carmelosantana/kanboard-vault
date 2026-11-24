<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Event\GenericEvent;

// The consumer events (spec amendment: Rotation and revocation). Each is dispatched on Kanboard's dispatcher after
// the change commits (VaultLock::afterCommit) and carries ids only: never a title, owner, consumer, field or value.
//   CHANGED  an entry was saved: ['entry_id' => int, 'version' => int], the new version
//   REVOKED  an entry lost its Server grant (revoked, Server turned off, the entry deleted): ['entry_id' => int]
final class ServerEvents
{
    public const CHANGED = 'vault.secret.changed';
    public const REVOKED = 'vault.secret.revoked';

    public static function changed($container, int $entryId, int $version): void
    {
        self::dispatch($container, self::CHANGED, ['entry_id' => $entryId, 'version' => $version]);
    }

    public static function revoked($container, int $entryId): void
    {
        self::dispatch($container, self::REVOKED, ['entry_id' => $entryId]);
    }

    private static function dispatch($container, string $name, array $payload): void
    {
        (new VaultLock($container))->afterCommit(static fn () => $container['dispatcher']->dispatch(new GenericEvent($payload), $name));
    }
}
