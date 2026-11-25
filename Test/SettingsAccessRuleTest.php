<?php

namespace Kanboard\Plugin\Vault\Test;

require_once 'tests/units/Base.php';

use Kanboard\Core\Plugin\Hook;
use Kanboard\Core\Security\Role;
use Kanboard\Plugin\Vault\Plugin;
use KanboardTests\units\Base;

/**
 * The settings controller used to share core's name `SettingsController` and so inherited its
 * admin-only rule. Renamed (#7337), it needs its own rule or it falls to the app-user default.
 */
class SettingsAccessRuleTest extends Base
{
    public function testEverySettingsActionIsAdminOnlyInTheAccessMap(): void
    {
        $this->container['hook'] = new Hook();
        (new Plugin($this->container))->initialize();
        $map = $this->container['applicationAccessMap'];
        foreach (['index', 'save', 'server'] as $action) {
            $this->assertSame([Role::APP_ADMIN], $map->getRoles('VaultSettingsController', $action), $action);
        }
    }

    /** Without libsodium initialize() returns early; the settings controller is still reachable by URL. */
    public function testTheRuleHoldsWithoutLibsodium(): void
    {
        $this->container['hook'] = new Hook();
        (new class($this->container) extends Plugin {
            public function isSupported(): bool
            {
                return false;
            }
        })->initialize();
        $map = $this->container['applicationAccessMap'];
        foreach (['index', 'save', 'server'] as $action) {
            $this->assertSame([Role::APP_ADMIN], $map->getRoles('VaultSettingsController', $action), $action);
        }
    }
}
