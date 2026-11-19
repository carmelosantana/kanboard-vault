<?php
require_once 'tests/units/Base.php';

use KanboardTests\units\Base;
use Kanboard\Plugin\Vault\Plugin;

class SodiumGateTest extends Base
{
    public function testIsSupportedTracksSodiumPwhash(): void
    {
        $this->assertSame(function_exists('sodium_crypto_pwhash'), (new Plugin($this->container))->isSupported());
    }

    public function testWithoutSodiumOnlyTheNoticeIsRegistered(): void
    {
        $plugin = new class($this->container) extends Plugin {
            public function isSupported(): bool { return false; }
        };
        $plugin->initialize();
        $this->assertSame([['template' => 'Vault:layout/sodium_notice']], $this->container['hook']->getListeners('template:layout:top'));
    }

    public function testWithSodiumNoNoticeIsRegistered(): void
    {
        $plugin = new class($this->container) extends Plugin {
            public function isSupported(): bool { return true; }
        };
        $plugin->initialize();
        $this->assertSame([], $this->container['hook']->getListeners('template:layout:top'));
    }

    // The console commands exist only when Vault is active (spec: vault:org-keygen, vault:org-recover, vault:purge).
    public function testConsoleCommandsRegisteredOnlyWithSodium(): void
    {
        $names = ['vault:org-keygen', 'vault:org-recover', 'vault:purge'];
        $without = new class($this->container) extends Plugin {
            public function isSupported(): bool { return false; }
        };
        $without->initialize();
        foreach ($names as $n) {
            $this->assertFalse($this->container['cli']->has($n), $n);
        }
        $with = new class($this->container) extends Plugin {
            public function isSupported(): bool { return true; }
        };
        $with->initialize();
        foreach ($names as $n) {
            $this->assertTrue($this->container['cli']->has($n), $n);
        }
    }

    public function testNoticeRendersForAdminsOnly(): void
    {
        $src = file_get_contents(__DIR__.'/../Template/layout/sodium_notice.php');
        $this->assertStringContainsString('$this->user->isAdmin()', $src);
        $this->assertStringContainsString('sodium', $src);
        $this->assertStringNotContainsString('<script', $src);
    }
}
