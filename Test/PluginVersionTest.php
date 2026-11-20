<?php
require_once 'tests/units/Base.php';

use KanboardTests\units\Base;
use Kanboard\Plugin\Vault\Plugin;

// Tag == plugin.json == getPluginVersion(): drift across the three is the most common release defect.
class PluginVersionTest extends Base
{
    public function testVersionsAgree(): void
    {
        $json = json_decode(file_get_contents(__DIR__.'/../plugin.json'), true);
        $this->assertSame('1.0.0', $json['version']);
        $this->assertSame($json['version'], (new Plugin($this->container))->getPluginVersion());
        $this->assertSame('MIT', $json['license']);
        $this->assertSame('>=1.2.47', $json['kanboard_version']);
        $this->assertSame('>=8.4', $json['php_version']);
        $this->assertSame([], $json['requires']);
        $this->assertSame('Agents', $json['recommends'][0]['name']);
    }

    // Final review I4: the spec chose server-side decryption in memory (approach B), not end-to-end encryption
    // (approach C, rejected). The listing text and the plugin page are the most widely read security claim Vault makes,
    // so neither may say end-to-end or zero-knowledge. Kills: the old "End-to-end encrypted" wording coming back.
    public function testDescriptionsMakeNoEndToEndClaim(): void
    {
        $json = json_decode(file_get_contents(__DIR__.'/../plugin.json'), true);
        $descriptions = [$json['description'], (new Plugin($this->container))->getPluginDescription()];
        foreach ($descriptions as $d) {
            $this->assertDoesNotMatchRegularExpression('/end[- ]to[- ]end|zero[- ]knowledge/i', $d);
            $this->assertStringContainsString('ncrypted password store', $d);
        }
    }
}
