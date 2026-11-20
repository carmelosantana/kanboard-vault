<?php
require_once 'tests/units/Base.php';

use KanboardTests\units\Base;

// Final review M11: Template/vault/app.php hands vault.js its endpoints and messages as JSON in data attributes.
// Plain json_encode returned false on one invalid UTF-8 string (a bad translation), and the page lost every message
// and every endpoint. Kills: the JSON_INVALID_UTF8_SUBSTITUTE / JSON_THROW_ON_ERROR flags dropped.
class AppTemplateTest extends Base
{
    public function testInvalidUtf8MessageKeepsEndpointsAndMessages(): void
    {
        $html = $this->container['template']->render('Vault:vault/app', [
            'state' => 'locked',
            'client' => [
                'csrf' => 'token',
                'endpoints' => ['unlock' => '/vault/unlock'],
                'messages' => ['good' => 'Unlocked', 'bad' => "broken \xff translation"],
                'idle_ms' => 1000,
            ],
            'https_ok' => true,
        ]);
        $this->assertMatchesRegularExpression('/data-endpoints="([^"]+)"/', $html);
        preg_match('/data-endpoints="([^"]*)"/', $html, $e);
        preg_match('/data-messages="([^"]*)"/', $html, $m);
        $this->assertSame(['unlock' => '/vault/unlock'], json_decode(html_entity_decode($e[1], ENT_QUOTES), true));
        $messages = json_decode(html_entity_decode($m[1] ?? '', ENT_QUOTES), true);
        $this->assertSame('Unlocked', $messages['good'] ?? null);
        $this->assertStringStartsWith('broken ', $messages['bad'] ?? '');
    }
}
