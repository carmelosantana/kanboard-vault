<?php
require_once 'tests/units/Base.php';

use Kanboard\Plugin\Vault\Model\UaFamily;
use KanboardTests\units\Base;
use PHPUnit\Framework\Attributes\DataProvider;

// Spec: Audit, ua_family "(browser and OS major only)". The value is built only from a fixed vocabulary and a
// major version of at most four digits, so nothing else from the header (build numbers, device names, tokens a
// client stuffs in) reaches the audit log.
class UaFamilyTest extends Base
{
    public static function agents(): array
    {
        return [
            'firefox linux' => ['Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0', 'Firefox 140 / Linux'],
            'chrome windows' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36', 'Chrome 131 / Windows'],
            'edge before chrome' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.70', 'Edge 131 / Windows'],
            'opera before chrome' => ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/114.0.0.0', 'Opera 114 / Linux'],
            'safari macos' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15', 'Safari 18 / macOS'],
            'safari ios before macos' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1', 'Safari 18 / iOS'],
            'chrome android before linux' => ['Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36', 'Chrome 131 / Android'],
            'chromeos' => ['Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'Chrome 131 / ChromeOS'],
            'unknown' => ['curl/8.5.0', 'Other / Other'],
            'long major capped' => ['Firefox/123456789 (Windows NT 10.0)', 'Firefox 1234 / Windows'],
            'stuffed token' => ['Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0 secret-token-XYZ <script>', 'Firefox 140 / Linux'],
        ];
    }

    // Kills: Chrome tested before Edge/Opera, macOS before iOS, Linux before Android, the version not truncated to
    // its major, the digits uncapped, raw header text copied through.
    /** @dataProvider agents */
    #[DataProvider('agents')]
    public function testFamilies(string $ua, string $expected): void
    {
        $this->assertSame($expected, UaFamily::fromUserAgent($ua));
    }

    // Kills: an empty header recorded as "Other / Other" rather than NULL.
    public function testEmptyIsNull(): void
    {
        $this->assertNull(UaFamily::fromUserAgent(''));
        $this->assertNull(UaFamily::fromUserAgent('   '));
    }
}
