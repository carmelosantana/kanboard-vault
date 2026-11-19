<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Core\Http\Request;

// The audit's ua_family (spec: Audit, "browser and OS major only"): "<Browser> <major> / <OS>", built only from the
// fixed names below and a major version of at most four digits, so no other part of the User-Agent header (build
// numbers, device models, anything a client stuffs in) reaches the log. The OS is named without a version.
final class UaFamily
{
    // Order matters: Edge and Opera also say Chrome; Chrome also says Safari.
    private const BROWSERS = [
        'Edge' => '~\bEdg(?:e|A|iOS)?/(\d{1,4})~',
        'Opera' => '~\bOPR/(\d{1,4})~',
        'Firefox' => '~\b(?:Firefox|FxiOS)/(\d{1,4})~',
        'Chrome' => '~\b(?:Chrome|CriOS)/(\d{1,4})~',
        'Safari' => '~\bVersion/(\d{1,4})[^ ]* (?:Mobile/\S+ )?Safari/~',
    ];
    // Order matters: iOS also says "like Mac OS X"; Android and ChromeOS also say Linux.
    private const SYSTEMS = [
        'iOS' => '~\b(?:iPhone|iPad|iPod)\b~',
        'Android' => '~\bAndroid\b~',
        'ChromeOS' => '~\bCrOS\b~',
        'Windows' => '~\bWindows\b~',
        'macOS' => '~\bMac OS X\b~',
        'Linux' => '~\bLinux\b~',
    ];

    // Exactly a value fromUserAgent can return: a fixed browser name with a major version, or Other; a fixed OS name or
    // Other. The audit refuses anything else (T10 carry), so no raw User-Agent text can reach vault_audit.
    public static function isFamily(string $value): bool
    {
        $browsers = implode('|', array_keys(self::BROWSERS));
        $systems = implode('|', array_keys(self::SYSTEMS));
        return preg_match('~^(?:(?:'.$browsers.') \d{1,4}|Other) / (?:'.$systems.'|Other)$~D', $value) === 1;
    }

    public static function fromRequest(Request $request): ?string
    {
        return self::fromUserAgent($request->getServerVariable('HTTP_USER_AGENT'));
    }

    public static function fromUserAgent(string $ua): ?string
    {
        if (trim($ua) === '') {
            return null;
        }
        $browser = 'Other';
        foreach (self::BROWSERS as $name => $re) {
            if (preg_match($re, $ua, $m) === 1) {
                $browser = $name.' '.$m[1];
                break;
            }
        }
        $os = 'Other';
        foreach (self::SYSTEMS as $name => $re) {
            if (preg_match($re, $ua) === 1) {
                $os = $name;
                break;
            }
        }
        return $browser.' / '.$os;
    }
}
