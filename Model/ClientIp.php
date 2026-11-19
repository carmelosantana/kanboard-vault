<?php
namespace Kanboard\Plugin\Vault\Model;

use Kanboard\Core\Base;
use Kanboard\Core\Http\Request;

// Resolves the client IP without Request::getIpAddress(), which trusts a forwarding header from any
// sender and returns its client-controlled left-most value.
// Forwarding headers count only when REMOTE_ADDR is inside a trusted CIDR:
// CF-Connecting-IP must hold exactly one valid IP; otherwise X-Forwarded-For is walked right to left,
// skipping trusted hops. Results are canonical, with IPv4-mapped IPv6 shown as IPv4.
class ClientIp extends Base
{
    // Returns '' when REMOTE_ADDR itself is not a valid IP.
    public function resolve(Request $request, array $trustedCidrs): string
    {
        $remote = self::normalize($request->getServerVariable('REMOTE_ADDR'));
        if ($remote === null || ! $this->inCidrs($remote, $trustedCidrs)) {
            return $remote ?? '';
        }

        $cf = $request->getServerVariable('HTTP_CF_CONNECTING_IP');
        if ($cf !== '') {
            return self::normalize(trim($cf)) ?? $remote;
        }

        $xff = $request->getServerVariable('HTTP_X_FORWARDED_FOR');
        if (trim($xff) === '') {
            return $remote;
        }
        $last = $remote;
        foreach (array_reverse(explode(',', $xff)) as $hop) {
            $ip = self::normalize(trim($hop));
            if ($ip === null) {
                // A malformed hop written before any untrusted one: the chain can't be read safely.
                return $remote;
            }
            if (! $this->inCidrs($ip, $trustedCidrs)) {
                return $ip;
            }
            $last = $ip;
        }
        // Every hop is trusted: the furthest one reached is the client.
        return $last;
    }

    // R41: did this request reach Kanboard over HTTPS? The connection's own HTTPS always counts. A proxy's
    // X-Forwarded-Proto (its right-most value: what the last proxy saw) or X-Forwarded-Ssl counts only when
    // REMOTE_ADDR is a trusted proxy. Request::isHTTPS() trusts X-Forwarded-Proto from any sender, so a client
    // on plain HTTP could claim HTTPS for itself.
    public function secureTransport(Request $request, array $trustedCidrs): bool
    {
        $https = strtolower($request->getServerVariable('HTTPS'));
        if ($https !== '' && $https !== 'off') {
            return true;
        }
        if (! $this->inCidrs($request->getServerVariable('REMOTE_ADDR'), $trustedCidrs)) {
            return false;
        }
        $proto = explode(',', $request->getServerVariable('HTTP_X_FORWARDED_PROTO'));
        return strtolower(trim((string) end($proto))) === 'https'
            || strtolower(trim($request->getServerVariable('HTTP_X_FORWARDED_SSL'))) === 'on';
    }

    // An IPv4-mapped IPv6 CIDR (::ffff:a.b.c.d/n) matches nothing: addresses are compared as IPv4 (T4 minor).
    public static function isMappedCidr(string $cidr): bool
    {
        $net = explode('/', $cidr)[0];
        $bin = filter_var($net, FILTER_VALIDATE_IP) === false ? false : inet_pton($net);
        return $bin !== false && strlen($bin) === 16 && substr($bin, 0, 12) === str_repeat("\0", 10)."\xff\xff";
    }

    // IPv4 → a.b.c.0/24, IPv6 → its /48; '' for anything that isn't an IP.
    public function truncate(string $ip): string
    {
        $ip = self::normalize($ip);
        if ($ip === null) {
            return '';
        }
        $bin = inet_pton($ip);
        if (strlen($bin) === 4) {
            return inet_ntop(substr($bin, 0, 3)."\0").'/24';
        }
        return inet_ntop(substr($bin, 0, 6).str_repeat("\0", 10)).'/48';
    }

    public function inCidrs(string $ip, array $cidrs): bool
    {
        $ip = self::normalize($ip);
        if ($ip === null) {
            return false;
        }
        $bin = inet_pton($ip);
        foreach ($cidrs as $cidr) {
            if (is_string($cidr) && self::matches($bin, $cidr)) {
                return true;
            }
        }
        return false;
    }

    // Malformed CIDRs match nothing, so a typo never widens trust.
    private static function matches(string $bin, string $cidr): bool
    {
        $parts = explode('/', $cidr);
        if (count($parts) > 2) {
            return false;
        }
        $net = self::normalize($parts[0]);
        if ($net === null) {
            return false;
        }
        $netBin = inet_pton($net);
        $max = strlen($netBin) * 8;
        if (count($parts) === 2) {
            if (! preg_match('/^(0|[1-9][0-9]{0,2})$/D', $parts[1]) || (int) $parts[1] > $max) {
                return false;
            }
            $prefix = (int) $parts[1];
        } else {
            $prefix = $max;
        }
        if (strlen($bin) !== strlen($netBin)) {
            return false;
        }
        $bytes = intdiv($prefix, 8);
        if (substr($bin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
            return false;
        }
        $bits = $prefix % 8;
        if ($bits === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $bits)) & 0xFF;
        return (ord($bin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
    }

    // Canonical text form, or null if not a valid IP. IPv4-mapped IPv6 becomes IPv4.
    private static function normalize(string $ip): ?string
    {
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $bin = inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 16 && substr($bin, 0, 12) === str_repeat("\0", 10)."\xff\xff") {
            $bin = substr($bin, 12);
        }
        return inet_ntop($bin);
    }
}
