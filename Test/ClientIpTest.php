<?php
require_once 'tests/units/Base.php';

use Kanboard\Core\Http\Request;
use Kanboard\Plugin\Vault\Model\ClientIp;
use KanboardTests\units\Base;

class ClientIpTest extends Base
{
    private function resolve(array $server, array $trusted): string
    {
        return (new ClientIp($this->container))->resolve(new Request($this->container, $server), $trusted);
    }

    public function testUntrustedRemoteIgnoresHeaders(): void
    {
        $server = ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_CF_CONNECTING_IP' => '1.1.1.1', 'HTTP_X_FORWARDED_FOR' => '2.2.2.2'];
        $this->assertSame('203.0.113.9', $this->resolve($server, []));
        $this->assertSame('203.0.113.9', $this->resolve($server, ['10.0.0.0/8', '127.0.0.1/32']));
    }

    public function testCfConnectingIpExactlyOne(): void
    {
        $trusted = ['127.0.0.1/32'];
        $base = ['REMOTE_ADDR' => '127.0.0.1'];
        $this->assertSame('198.51.100.7', $this->resolve($base + ['HTTP_CF_CONNECTING_IP' => '198.51.100.7'], $trusted));
        $this->assertSame('198.51.100.7', $this->resolve($base + ['HTTP_CF_CONNECTING_IP' => ' 198.51.100.7 '], $trusted));
        $this->assertSame('2001:db8::1', $this->resolve($base + ['HTTP_CF_CONNECTING_IP' => '2001:DB8:0::1'], $trusted));
        foreach (['1.2.3.4, 5.6.7.8', '1.2.3.4 5.6.7.8', 'nope', '1.2.3.4:80', '999.1.1.1', '  '] as $bad) {
            $this->assertSame('127.0.0.1', $this->resolve($base + ['HTTP_CF_CONNECTING_IP' => $bad, 'HTTP_X_FORWARDED_FOR' => '9.9.9.9'], $trusted), "CF '$bad'");
        }
    }

    public function testCfAbsentFallsBackToXff(): void
    {
        $server = ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '9.9.9.9'];
        $this->assertSame('9.9.9.9', $this->resolve($server, ['127.0.0.1/32']));
    }

    public function testXffWalksRightSkippingTrusted(): void
    {
        $server = ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6, 9.9.9.9, 10.0.0.2'];
        $this->assertSame('9.9.9.9', $this->resolve($server, ['10.0.0.0/8']));
    }

    public function testXffEdgeCases(): void
    {
        $trusted = ['10.0.0.0/8'];
        $remote = ['REMOTE_ADDR' => '10.0.0.1'];
        // No header: the trusted proxy itself is the client.
        $this->assertSame('10.0.0.1', $this->resolve($remote, $trusted));
        // A malformed hop before any untrusted address: fall back to REMOTE_ADDR.
        $this->assertSame('10.0.0.1', $this->resolve($remote + ['HTTP_X_FORWARDED_FOR' => '6.6.6.6, garbage, 10.0.0.2'], $trusted));
        // A malformed entry left of the client is client-controlled and never read.
        $this->assertSame('9.9.9.9', $this->resolve($remote + ['HTTP_X_FORWARDED_FOR' => 'garbage, 9.9.9.9'], $trusted));
        // Every hop trusted: the furthest one reached.
        $this->assertSame('10.1.1.1', $this->resolve($remote + ['HTTP_X_FORWARDED_FOR' => '10.1.1.1,10.0.0.2'], $trusted));
    }

    public function testIpv6CidrsAndMappedAddresses(): void
    {
        $trusted = ['fd00::/8', '172.16.0.0/12'];
        $this->assertSame('2001:db8::5', $this->resolve(['REMOTE_ADDR' => 'fd12::1', 'HTTP_X_FORWARDED_FOR' => '2001:db8::5, fd00::9'], $trusted));
        // fe00:: is outside fd00::/8 by one bit.
        $this->assertSame('fe00::1', $this->resolve(['REMOTE_ADDR' => 'fe00::1', 'HTTP_X_FORWARDED_FOR' => '2001:db8::5'], $trusted));
        // An IPv4-mapped IPv6 sender matches the IPv4 range; results are plain IPv4.
        $this->assertSame('8.8.8.8', $this->resolve(['REMOTE_ADDR' => '::ffff:172.20.0.3', 'HTTP_X_FORWARDED_FOR' => '::ffff:8.8.8.8'], $trusted));
        // 172.32.0.1 is just outside 172.16.0.0/12.
        $this->assertSame('172.32.0.1', $this->resolve(['REMOTE_ADDR' => '172.32.0.1', 'HTTP_X_FORWARDED_FOR' => '8.8.8.8'], $trusted));
    }

    public function testCidrParsing(): void
    {
        $ip = new ClientIp($this->container);
        $this->assertTrue($ip->inCidrs('192.168.1.200', ['192.168.1.0/24']));
        $this->assertFalse($ip->inCidrs('192.168.2.1', ['192.168.1.0/24']));
        $this->assertTrue($ip->inCidrs('192.168.1.7', ['192.168.1.7']), 'a bare address is a /32');
        $this->assertTrue($ip->inCidrs('8.8.8.8', ['0.0.0.0/0']));
        $this->assertTrue($ip->inCidrs('10.0.0.1', ['10.0.0.1/31']));
        $this->assertFalse($ip->inCidrs('10.0.0.2', ['10.0.0.1/31']));
        $this->assertFalse($ip->inCidrs('::1', ['127.0.0.0/8']), 'families never cross');
        $this->assertFalse($ip->inCidrs('127.0.0.1', ['::/0']));
        // Malformed entries trust nothing.
        foreach (['10.0.0.0/33', '10.0.0.0/-1', '10.0.0.0/', '10.0.0.0/8x', 'x/8', '', '::/129', '10.0.0.0/08 '] as $bad) {
            $this->assertFalse($ip->inCidrs('10.0.0.1', [$bad]), "'$bad'");
        }
    }

    public function testInvalidRemoteAddrResolvesEmpty(): void
    {
        $this->assertSame('', $this->resolve([], ['0.0.0.0/0']));
        $this->assertSame('', $this->resolve(['REMOTE_ADDR' => 'unix:'], []));
    }

    public function testTruncate(): void
    {
        $ip = new ClientIp($this->container);
        $this->assertSame('203.0.113.0/24', $ip->truncate('203.0.113.77'));
        $this->assertSame('2001:db8:abcd::/48', $ip->truncate('2001:db8:abcd:12:34::1'));
        $this->assertSame('2001:db8:ab00::/48', $ip->truncate('2001:0db8:ab00:ffff::'));
        $this->assertSame('192.0.2.0/24', $ip->truncate('::ffff:192.0.2.200'));
        $this->assertSame('', $ip->truncate('not an ip'));
        $this->assertSame('', $ip->truncate(''));
    }
}
