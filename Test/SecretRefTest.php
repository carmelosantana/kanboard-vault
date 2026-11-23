<?php
require_once 'tests/units/Base.php';

use Kanboard\Plugin\Vault\Secrets\SecretRef;
use KanboardTests\units\Base;

// Spec amendment: Consumer API → refs. vault://<entry_id>/<field>: an id of 1 to 18 digits with no leading zero, and a
// percent-encoded field that decodes to a top-level key or a custom name (valid UTF-8, 1..128 bytes, no control
// characters). P1 has no versions, so '@…' is refused. Kills: a looser id pattern (leading zero, 19 digits), the field
// checked before decoding, a decoded control character or '/' handled wrong.
class SecretRefTest extends Base
{
    public static function valid(): array
    {
        return [
            'top-level' => ['vault://7/password', 7, 'password', true],
            'title is top-level (R5)' => ['vault://1/title', 1, 'title', true],
            'custom, encoded space' => ['vault://42/My%20Token', 42, 'My Token', false],
            'custom, %2F decodes to a slash' => ['vault://42/a%2Fb', 42, 'a/b', false],
            'custom, UTF-8' => ['vault://3/cl%C3%A9', 3, 'clé', false],
            '18 digits' => ['vault://123456789012345678/otp', 123456789012345678, 'otp', true],
            'percent-encoded top-level name' => ['vault://5/%70assword', 5, 'password', true],
        ];
    }

    /** @dataProvider valid */
    public function testValidRefs(string $ref, int $id, string $field, bool $top): void
    {
        $r = SecretRef::parse($ref);
        $this->assertNotNull($r);
        $this->assertSame([$id, $field, $top], [$r->entryId, $r->field, $r->isTopLevel()]);
    }

    public static function invalid(): array
    {
        return [
            'leading zero' => ['vault://01/x'],
            'zero' => ['vault://0/x'],
            '19 digits' => ['vault://1234567890123456789/x'],
            'empty field' => ['vault://5/'],
            'no field' => ['vault://5'],
            'version (P1)' => ['vault://5/password@2'],
            'query' => ['vault://5/password?x=1'],
            'fragment' => ['vault://5/password#x'],
            'raw slash' => ['vault://5/a/b'],
            'space' => ['vault://5/a b'],
            'trailing newline' => ["vault://5/password\n"],
            'NUL' => ['vault://5/a%00b'],
            'control character' => ['vault://5/a%1Fb'],
            'DEL' => ['vault://5/a%7Fb'],
            'invalid UTF-8' => ['vault://5/%C3'],
            'over 128 bytes decoded' => ['vault://5/'.str_repeat('%41', 129)],
            'over 384 characters' => ['vault://5/'.str_repeat('a', 385)],
            'wrong scheme' => ['vaults://5/password'],
            'one slash' => ['vault:/x'],
            'empty' => [''],
            'negative id' => ['vault://-1/password'],
        ];
    }

    /** @dataProvider invalid */
    public function testInvalidRefsAreNull(string $ref): void
    {
        $this->assertNull(SecretRef::parse($ref));
    }

    public function testFieldOfExactlyTheLimits(): void
    {
        $this->assertSame(str_repeat('A', 128), SecretRef::parse('vault://5/'.str_repeat('%41', 128))?->field);
        $this->assertNull(SecretRef::parse('vault://5/'.str_repeat('a', 129)), '129 bytes, 129 characters');
    }
}
