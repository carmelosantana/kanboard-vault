<?php
require_once 'tests/units/Base.php';

use Kanboard\Plugin\Vault\Model\Correlation;
use PHPUnit\Framework\TestCase;

// Spec amendment: the 128-bit correlation id ties one request's or one job's audit rows together.
class CorrelationTest extends TestCase
{
    // Kills: a short or non-hex id; a new id per call; begin() not changing the id or not returning it.
    public function testIdIsStableUntilBegin(): void
    {
        $id = Correlation::id();
        $this->assertMatchesRegularExpression(Correlation::PATTERN, $id);
        $this->assertSame($id, Correlation::id());
        $next = Correlation::begin();
        $this->assertMatchesRegularExpression(Correlation::PATTERN, $next);
        $this->assertNotSame($id, $next);
        $this->assertSame($next, Correlation::id());
    }

    // Kills: a pattern that takes upper case, a newline or another length.
    public function testPatternIsExact(): void
    {
        foreach ([str_repeat('ab', 16)] as $ok) {
            $this->assertMatchesRegularExpression(Correlation::PATTERN, $ok);
        }
        foreach ([str_repeat('AB', 16), str_repeat('ab', 16)."\n", str_repeat('a', 31), str_repeat('a', 33), str_repeat('g', 32)] as $bad) {
            $this->assertDoesNotMatchRegularExpression(Correlation::PATTERN, $bad);
        }
    }
}
