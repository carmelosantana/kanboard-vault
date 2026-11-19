<?php
namespace Kanboard\Plugin\Vault\Console;

use Closure;
use Kanboard\Console\BaseCommand;
use Kanboard\Plugin\Vault\Model\Purger;
use Pimple\Container;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

// `php cli vault:purge` (spec: Data model → Purge): the purge, unconditionally (the once-a-minute throttle is for
// the opportunistic run on vault requests). Kanboard's cron has no plugin hook, so the docs give a crontab line.
class PurgeCommand extends BaseCommand
{
    private Closure $purger;
    private Closure $clock;

    // $purger and $clock are test-only.
    public function __construct(Container $container, ?callable $purger = null, ?callable $clock = null)
    {
        $this->purger = $purger !== null ? Closure::fromCallable($purger) : static fn (): Purger => new Purger($container);
        $this->clock = $clock !== null ? Closure::fromCallable($clock) : static fn (): int => time();
        parent::__construct($container);
    }

    protected function configure(): void
    {
        $this
            ->setName('vault:purge')
            ->setDescription('Vault: purge expired grants, sessions, challenges, shares and old audit rows, and sweep deleted users');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $counts = ($this->purger)()->run((int) ($this->clock)(), true);
        unset($counts['ran']);
        foreach ($counts as $step => $n) {
            $output->writeln($step.': '.$n);
        }
        return 0;
    }
}
