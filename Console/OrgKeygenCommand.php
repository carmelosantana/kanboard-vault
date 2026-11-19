<?php
namespace Kanboard\Plugin\Vault\Console;

use Closure;
use Kanboard\Console\BaseCommand;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\VaultException;
use Pimple\Container;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

// `php cli vault:org-keygen` (spec: Recovery, the org key): prints the org secret key once and stores only the
// public key. Refuses when a key exists, unless --replace.
class OrgKeygenCommand extends BaseCommand
{
    private Closure $service;

    // $service is test-only: a factory for the RecoveryService.
    public function __construct(Container $container, ?callable $service = null)
    {
        $this->service = $service !== null ? Closure::fromCallable($service) : static fn (): RecoveryService => new RecoveryService($container);
        parent::__construct($container);
    }

    protected function configure(): void
    {
        $this
            ->setName('vault:org-keygen')
            ->setDescription('Vault: generate the org recovery key (prints the secret once; stores only the public key)')
            ->addOption('replace', null, InputOption::VALUE_NONE, 'Replace the existing org key; org wraps sealed to it are deleted and their users rotate at their next unlock');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $display = ($this->service)()->orgKeygen((bool) $input->getOption('replace'));
        } catch (VaultException $e) {
            $output->writeln($e->errorCode() === 'org_key_exists'
                ? '<error>An org key already exists. Use --replace to replace it.</error>'
                : '<error>Org key generation failed.</error>');
            return 1;
        }
        $output->writeln('Org recovery secret key. It is shown once and stored nowhere; keep it offline:');
        $output->writeln($display);
        sodium_memzero($display);
        return 0;
    }
}
