<?php
namespace Kanboard\Plugin\Vault\Console;

use Closure;
use Kanboard\Console\BaseCommand;
use Kanboard\Plugin\Vault\Model\RecoveryService;
use Kanboard\Plugin\Vault\Model\RotationService;
use Kanboard\Plugin\Vault\Model\VaultException;
use Pimple\Container;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\StreamableInputInterface;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

// `php cli vault:org-recover <username>` (spec: Recovery, org recovery). The org secret and the new passphrase
// are read from stdin, one per line, never from argv (which ps and shell history show). On a terminal, echo is
// off while they are typed. Prompts go to stderr; neither secret is ever written out.
class OrgRecoverCommand extends BaseCommand
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
            ->setName('vault:org-recover')
            ->setDescription('Vault: recover a user\'s vault with the org key (reads the org secret, then the new passphrase, from stdin)')
            ->addArgument('username', InputArgument::REQUIRED, 'The Kanboard username to recover');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $stream = $input instanceof StreamableInputInterface && $input->getStream() !== null ? $input->getStream() : STDIN;
        $err = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
        $username = (string) $input->getArgument('username');
        $secret = $passphrase = '';
        try {
            $err->writeln('Org secret key:');
            $secret = self::readSecretLine($stream);
            $err->writeln('New vault passphrase for '.$username.':');
            $passphrase = self::readSecretLine($stream);
            $result = ($this->service)()->orgRecover($username, $secret, $passphrase);
        } catch (VaultException $e) {
            $output->writeln('<error>'.self::message($e->errorCode()).'</error>');
            return 1;
        } finally {
            sodium_memzero($secret);
            sodium_memzero($passphrase);
        }
        $output->writeln($result === RotationService::ROTATED
            ? 'Recovered. The user\'s keys were rotated and their hardware keys removed.'
            : 'Recovered. The key rotation is pending and finishes at the user\'s next unlock.');
        return 0;
    }

    private static function message(string $code): string
    {
        return match ($code) {
            'passphrase_weak' => 'The new passphrase is too weak: at least 14 characters, and not the username.',
            'passphrase_reuse' => 'The new passphrase must not be the user\'s login password.',
            'busy', 'busy_global' => 'Busy; try again shortly.',
            default => 'Org recovery failed.',
        };
    }

    /** @param resource $stream */
    private static function readSecretLine($stream): string
    {
        $tty = $stream === STDIN && function_exists('posix_isatty') && @posix_isatty(STDIN);
        if ($tty) {
            @shell_exec('stty -echo');
        }
        try {
            $line = fgets($stream);
        } finally {
            if ($tty) {
                @shell_exec('stty echo');
            }
        }
        return $line === false ? '' : rtrim($line, "\r\n");
    }
}
