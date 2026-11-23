<?php
namespace Kanboard\Plugin\Vault\Secrets;

// The consumer API (spec amendment): what an unattended plugin uses to read a secret an owner shared with Server.
// The container has it as 'vaultSecrets' only while Server sharing is on.
interface ServiceSecrets
{
    /** Server is on and its key provider opens its key now. */
    public function available(): bool;

    /** One field of one entry, for $consumer. Every refusal is a ServiceSecretException carrying only its reason. */
    public function read(string $consumer, #[\SensitiveParameter] string $ref, ?string $jobRef = null): SecretValue;

    /** Whether $ref would be readable, for settings pages: no title, no value, no audit row, no token spent. */
    public function describe(#[\SensitiveParameter] string $ref): RefStatus;
}
