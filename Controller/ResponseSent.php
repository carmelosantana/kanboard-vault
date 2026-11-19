<?php
namespace Kanboard\Plugin\Vault\Controller;

use RuntimeException;

// Thrown after a guard (requirePostCsrf, requireUnlocked) has already sent the response, to stop the action.
// BaseVaultController::handle() swallows it.
final class ResponseSent extends RuntimeException
{
}
