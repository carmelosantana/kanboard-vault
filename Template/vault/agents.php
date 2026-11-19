<?php
// The owner's agents and their vault access (spec: Agents → Enrolment). The forms POST natively to their endpoints with
// the CSRF token, and vault-agents.js sends them through KBVault.api instead when it runs. A vault key is shown once:
// from JSON by vault-agents.js, or rendered here once after a native POST ($shown_key, no-store), as the ready-to-paste
// KANBOARD_VAULT_KEY= line. No inline JS.
$unlocked = $owner_state === 'unlocked';
$states = ['none' => t('No vault access'), 'enrolled' => t('Vault access enabled'), 'human' => t('Enrolled as a person: enable vault access to convert it')];
?>
<div class="page-header vault-header">
    <h2><?= t('Vault access for my agents') ?></h2>
    <ul class="vault-toolbar">
        <li><a class="btn" href="<?= $this->url->href('VaultController', 'index', ['plugin' => 'Vault']) ?>"><i class="fa fa-arrow-left" aria-hidden="true"></i> <?= t('Back to the vault') ?></a></li>
    </ul>
</div>
<?= $this->render('Vault:vault/app', ['state' => $unlocked ? 'unlocked' : 'locked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-agents.js') ?>
<?php if ($notice !== ''): ?>
<p class="alert alert-success vault-banner" role="status"><?= $this->text->e($notice) ?></p>
<?php endif ?>
<?php if ($error !== ''): ?>
<p class="alert alert-error vault-banner" role="alert"><?= $this->text->e($error) ?></p>
<?php endif ?>

<?php if (! $available): ?>
<p class="alert alert-info" data-vault-agents-unavailable><?= t('The Agents plugin is not installed, so there are no agents to give vault access.') ?></p>
<?php else: ?>
    <?php if ($owner_state === 'none'): ?>
    <p class="alert alert-info" data-vault-owner-state="none"><?= t('An agent gets vault access from its owner\'s vault. Set up your own vault first.') ?> <?= $this->url->link(t('Set up my vault'), 'VaultController', 'index', ['plugin' => 'Vault']) ?></p>
    <?php elseif ($owner_state === 'locked'): ?>
    <p class="alert alert-info" data-vault-owner-state="locked"><?= t('Unlock your vault to give an agent vault access or a new key.') ?> <?= $this->url->link(t('Unlock my vault'), 'VaultController', 'index', ['plugin' => 'Vault']) ?></p>
    <?php endif ?>

    <section class="vault-card vault-section" data-vault-agent-key-panel<?php if ($shown_key === ''): ?> hidden<?php endif ?>>
        <p><?= t('Copy this line into the agent\'s settings now. It won\'t be shown again.') ?></p>
        <p><code class="vault-agent-key" data-vault-agent-env><?php if ($shown_key !== ''): ?>KANBOARD_VAULT_KEY=<?= $this->text->e($shown_key) ?><?php endif ?></code></p>
        <div class="form-actions"><button type="button" class="btn" data-vault-action="agent-key-done"><?= t('I saved it') ?></button></div>
    </section>
    <p class="vault-status" data-vault-agent-status role="status" hidden></p>

    <?php if ($agents === []): ?>
    <p data-vault-no-agents><?= t('You have no agents.') ?></p>
    <?php else: ?>
    <table class="table-striped vault-agents">
        <thead><tr><th><?= t('Agent') ?></th><th><?= t('Vault access') ?></th><th></th><th><?= t('Secret reads an hour') ?></th></tr></thead>
        <tbody>
        <?php foreach ($agents as $a): ?>
            <?php $re = $a['state'] === 'enrolled'; ?>
            <tr data-vault-agent="<?= (int) $a['id'] ?>">
                <td><?= $this->text->e($a['username']) ?></td>
                <td data-vault-agent-state="<?= $this->text->e($a['state']) ?>"><?= $this->text->e($states[$a['state']] ?? '') ?></td>
                <td>
                    <form method="post" action="<?= $this->url->href('VaultAgentController', $re ? 'reenrol' : 'enrol', ['plugin' => 'Vault']) ?>" data-vault-form="<?= $re ? 'agent-reenrol' : 'agent-enrol' ?>">
                        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
                        <input type="hidden" name="agent_id" value="<?= (int) $a['id'] ?>">
                        <button type="submit" class="btn btn-blue"<?php if (! $unlocked): ?> disabled<?php endif ?>><?= $re ? t('Re-enrol (new key)') : t('Enable vault access') ?></button>
                    </form>
                </td>
                <td>
                    <form method="post" action="<?= $this->url->href('VaultAgentController', 'cap', ['plugin' => 'Vault']) ?>" data-vault-form="agent-cap">
                        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
                        <input type="hidden" name="agent_id" value="<?= (int) $a['id'] ?>">
                        <input type="number" name="cap" min="1" max="<?= (int) $cap_max ?>" value="<?= (int) min($a['read_cap'], $cap_max) ?>" aria-label="<?= t('Secret reads an hour') ?>">
                        <button type="submit" class="btn"<?php if (! $unlocked): ?> disabled<?php endif ?>><?= t('Save') ?></button>
                    </form>
                </td>
            </tr>
        <?php endforeach ?>
        </tbody>
    </table>
    <p class="form-help"><?= t('Your administrator allows at most %d secret reads an hour per agent.', (int) $cap_max) ?></p>
    <?php endif ?>
<?php endif ?>
