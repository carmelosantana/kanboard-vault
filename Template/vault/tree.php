<?php
// The groups pane. vault-browser.js fills it from vault/tree, with textContent only; nothing decrypted is rendered here.
?>
<nav class="vault-tree" aria-label="<?= t('Groups') ?>">
    <h3 class="vault-tree-head"><?= t('My vault') ?></h3>
    <ul class="vault-tree-list" data-vault-tree="own"></ul>
    <h3 class="vault-tree-head"><?= t('Shared with me') ?></h3>
    <ul class="vault-tree-list" data-vault-tree="shared"></ul>
    <button type="button" class="vault-node" data-vault-action="shared-entries" hidden><?= t('Entries shared with me') ?></button>
    <button type="button" class="vault-node vault-activity-link" data-vault-action="activity"><i class="fa fa-history" aria-hidden="true"></i> <?= t('Activity') ?></button>
</nav>
