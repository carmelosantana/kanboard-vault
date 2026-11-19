<?php
// The entry list. vault-browser.js fills it from vault/list (metadata only, 200 rows a page), with textContent only.
?>
<section class="vault-list" aria-label="<?= t('Entries') ?>">
    <div class="vault-list-head">
        <h3 class="vault-list-title" data-vault-list-title></h3>
        <button type="button" class="btn btn-small" data-vault-action="delete-group" hidden><?= t('Delete group') ?></button>
    </div>
    <table class="vault-table">
        <thead>
            <tr><th><?= t('Title') ?></th><th><?= t('Username') ?></th><th><?= t('URL') ?></th><th><?= t('Modified') ?></th></tr>
        </thead>
        <tbody data-vault-rows></tbody>
    </table>
    <p class="vault-muted" data-vault-list-empty><?= t('Select a group.') ?></p>
    <button type="button" class="btn" data-vault-action="more" hidden><?= t('More') ?></button>
</section>
