<?php
// The activity view (spec: Audit → Who sees what). vault-share.js fills it from vault/activity, which returns only the
// rows the viewer may see, a page at a time, and writes them with textContent only.
?>
<section class="vault-activity" data-vault-activity aria-labelledby="vault-activity-title" hidden>
    <div class="vault-list-head">
        <h3 id="vault-activity-title"><?= t('Activity') ?></h3>
        <button type="button" class="btn btn-small" data-vault-action="activity-close"><?= t('Close') ?></button>
    </div>
    <table class="vault-table">
        <thead>
            <tr><th><?= t('When') ?></th><th><?= t('Who') ?></th><th><?= t('Action') ?></th><th><?= t('Item') ?></th><th><?= t('Details') ?></th></tr>
        </thead>
        <tbody data-vault-activity-rows></tbody>
    </table>
    <p class="vault-muted" data-vault-activity-empty hidden><?= t('No activity yet.') ?></p>
    <button type="button" class="btn" data-vault-action="activity-more" hidden><?= t('More') ?></button>
</section>
