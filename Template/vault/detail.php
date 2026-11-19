<?php
// The detail pane: metadata from vault/entry only. Password, notes, the OTP seed and custom field values are fetched
// one at a time from vault/field when revealed or copied, and never rendered by the server. A [data-vault-onetime-field]
// button makes a one-time link of that field (vault-onetime.js).
?>
<div class="vault-entry" data-vault-detail hidden>
    <div class="vault-detail-head">
        <h3 data-field="title"></h3>
        <div class="vault-detail-actions">
            <button type="button" class="btn btn-small" data-vault-action="edit" hidden><?= t('Edit') ?></button>
            <button type="button" class="btn btn-small" data-vault-action="share-entry" data-vault-share-button hidden><?= t('Share') ?></button>
            <select class="vault-move" data-vault-move aria-label="<?= t('Move to group') ?>" hidden>
                <option value=""><?= t('Move to…') ?></option>
            </select>
            <button type="button" class="btn btn-small btn-red" data-vault-action="delete" hidden><?= t('Delete') ?></button>
        </div>
    </div>
    <dl class="vault-fields">
        <dt><?= t('Username') ?></dt>
        <dd><span data-field="username"></span> <button type="button" class="vault-icon" data-vault-copy="username" title="<?= t('Copy') ?>"><i class="fa fa-clipboard" aria-hidden="true"></i><span class="sr-only"><?= t('Copy') ?></span></button></dd>
        <dt data-vault-secret="password"><?= t('Password') ?></dt>
        <dd data-vault-secret="password"><span class="vault-secret" data-vault-value="password">••••••••</span>
            <button type="button" class="vault-icon" data-vault-reveal="password" title="<?= t('Show') ?>"><i class="fa fa-eye" aria-hidden="true"></i><span class="sr-only"><?= t('Show') ?></span></button>
            <button type="button" class="vault-icon" data-vault-copy="password" title="<?= t('Copy') ?>"><i class="fa fa-clipboard" aria-hidden="true"></i><span class="sr-only"><?= t('Copy') ?></span></button>
            <button type="button" class="vault-icon" data-vault-onetime-field="password" data-vault-onetime-label="<?= t('password') ?>" title="<?= t('One-time link') ?>"><i class="fa fa-link" aria-hidden="true"></i><span class="sr-only"><?= t('One-time link') ?></span></button></dd>
        <dt><?= t('URL') ?></dt>
        <dd><a data-field="url" data-href="url"></a> <button type="button" class="vault-icon" data-vault-copy="url" title="<?= t('Copy') ?>"><i class="fa fa-clipboard" aria-hidden="true"></i><span class="sr-only"><?= t('Copy') ?></span></button></dd>
        <dt data-vault-secret="otp"><?= t('OTP seed') ?></dt>
        <dd data-vault-secret="otp"><span class="vault-secret" data-vault-value="otp">••••••••</span>
            <button type="button" class="vault-icon" data-vault-reveal="otp" title="<?= t('Show') ?>"><i class="fa fa-eye" aria-hidden="true"></i><span class="sr-only"><?= t('Show') ?></span></button>
            <button type="button" class="vault-icon" data-vault-copy="otp" title="<?= t('Copy') ?>"><i class="fa fa-clipboard" aria-hidden="true"></i><span class="sr-only"><?= t('Copy') ?></span></button>
            <button type="button" class="vault-icon" data-vault-onetime-field="otp" data-vault-onetime-label="<?= t('OTP seed') ?>" title="<?= t('One-time link') ?>"><i class="fa fa-link" aria-hidden="true"></i><span class="sr-only"><?= t('One-time link') ?></span></button></dd>
        <dt data-vault-secret="notes"><?= t('Notes') ?></dt>
        <dd data-vault-secret="notes"><span class="vault-secret vault-notes" data-vault-value="notes">••••••••</span>
            <button type="button" class="vault-icon" data-vault-reveal="notes" title="<?= t('Show') ?>"><i class="fa fa-eye" aria-hidden="true"></i><span class="sr-only"><?= t('Show') ?></span></button>
            <button type="button" class="vault-icon" data-vault-onetime-field="notes" data-vault-onetime-label="<?= t('notes') ?>" title="<?= t('One-time link') ?>"><i class="fa fa-link" aria-hidden="true"></i><span class="sr-only"><?= t('One-time link') ?></span></button></dd>
        <dt><?= t('Tags') ?></dt>
        <dd data-field="tags"></dd>
        <dt><?= t('Expires') ?></dt>
        <dd data-field="expires"></dd>
        <dt><?= t('Modified') ?></dt>
        <dd data-field="modified"></dd>
    </dl>
    <dl class="vault-fields" data-vault-custom></dl>
</div>
<p class="vault-muted" data-vault-detail-empty><?= t('Select an entry.') ?></p>
