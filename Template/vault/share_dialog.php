<?php
// The sharing dialog (spec: UI → The sharing dialog): a user or an enrolled agent, Read or Edit, an optional expiry, and
// for a group the number of entries it covers. vault-share.js fills it from vault/sharing with textContent only and
// posts grants and revokes through KBVault.api. The form still posts natively with the CSRF token, never as a GET.
// The Server section (spec amendment) shows only when vault/sharing says Server is available (Server on, an entry):
// the consumers, the fields Server may read and optional rates, posted to vault/grant-server. The field checkboxes are
// the entry's top-level keys (ServerGrant::TOP_LEVEL), written out so each label is translated.
?>
<section class="vault-share" data-vault-share role="dialog" aria-labelledby="vault-share-title" hidden
         data-msg-agent="<?= t('agent') ?>"
         data-msg-read="<?= t('Read') ?>"
         data-msg-edit="<?= t('Edit') ?>"
         data-msg-until="<?= t('until') ?>"
         data-msg-revoke="<?= t('Revoke') ?>"
         data-msg-covered="<?= t('Sharing this group gives access to all {n} entries in it and in its sub-groups.') ?>"
         data-msg-confirm-group="<?= t('Share this group and all {n} entries in it?') ?>"
         data-msg-confirm-revoke="<?= t('Remove this person\'s access? The item is re-encrypted for everyone else.') ?>"
         data-msg-server="<?= t('Server') ?>"
         data-msg-field-hidden="<?= t('(a renamed or removed field)') ?>"
         data-msg-per-hour="<?= t('{n} reads an hour') ?>"
         data-msg-confirm-revoke-server="<?= t('Stop sharing this entry with Server? Server could have read it, so rotate the secret at its provider afterwards.') ?>"
         data-msg-no-candidates="<?= t('Nobody to share with: only enrolled people in your projects, and your agents, are listed.') ?>">
    <div class="vault-share-head">
        <h3 id="vault-share-title"><?= t('Share') ?> <span data-vault-share-label></span></h3>
        <button type="button" class="btn btn-small" data-vault-action="share-close"><?= t('Close') ?></button>
    </div>
    <p class="alert alert-info" data-vault-share-covered hidden></p>
    <form class="vault-form" data-vault-form="share" autocomplete="off" method="post" action="<?= $this->url->href('ShareGrantController', 'grant', ['plugin' => 'Vault']) ?>">
        <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
        <label for="vault-s-grantee"><?= t('Share with') ?></label>
        <select id="vault-s-grantee" name="grantee_id" data-vault-share-grantee required></select>
        <label for="vault-s-perm"><?= t('Permission') ?></label>
        <select id="vault-s-perm" name="perm" data-vault-share-perm>
            <option value="read"><?= t('Read') ?></option>
            <option value="edit"><?= t('Edit') ?></option>
        </select>
        <p class="vault-muted" data-vault-share-agent hidden><?= t('Agents get Read access only.') ?></p>
        <label for="vault-s-expires"><?= t('Expires (optional)') ?></label>
        <input type="datetime-local" id="vault-s-expires" name="expires" data-vault-share-expires>
        <div class="form-actions">
            <button type="submit" class="btn btn-blue"><?= t('Share') ?></button>
        </div>
    </form>
    <section class="vault-share-server" data-vault-share-server hidden>
        <h4><?= t('Share with Server') ?></h4>
        <p class="vault-muted"><?= t('Server reads only the fields you choose, for the services you name, and never sees anything else in your vault.') ?></p>
        <form class="vault-form" data-vault-form="share-server" autocomplete="off" method="post" action="<?= $this->url->href('ShareGrantController', 'grantServer', ['plugin' => 'Vault']) ?>">
            <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
            <label for="vault-s-consumers"><?= t('Services that may read it (comma or one per line)') ?></label>
            <textarea id="vault-s-consumers" name="consumers" rows="2" data-vault-server-consumers required></textarea>
            <fieldset>
                <legend><?= t('Fields') ?></legend>
                <label><input type="checkbox" name="fields[]" value="title" data-vault-server-field> <?= t('Title') ?></label>
                <label><input type="checkbox" name="fields[]" value="username" data-vault-server-field> <?= t('Username') ?></label>
                <label><input type="checkbox" name="fields[]" value="password" data-vault-server-field> <?= t('Password') ?></label>
                <label><input type="checkbox" name="fields[]" value="url" data-vault-server-field> <?= t('URL') ?></label>
                <label><input type="checkbox" name="fields[]" value="notes" data-vault-server-field> <?= t('Notes') ?></label>
                <label><input type="checkbox" name="fields[]" value="otp" data-vault-server-field> <?= t('OTP') ?></label>
            </fieldset>
            <label for="vault-s-custom"><?= t('Custom fields (names, comma-separated)') ?></label>
            <input type="text" id="vault-s-custom" name="custom_fields" data-vault-server-custom>
            <label for="vault-s-rate"><?= t('Reads an hour (optional)') ?></label>
            <input type="number" id="vault-s-rate" name="rate_per_hour" min="1" step="1" data-vault-server-rate>
            <label for="vault-s-burst"><?= t('Burst (optional)') ?></label>
            <input type="number" id="vault-s-burst" name="rate_burst" min="1" step="1" data-vault-server-burst>
            <p class="vault-muted"><?= t('Rates are capped at the maximum your administrator set.') ?></p>
            <div class="form-actions">
                <button type="submit" class="btn btn-blue"><?= t('Share with Server') ?></button>
            </div>
        </form>
    </section>
    <p class="vault-muted" data-vault-share-status role="status"></p>
    <p class="alert alert-error" data-vault-share-rotate hidden><?= t('Access removed. They may have copied what they could see: change those passwords and keys.') ?></p>
    <p class="alert alert-error" data-vault-share-server-rotate hidden><?= t('Server access removed. Server could have read this secret: rotate it at its provider (issue a new password, key or token there) and update the entry.') ?></p>
    <h4><?= t('Shared with') ?></h4>
    <ul class="vault-share-grants" data-vault-share-grants></ul>
    <p class="vault-muted" data-vault-share-none><?= t('Not shared with anyone directly.') ?></p>
</section>
