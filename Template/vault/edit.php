<?php
// The entry editor. It posts to vault/save with the CSRF token even without vault.js (fix C1: a form holding a
// password never falls back to a GET). vault-browser.js fills it with the entry's metadata and the secrets it fetches
// through vault/field, and sends the payload as JSON.
?>
<form class="vault-form vault-editor" data-vault-form="edit" method="post" action="<?= $this->url->href('EntryController', 'save', ['plugin' => 'Vault']) ?>" hidden>
    <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
    <label for="vault-e-title"><?= t('Title') ?></label>
    <input type="text" id="vault-e-title" name="title" maxlength="1000" autocomplete="off">
    <label for="vault-e-username"><?= t('Username') ?></label>
    <input type="text" id="vault-e-username" name="username" autocomplete="off">
    <label for="vault-e-password"><?= t('Password') ?></label>
    <input type="password" id="vault-e-password" name="password" autocomplete="new-password">
    <label for="vault-e-url"><?= t('URL') ?></label>
    <input type="text" id="vault-e-url" name="url" autocomplete="off">
    <label for="vault-e-otp"><?= t('OTP seed') ?></label>
    <input type="text" id="vault-e-otp" name="otp" autocomplete="off" spellcheck="false">
    <label for="vault-e-notes"><?= t('Notes') ?></label>
    <textarea id="vault-e-notes" name="notes" rows="4"></textarea>
    <label for="vault-e-tags"><?= t('Tags (comma separated)') ?></label>
    <input type="text" id="vault-e-tags" name="tags" autocomplete="off">
    <label for="vault-e-expires"><?= t('Expires') ?></label>
    <input type="date" id="vault-e-expires" name="expires">
    <fieldset class="vault-custom-edit">
        <legend><?= t('Custom fields') ?></legend>
        <div data-vault-edit-fields></div>
        <button type="button" class="btn btn-small" data-vault-action="add-field"><?= t('Add field') ?></button>
    </fieldset>
    <div class="form-actions">
        <button type="submit" class="btn btn-blue"><?= t('Save') ?></button>
        <button type="button" class="btn" data-vault-action="cancel"><?= t('Cancel') ?></button>
    </div>
</form>
