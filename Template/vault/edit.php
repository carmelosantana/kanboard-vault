<?php
// The entry editor. It posts to vault/save with the CSRF token even without vault.js (fix C1: a form holding a
// password never falls back to a GET). vault-browser.js fills it with the entry's metadata and the secrets it fetches
// through vault/field, and sends the payload as JSON. autocomplete="off" and the password-manager hints keep entry secrets
// out of the browser's password store (T12 review M3). vault-generator.js drives the generator panel; its controls
// carry data-vault-gen and no name, so they are never part of the entry.
?>
<form class="vault-form vault-editor" data-vault-form="edit" autocomplete="off" method="post" action="<?= $this->url->href('EntryController', 'save', ['plugin' => 'Vault']) ?>" hidden>
    <input type="hidden" name="csrf_token" value="<?= $this->text->e($client['csrf']) ?>">
    <label for="vault-e-title"><?= t('Title') ?></label>
    <input type="text" id="vault-e-title" name="title" maxlength="1000" autocomplete="off">
    <label for="vault-e-username"><?= t('Username') ?></label>
    <input type="text" id="vault-e-username" name="username" autocomplete="off">
    <label for="vault-e-password"><?= t('Password') ?></label>
    <div class="vault-password-row">
        <input type="password" id="vault-e-password" name="password" autocomplete="off" data-lpignore="true" data-1p-ignore data-bwignore spellcheck="false">
        <button type="button" class="btn btn-small" data-vault-action="generate" aria-expanded="false" aria-controls="vault-generator"><i class="fa fa-random" aria-hidden="true"></i> <?= t('Generate') ?></button>
    </div>
    <fieldset class="vault-generator" id="vault-generator" data-vault-generator data-vault-gen-target="vault-e-password"
              data-wordlist="<?= $this->text->e($this->url->dir().'plugins/Vault/Assets/vendor/eff_large_wordlist.txt') ?>"
              data-msg-bits="<?= t('bits') ?>"
              data-msg-invalid="<?= t('Pick at least one character class and a length from 8 to 128, or 4 to 20 words.') ?>"
              data-msg-wordlist="<?= t('The word list could not be loaded.') ?>" hidden>
        <legend><?= t('Generator') ?></legend>
        <label for="vault-g-mode"><?= t('Type') ?></label>
        <select id="vault-g-mode" data-vault-gen="mode">
            <option value="password"><?= t('Password') ?></option>
            <option value="passphrase"><?= t('Passphrase') ?></option>
        </select>
        <label for="vault-g-length"><?= t('Length') ?></label>
        <input type="number" id="vault-g-length" data-vault-gen="length" min="8" max="128" value="24">
        <label><input type="checkbox" data-vault-gen="lower" checked> a–z</label>
        <label><input type="checkbox" data-vault-gen="upper" checked> A–Z</label>
        <label><input type="checkbox" data-vault-gen="digits" checked> 0–9</label>
        <label><input type="checkbox" data-vault-gen="symbols" checked> !#$…</label>
        <label><input type="checkbox" data-vault-gen="excludeLookalikes"> <?= t('Exclude look-alikes (0 O 1 l I)') ?></label>
        <label for="vault-g-words"><?= t('Words') ?></label>
        <input type="number" id="vault-g-words" data-vault-gen="words" min="4" max="20" value="6">
        <label for="vault-g-sep"><?= t('Separator') ?></label>
        <input type="text" id="vault-g-sep" data-vault-gen="sep" value="-" maxlength="8" autocomplete="off">
        <p class="vault-muted" data-vault-gen-entropy aria-live="polite"></p>
        <button type="button" class="btn btn-small" data-vault-action="regenerate"><?= t('Generate again') ?></button>
    </fieldset>
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
