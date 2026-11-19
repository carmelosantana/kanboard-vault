<?php
// The T13 generator offered for a new vault passphrase (enrolment, passphrase change). It fills both the new
// passphrase and its confirmation (#vault-new-passphrase, #vault-new-confirm) and shows the value in
// [data-vault-gen-show] so the user can write it down. Passphrase mode comes first: a vault passphrase must be
// typed from memory. Its controls carry data-vault-gen and no name, so they are never part of the form.
?>
<button type="button" class="btn btn-small" data-vault-action="generate" aria-expanded="false" aria-controls="vault-pgen"><i class="fa fa-random" aria-hidden="true"></i> <?= t('Suggest a passphrase') ?></button>
<fieldset class="vault-generator" id="vault-pgen" data-vault-generator data-vault-gen-target="vault-new-passphrase" data-vault-gen-confirm="vault-new-confirm"
          data-wordlist="<?= $this->text->e($this->url->dir().'plugins/Vault/Assets/vendor/eff_large_wordlist.txt') ?>"
          data-msg-bits="<?= t('bits') ?>"
          data-msg-invalid="<?= t('Pick at least one character class and a length from 8 to 128, or 4 to 20 words.') ?>"
          data-msg-wordlist="<?= t('The word list could not be loaded.') ?>" hidden>
    <legend><?= t('Generator') ?></legend>
    <label for="vault-pg-mode"><?= t('Type') ?></label>
    <select id="vault-pg-mode" data-vault-gen="mode">
        <option value="passphrase"><?= t('Passphrase') ?></option>
        <option value="password"><?= t('Password') ?></option>
    </select>
    <label for="vault-pg-words"><?= t('Words') ?></label>
    <input type="number" id="vault-pg-words" data-vault-gen="words" min="4" max="20" value="6">
    <label for="vault-pg-sep"><?= t('Separator') ?></label>
    <input type="text" id="vault-pg-sep" data-vault-gen="sep" value="-" maxlength="8" autocomplete="off">
    <label for="vault-pg-length"><?= t('Length') ?></label>
    <input type="number" id="vault-pg-length" data-vault-gen="length" min="8" max="128" value="24">
    <label><input type="checkbox" data-vault-gen="lower" checked> a–z</label>
    <label><input type="checkbox" data-vault-gen="upper" checked> A–Z</label>
    <label><input type="checkbox" data-vault-gen="digits" checked> 0–9</label>
    <label><input type="checkbox" data-vault-gen="symbols" checked> !#$…</label>
    <label><input type="checkbox" data-vault-gen="excludeLookalikes"> <?= t('Exclude look-alikes (0 O 1 l I)') ?></label>
    <p><?= t('Your new passphrase:') ?> <code class="vault-gen-show" data-vault-gen-show></code></p>
    <p class="vault-muted" data-vault-gen-entropy aria-live="polite"></p>
    <p class="form-help"><?= t('Write it down until you know it by heart. It is filled into both fields.') ?></p>
    <button type="button" class="btn btn-small" data-vault-action="regenerate"><?= t('Generate again') ?></button>
</fieldset>
