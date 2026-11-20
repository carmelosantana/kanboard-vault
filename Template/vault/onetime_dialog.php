<?php
// The one-time link dialog (spec: One-time shares → Creating a share). vault-onetime.js encrypts in the browser and
// sends the server only the ciphertext and BLAKE2b(b); k and b stay in the link's #fragment. There is no <form> and no
// named field, so nothing here can be submitted natively (a GET would put the text or passphrase in a URL). The
// expiry choices are the ones the admin's maximum allows ($share_expiries, ShareModel::EXPIRIES keys).
$share_expiries = $share_expiries ?? ['1h', '1d', '7d'];
$expiry_names = ['1h' => t('1 hour'), '1d' => t('1 day'), '7d' => t('7 days')];
?>
<section class="vault-share vault-onetime" data-vault-onetime role="dialog" aria-labelledby="vault-ot-title" hidden
         data-wordlist="<?= $this->text->e($this->url->dir().'plugins/Vault/Assets/vendor/eff_large_wordlist.txt') ?>"
         data-msg-field="<?= t('Shares the {field} of {title}. It is read when you create the link and not shown here.') ?>"
         data-msg-working="<?= t('Encrypting…') ?>"
         data-msg-empty="<?= t('There is nothing to share.') ?>"
         data-msg-error-empty="<?= t('There is nothing to share.') ?>"
         data-msg-no-passphrase="<?= t('Enter a passphrase, or untick the passphrase option.') ?>"
         data-msg-error-payload_too_large="<?= t('A one-time link holds at most 64 KB.') ?>"
         data-msg-error-payload_invalid="<?= t('The link could not be created. Pick another expiry.') ?>"
         data-msg-error-rate_limited="<?= t('Too many attempts. Wait a while, then try again.') ?>"
         data-msg-error-locked="<?= t('Your vault is locked. Unlock it, then try again.') ?>"
         data-msg-error-worker_failed="<?= t('This browser could not run the encryption.') ?>"
         data-msg-wordlist="<?= t('The word list could not be loaded.') ?>"
         data-msg-failed="<?= t('Something went wrong.') ?>"
         data-msg-send-passphrase="<?= t('Send the passphrase separately from the link, by another channel.') ?>"
         data-msg-no-label="<?= t('(no label)') ?>"
         data-msg-expires="<?= t('expires') ?>"
         data-msg-with-passphrase="<?= t('passphrase') ?>"
         data-msg-revoke="<?= t('Revoke') ?>"
         data-msg-revoked="<?= t('Link revoked.') ?>"
         data-msg-confirm-revoke="<?= t('Revoke this link? Nobody will be able to open it.') ?>">
    <div class="vault-share-head">
        <h3 id="vault-ot-title"><?= t('One-time link') ?></h3>
        <button type="button" class="btn btn-small" data-vault-action="onetime-close"><?= t('Close') ?></button>
    </div>
    <div class="vault-form" data-vault-ot-form>
        <p class="vault-muted" data-vault-ot-source hidden></p>
        <label for="vault-ot-text" data-vault-ot-text-label><?= t('Text to share (it never enters your vault)') ?></label>
        <textarea id="vault-ot-text" rows="5" autocomplete="off" spellcheck="false" data-vault-ot-text></textarea>
        <label for="vault-ot-label"><?= t('Label (only you see it)') ?></label>
        <input type="text" id="vault-ot-label" maxlength="100" autocomplete="off" data-vault-ot-label>
        <label for="vault-ot-expiry"><?= t('Expires after') ?></label>
        <select id="vault-ot-expiry" data-vault-ot-expiry>
            <?php foreach ($share_expiries as $key): ?>
            <option value="<?= $this->text->e($key) ?>" <?= $key === '1d' ? 'selected' : '' ?>><?= $this->text->e($expiry_names[$key] ?? $key) ?></option>
            <?php endforeach ?>
        </select>
        <label><input type="checkbox" data-vault-ot-use-pass> <?= t('Also require a passphrase') ?></label>
        <div data-vault-ot-pass-row hidden>
            <label for="vault-ot-pass"><?= t('Passphrase') ?></label>
            <input type="text" id="vault-ot-pass" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore spellcheck="false" data-vault-ot-pass>
            <button type="button" class="btn btn-small" data-vault-action="onetime-generate"><i class="fa fa-random" aria-hidden="true"></i> <?= t('Generate again') ?></button>
            <p class="form-help"><?= t('A weak passphrase can be guessed offline. The suggested one has 5 random words.') ?></p>
        </div>
        <div class="form-actions">
            <button type="button" class="btn btn-blue" data-vault-action="onetime-create"><?= t('Create link') ?></button>
        </div>
    </div>
    <p class="vault-muted" data-vault-ot-status role="status" hidden></p>
    <div data-vault-ot-result hidden>
        <label for="vault-ot-link"><?= t('Link (shown only now; it opens once)') ?></label>
        <input type="text" id="vault-ot-link" readonly autocomplete="off" data-vault-ot-link>
        <button type="button" class="btn btn-small" data-vault-action="onetime-copy"><?= t('Copy') ?></button>
    </div>
    <h4><?= t('My one-time links') ?></h4>
    <ul class="vault-share-grants" data-vault-ot-list></ul>
    <p class="vault-muted" data-vault-ot-none><?= t('No live links.') ?></p>
</section>
