<?php
// The one-time share page (spec: One-time shares → Opening a share). One static shell for every id: nothing here
// depends on the id, which this template never receives. Only Kanboard's per-session CSRF token varies. A standalone
// page, outside Kanboard's layout, so no other plugin's layout script runs where a secret is decrypted.
// vault-reveal.js (T18, after vault-onetime.js) reads the id from the query string and k ‖ b from the #fragment, wipes
// the fragment from the address bar, POSTs {id, b, csrf_token} to data-reveal-url on Reveal, and decrypts in the page.
// Opening the page reveals nothing; the Reveal button does. Its messages are the data-msg-* attributes.
// There is no <form> and no named field (fix I1): nothing here can submit natively, which would put the passphrase in
// a GET query string and drop the #fragment. The script binds the button and Enter in the field itself.
?><!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<title><?= t('One-time secret') ?></title>
<?= $this->asset->css('plugins/Vault/Assets/css/vault.css') ?>
</head>
<body class="vault-reveal-page">
<main id="vault-reveal" class="vault-reveal" data-reveal-url="<?= $this->text->e($reveal_url) ?>" data-csrf="<?= $this->text->e($csrf) ?>" data-vault-https="<?= $https_ok ? '1' : '0' ?>"
      data-msg-incomplete="<?= t('This link is incomplete. Copy the whole link, including the part after #.') ?>"
      data-msg-need-passphrase="<?= t('This secret needs the passphrase the sender gave you. Enter it, then press Reveal again.') ?>"
      data-msg-wrong-passphrase="<?= t('Wrong passphrase. The secret is still here: check the passphrase and press Reveal again. Don\'t reload the page.') ?>"
      data-msg-decrypting="<?= t('Decrypting…') ?>"
      data-msg-not-available="<?= t('This secret is not available. It may have been viewed already, revoked, or expired.') ?>"
      data-msg-rate-limited="<?= t('Too many attempts. Wait a while, then try again.') ?>"
      data-msg-https="<?= t('This link only opens over HTTPS. Open it with https:// instead.') ?>"
      data-msg-damaged="<?= t('The secret could not be decrypted. Ask the sender for a new link.') ?>"
      data-msg-unsupported="<?= t('This browser could not run the decryption. Ask the sender for a new link and open it in a current browser.') ?>"
      data-msg-copied="<?= t('Copied.') ?>"
      data-msg-failed="<?= t('Something went wrong. Try again.') ?>">
    <h1><?= t('One-time secret') ?></h1>
    <?php if (! $https_ok): ?>
    <p class="vault-reveal-error" role="alert"><?= t('This link only opens over HTTPS. Open it with https:// instead.') ?></p>
    <?php endif ?>
    <p><?= t('Someone shared a secret with you. It can be viewed once: after you reveal it, the link stops working.') ?></p>
    <noscript><p class="vault-reveal-error"><?= t('Revealing the secret needs JavaScript.') ?></p></noscript>
    <div class="vault-reveal-form" data-vault-reveal-form>
        <label for="vault-reveal-passphrase"><?= t('Passphrase (only if the sender gave you one)') ?></label>
        <input type="password" id="vault-reveal-passphrase" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore spellcheck="false" data-vault-reveal-passphrase>
        <button type="button" class="btn btn-blue" data-vault-reveal-button><?= t('Reveal') ?></button>
    </div>
    <p class="vault-reveal-status" data-vault-reveal-status role="status" hidden></p>
    <div class="vault-reveal-result" data-vault-reveal-result hidden>
        <textarea readonly rows="8" aria-label="<?= t('Secret') ?>" data-vault-reveal-secret></textarea>
        <button type="button" class="btn" data-vault-reveal-copy><?= t('Copy') ?></button>
    </div>
</main>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-onetime.js') ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-reveal.js') ?>
</body>
</html>
