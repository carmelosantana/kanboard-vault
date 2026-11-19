<?php
// The one-time share page (spec: One-time shares → Opening a share). One static shell for every id: nothing here
// depends on the id, which this template never receives. Only Kanboard's per-session CSRF token varies. A standalone
// page, outside Kanboard's layout, so no other plugin's layout script runs where a secret is decrypted.
// vault-reveal.js (T18) reads the id from the query string and k ‖ b from the #fragment, POSTs {id, b, csrf_token}
// to data-reveal-url, and decrypts in the page. Opening the page reveals nothing; the Reveal button does.
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
<main id="vault-reveal" class="vault-reveal" data-reveal-url="<?= $this->text->e($reveal_url) ?>" data-csrf="<?= $this->text->e($csrf) ?>" data-vault-https="<?= $https_ok ? '1' : '0' ?>">
    <h1><?= t('One-time secret') ?></h1>
    <?php if (! $https_ok): ?>
    <p class="vault-reveal-error" role="alert"><?= t('This link only opens over HTTPS. Open it with https:// instead.') ?></p>
    <?php endif ?>
    <p><?= t('Someone shared a secret with you. It can be viewed once: after you reveal it, the link stops working.') ?></p>
    <noscript><p class="vault-reveal-error"><?= t('Revealing the secret needs JavaScript.') ?></p></noscript>
    <form class="vault-reveal-form" data-vault-reveal-form>
        <label for="vault-reveal-passphrase"><?= t('Passphrase (only if the sender gave you one)') ?></label>
        <input type="password" id="vault-reveal-passphrase" name="passphrase" autocomplete="off" spellcheck="false">
        <button type="submit" class="btn btn-blue" data-vault-reveal-button><?= t('Reveal') ?></button>
    </form>
    <p class="vault-reveal-status" data-vault-reveal-status role="status" hidden></p>
    <div class="vault-reveal-result" data-vault-reveal-result hidden>
        <textarea readonly rows="8" aria-label="<?= t('Secret') ?>" data-vault-reveal-secret></textarea>
        <button type="button" class="btn" data-vault-reveal-copy><?= t('Copy') ?></button>
    </div>
</main>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-reveal.js') ?>
</body>
</html>
