<?php
// Hardware keys (spec: Hardware keys). WebAuthn needs JavaScript: vault-webauthn.js drives every ceremony through
// KBVault.api (POST + CSRF). The forms have no action, and their buttons are type="button", so nothing is ever
// submitted natively. Labels are escaped; the key list carries metadata only. No inline JS.
?>
<div class="page-header vault-header">
    <h2><?= t('Hardware keys') ?></h2>
    <ul class="vault-toolbar">
        <li><a class="btn" href="<?= $this->url->href('VaultController', 'index', ['plugin' => 'Vault']) ?>"><i class="fa fa-arrow-left" aria-hidden="true"></i> <?= t('Back to the vault') ?></a></li>
        <li><button type="button" class="btn" data-vault-action="lock"><i class="fa fa-lock" aria-hidden="true"></i> <?= t('Lock') ?></button></li>
    </ul>
</div>
<?= $this->render('Vault:vault/app', ['state' => 'unlocked', 'client' => $client, 'https_ok' => $https_ok]) ?>
<?= $this->asset->js('plugins/Vault/Assets/js/vault-webauthn.js') ?>
<noscript><p class="alert alert-error"><?= t('Hardware keys need JavaScript.') ?></p></noscript>
<?php if ($enrolment_required): ?>
<p class="alert alert-info vault-banner"><?= t('Your organisation requires two hardware keys. Add them to use your vault.') ?></p>
<?php endif ?>
<?php if ($rotation_queued): ?>
<p class="alert alert-info vault-banner" data-vault-hw-queued><?= t('Your vault needs new keys. Use "Rotate with my keys" below, with every key.') ?></p>
<?php endif ?>
<?php if ($rp_error !== ''): ?>
<p class="alert alert-error vault-banner" data-vault-hw-rp-error><?= $this->text->e($rp_error) ?></p>
<?php endif ?>

<section class="vault-card vault-section" data-vault-hw-keys>
    <h3><?= t('Your keys') ?></h3>
    <p><?= t('With two keys, unlocking needs your passphrase and one of your keys. Keep the second key somewhere safe: it is your spare.') ?></p>
    <?php if ($rp !== null): ?>
    <p class="form-help"><?= t('Keys are bound to') ?> <code data-vault-hw-rp><?= $this->text->e($rp['rp_id']) ?></code>. <?= t('Moving Kanboard to another address makes them unusable: remove them first.') ?></p>
    <?php endif ?>
    <?php if (empty($keys)): ?>
    <p data-vault-hw-none><?= t('No hardware keys yet.') ?></p>
    <?php endif ?>
    <ul class="vault-hw-list">
        <?php foreach ($keys as $key): ?>
        <li data-vault-hw-key="<?= $this->text->e($key['credential_id']) ?>">
            <strong><?= $this->text->e($key['label']) ?></strong>
            <span class="vault-muted"><?= t('added') ?> <?= $this->dt->date($key['created_at']) ?></span>
            <button type="button" class="btn btn-small" data-vault-hw-remove="<?= $this->text->e($key['credential_id']) ?>"><?= t('Remove') ?></button>
        </li>
        <?php endforeach ?>
    </ul>
    <form class="vault-form" data-vault-form="hwremove" hidden>
        <label for="vault-hw-remove-passphrase"><?= t('Your passphrase (needed when one key or none would be left)') ?></label>
        <input type="password" id="vault-hw-remove-passphrase" data-vault-hw-field="passphrase" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
    </form>
    <p class="vault-status" data-vault-hw-status="remove" role="status" hidden></p>
</section>

<?php if ($rp !== null && $https_ok): ?>
<section class="vault-card vault-section">
    <h3><?= t('Add a hardware key') ?></h3>
    <p><?= t('The key must support the PRF extension (most recent FIDO2 security keys do). When you add your second key, the keys you already have are asked for too, and your vault gets a new key.') ?></p>
    <form class="vault-form" data-vault-form="hwregister">
        <label for="vault-hw-label"><?= t('Name for this key') ?></label>
        <input type="text" id="vault-hw-label" data-vault-hw-field="label" maxlength="64" autocomplete="off" required>
        <label for="vault-hw-passphrase"><?= t('Your passphrase') ?></label>
        <input type="password" id="vault-hw-passphrase" data-vault-hw-field="passphrase" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore required>
        <p class="vault-status" data-vault-hw-status="register" role="status" hidden></p>
        <div class="form-actions"><button type="button" class="btn btn-blue" data-vault-action="hw-register"><?= t('Add key') ?></button></div>
    </form>
</section>

<section class="vault-card vault-section">
    <h3><?= t('Rotate with my keys') ?></h3>
    <p><?= t('Gives your vault a new key, optionally with a new passphrase. Every key is asked for in turn.') ?></p>
    <form class="vault-form" data-vault-form="hwrotate">
        <label for="vault-hw-rotate-passphrase"><?= t('Current passphrase') ?></label>
        <input type="password" id="vault-hw-rotate-passphrase" data-vault-hw-field="passphrase" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore required>
        <label for="vault-hw-rotate-new"><?= t('New passphrase (leave empty to keep it)') ?></label>
        <input type="password" id="vault-hw-rotate-new" data-vault-hw-field="new_passphrase" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <label for="vault-hw-rotate-confirm"><?= t('Type it again') ?></label>
        <input type="password" id="vault-hw-rotate-confirm" data-vault-hw-field="confirm" autocomplete="off" data-1p-ignore data-lpignore="true" data-bwignore>
        <p class="vault-status" data-vault-hw-status="rotate" role="status" hidden></p>
        <div class="form-actions"><button type="button" class="btn btn-blue" data-vault-action="hw-rotate"><?= t('Rotate my keys') ?></button></div>
    </form>
</section>
<?php endif ?>
