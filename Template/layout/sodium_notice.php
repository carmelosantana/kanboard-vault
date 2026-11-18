<?php if ($this->user->isAdmin()): ?>
<p class="alert alert-error"><?= t('Vault is disabled: PHP is missing the sodium extension (sodium_crypto_pwhash). Install php84-sodium and reload.') ?></p>
<?php endif ?>
