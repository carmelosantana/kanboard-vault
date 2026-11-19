<?php
// The sharing dialog (spec: UI → The sharing dialog): a user or an enrolled agent, Read or Edit, an optional expiry, and
// for a group the number of entries it covers. vault-share.js fills it from vault/sharing with textContent only and
// posts grants and revokes through KBVault.api. The form still posts natively with the CSRF token, never as a GET.
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
    <p class="vault-muted" data-vault-share-status role="status"></p>
    <p class="alert alert-error" data-vault-share-rotate hidden><?= t('Access removed. They may have copied what they could see: change those passwords and keys.') ?></p>
    <h4><?= t('Shared with') ?></h4>
    <ul class="vault-share-grants" data-vault-share-grants></ul>
    <p class="vault-muted" data-vault-share-none><?= t('Not shared with anyone directly.') ?></p>
</section>
