# Vault (Kanboard plugin)

An end-to-end encrypted password store for Kanboard: per-user keys, shared groups, agent access,
one-time share links and KeePassXC import and export. The server stores only ciphertext.

> Status: under development (v1.0.0 is not released). The repository stays private until the
> implementation passes its security reviews.

## Requirements

- Kanboard `>=1.2.47`, PHP `>=8.4`, SQLite, MySQL or Postgres.
- The PHP **sodium** extension (`sodium_crypto_pwhash`). Without it Vault registers no routes and
  shows administrators a notice instead. On the official Kanboard image, add it with
  `apk add php84-sodium`.

## Install

Unzip `Vault-<version>.zip` into `plugins/Vault/` (the zip's single top-level folder is `Vault`).
The `vault_*` tables are created on first load.

## Deleting users

Deleting a user removes their keys, sessions, grants and the vault objects they own. Records that
only name them as a contributor survive: entries they added to someone else's group, grants they
made and audit rows keep their data with that user reference set to empty (NULL).

## License

MIT
