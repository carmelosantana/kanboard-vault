# Vault (Kanboard plugin)

An encrypted password store for Kanboard, modelled on KeePassXC: a groups tree, an entry list, copy to clipboard
and a password generator. Each user has their own keys behind a vault passphrase that is separate from their
Kanboard login. Entries can be shared with teammates (Read or Edit) and with API agents, sent to anyone as a
one-time link, and imported from or exported to KeePassXC.

The server stores only ciphertext. A stolen database backup, `config.php` included, opens nothing without a user's
passphrase (and hardware key, if they enrolled one). The server decrypts in memory while it serves an unlocked user,
so Vault does not defend against a compromised server. [docs/security.md](docs/security.md) has the threat model.

> Status: v1.0.0 is not released yet.

## Requirements

- Kanboard `>=1.2.47` and PHP `>=8.4`.
- SQLite, MySQL 8.0 or later, MariaDB 10.2.4 or later, or Postgres.
- The PHP **sodium** extension (`sodium_crypto_pwhash`). Without it Vault registers no routes and shows
  administrators a notice instead.
- HTTPS. Vault refuses to unlock over plain HTTP.

## Install

### The Docker image, with sodium

The official `kanboard/kanboard` image doesn't ship sodium. Build a small image on top of it:

```dockerfile
FROM kanboard/kanboard:v1.2.47
# Keep every php84 package on one version, so the core and php84-sodium match.
RUN apk upgrade --no-cache php84 'php84-*' && apk add --no-cache php84-sodium
```

Check it with `docker exec <container> php -m | grep sodium`. On other installs, install your distribution's PHP
sodium package.

### The plugin

Unzip `Vault-<version>.zip` into `plugins/Vault/` (the zip's single top-level folder is `Vault`). The `vault_*`
tables are created on first load. Vault recommends the **Agents** plugin, which agent access needs; everything else
works without it.

Then open **Settings → Vault** and work through the deployment checks at the bottom of the page.

### Deployment checks

Vault's guarantees hold only when these are true. The settings page checks each one:

| Check | Why |
|---|---|
| HTTPS | The vault cookie is `__Host-`, `Secure` and `HttpOnly`; over plain HTTP Vault won't unlock. |
| `PLUGIN_INSTALLER` is off (Kanboard's default) | An admin who can install plugins can replace Vault's code. |
| The web server can't write to the plugin directory | Same reason. |
| Proxy headers | Forwarding headers from a sender you haven't trusted are ignored (see below). |
| sodium | Required for every key operation. |
| The Argon2 lock directory (`DATA_DIR/vault`) is `0700` or tighter | It holds the lock files that cap concurrent key derivations. |

## Behind a reverse proxy or Cloudflare Tunnel

Vault works out the client IP and HTTPS itself, because its rate limits and its HTTPS gate must not trust headers
a client can set.

- **Trusted proxy addresses** (`vault_trusted_proxy_cidrs`, Settings → Vault) lists the addresses allowed to send
  forwarding headers. It is empty by default, and then Vault uses `REMOTE_ADDR` and ignores every forwarding header,
  `X-Forwarded-Proto` included.
- Add your proxy's address: for example `127.0.0.1/32` when `cloudflared` or nginx runs on the same host, or the
  Docker network's CIDR when it runs in another container. Without it, a TLS-terminating proxy that talks plain HTTP
  to Kanboard looks like plain HTTP, and Vault won't unlock. Every client would also share the proxy's rate-limit
  bucket.
- Write IPv4 ranges as IPv4. An IPv4-mapped IPv6 range (`::ffff:a.b.c.d/n`) matches nothing, and the settings page
  says so.
- Set Kanboard's own `TRUSTED_PROXY_HEADERS` too, for the rest of Kanboard.
- **Cloudflare Tunnel.** Vault reads `CF-Connecting-IP` from a trusted address. It must hold exactly one valid IP;
  anything else falls back to `REMOTE_ADDR`. Make sure the origin can be reached only through the tunnel.
- **The Host header.** Hardware-key ceremonies refuse a request whose Host isn't the host of Kanboard's
  *Application URL* (`rp_id_mismatch`). `cloudflared` forwards the original Host unless `httpHostHeader` is set in
  its ingress rule, so leave that unset, or set it to the public host name.

## Scheduled purge

Kanboard's cron has no plugin hook. Vault purges opportunistically on vault requests, at most once a minute, but a
quiet install also needs a cron job. It removes expired grants (and re-keys what they covered), sessions,
challenges, reservations and one-time links, audit rows past retention, and the keys of deleted users:

```cron
*/5 * * * * cd /var/www/app && php cli vault:purge >/dev/null
```

In Docker, run it as the web server's user so any file it creates keeps the right owner:

```cron
*/5 * * * * docker exec -u nginx kanboard php /var/www/app/cli vault:purge >/dev/null
```

## Recovery policy

There is no admin "reset this user's vault". Pick a recovery policy in Settings → Vault:

| Policy | What it means |
|---|---|
| **None** (default) | A forgotten passphrase, or lost hardware keys, means that user's own entries are lost. Entries other people shared with them can be shared again by their owners. Users are told this at enrolment, and pointed at KeePassXC export as a personal backup. |
| **Personal recovery code** | Each user may create a recovery code (shown once). Creating one needs the current passphrase, and a hardware key for users who have keys. Using a code sets a new passphrase and rotates the user's keys. **A recovery code bypasses hardware keys**, and removes them. |
| **Personal code + org key** | As above, plus every user's key is also sealed to an org public key. Generate it with `php cli vault:org-keygen` (it prints the secret **once**; keep it offline). `php cli vault:org-recover <username>` reads that secret and a new passphrase from stdin, and resets the user's vault. Each user sees a one-time notice that the org key holder can now recover their vault. |

Lowering the policy deletes the codes or org wraps it no longer allows, at once, and rotates the affected users'
keys at their next unlock.

Notes:

- Changing your passphrase discards your recovery code (it was tied to your old keys). Make a new one afterwards; the
  security page offers it.
- After a code is shown, you confirm it by typing back its third group. That check runs in the browser only; if you
  skip it and lose the code, make a new one while unlocked.

## Hardware keys

Users can add hardware keys (WebAuthn with the PRF extension) as a second factor; an admin can make them mandatory.
Two keys are needed, so losing one doesn't lock you out.

- **Domain changes break hardware keys.** Keys are bound to Kanboard's host name. Before moving Kanboard to a new
  domain, export your vault or remove your keys. The settings page shows the bound host, and unlock says plainly when
  it doesn't match.
- **Changing a key's PIN changes what it unlocks with.** The vault then won't open with that key. Keep your second
  key, unlock with it, then remove and re-add the first.
- "Rotate my keys", and a passphrase change, need every registered key present. Remove a lost key first.
- Hardware keys need JavaScript.

## Old backups

Key rotation (on a passphrase change, a recovery, hardware-key enrolment or **Rotate my keys**) and the re-key that
follows a revocation protect data written **afterwards**. A backup taken **before** stays readable with the credentials that were valid
when it was taken: the old passphrase opens the old backup. Treat old backups as you would the old passphrase, and
rotate the secrets themselves (not only Vault's keys) after removing someone's access.

## Deleting users

Deleting a user removes their keys, sessions, grants and the vault objects they own, including entries other people
added to that user's shared groups (those belong to the group owner). Kanboard has no hook on the user-removal screen,
so there is no warning there: move or re-share anything that should survive first. Records that only name them as a
contributor survive: grants they made and audit rows keep their data with that user reference set to empty (NULL).

Disabling a user locks their vault sessions. Disabling an agent keeps its "Agent-created" group readable by its owner;
deleting the agent deletes the group.

## Agents

With the Agents plugin, an agent's owner can turn on vault access for it. The owner gets a vault key, shown once as
`KANBOARD_VAULT_KEY=…`. Agents call four JSON-RPC methods (`getVaultEntries`, `getVaultSecret`, `createVaultEntry`,
`updateVaultEntry`) with their API token **and** the `X-Kanboard-Vault-Key` header; a leaked API token alone opens
nothing. Grants to agents are Read only. Agents write only in their own "Agent-created" group, every secret read is
audited, and reads are capped per hour (60 by default, burst 10; the owner can lower it, and the admin sets the
maximum).

Refusals come back as `{ok: false, reason}`: `not_agent`, `bad_vault_key`, `rate_limited`, `not_found`, `conflict`,
`agents_unavailable`, `payload_invalid`, `payload_too_large`, or `error` for an unexpected failure (logged by class
only).

## One-time links

A one-time link encrypts in the browser; the key lives only in the link's `#fragment`, which never reaches the server.
The page shows nothing until the recipient clicks Reveal, and the link works once. Reveals are limited per client IP
(20 per 10 minutes, and a daily bucket of 200 that refills steadily, so up to about 400 in a rolling 24 hours). A
network drop after Reveal burns the link; send a new one.

## KeePassXC import and export

Both run in your browser. Import reads KDBX 3.1 and 4. It refuses files over 50 MiB, KDF settings past fixed caps,
Twofish, and YubiKey challenge-response databases (save a copy without the YubiKey in KeePassXC, import that, then
delete it). Attachments, history, custom icons and auto-type are skipped and counted in the import report.

Export writes KDBX 4.0 (Argon2id, 64 MiB, 8 iterations, 2 lanes; ChaCha20) under a password you choose. A few values
change on the way out:

- U+FFFE and U+FFFF, which XML can't carry, become U+FFFD. In group names, field names and tags, other control
  characters (except tab and LF) become U+FFFD too.
- A value holding a control character (other than tab and LF) or CR is written as a protected field, so its bytes
  survive in KeePassXC. pykeepass drops control characters even from protected values.
- Tags are written joined by `;`. A tag that contains `,` or `;` (or `:`, for kdbxweb-based readers) is split into
  several tags when the file is read again.

## Known gaps

- **SQLite and parallel requests.** Kanboard core's session write on SQLite can fail with "database is locked" when
  two requests of the same session overlap, and the page then shows "Something went wrong". Vault sends one request
  at a time, but another plugin's background poll can still collide with it. Retrying works. MariaDB, MySQL and
  Postgres are unaffected.
- **Databases tested.** The suite runs on SQLite, MariaDB 11.4 and Postgres 17. MySQL 8 itself has not been run.
- **Browsers tested.** The end-to-end tests drive Chromium only. Firefox and Safari are not covered by automated
  tests.
- **Clipboard.** Copy tries to clear the clipboard after 30 seconds, by writing an empty string, only if the tab still
  has focus. A reload within those 30 seconds, or an unfocused tab, leaves the value there. A second copy within 30
  seconds is cleared at the first copy's time. Clipboard managers keep their own history.
- **Agents can be locked out of the API.** Kanboard core counts a failed JSON-RPC login against the username. Seven
  bad tokens sent with an agent's username lock that agent out of the API for 15 minutes, even with its correct
  token. No data is exposed; it is a denial of service. Keep agent usernames private.
- **Steward.** When the Steward plugin's "switch user" session is active, Vault refuses to unlock, to use a recovery
  code and to enrol (error `switched`), and an unlocked vault locks on its next request. Switch back first.
- **Failed-unlock counter.** The per-user back-off after five failed unlocks never fails permanently (it caps at one
  hour), but the count resets only on a successful unlock, not over time.
- **Other plugins' scripts** run on Vault's pages, as on every Kanboard page. For strict isolation, run Vault on a
  dedicated Kanboard install with only the plugins you trust.

## Email notices

Vault emails users after five failed unlocks, an org recovery or a one-time-link reveal, and agent owners when
their agent fails its vault key or hits its read cap. When an agent gets a new vault key, users who had shared
something with it are told, so they can share it again. It skips email unless Kanboard has a working transport and a real sender address
(Settings → Email, or `MAIL_FROM`); Kanboard's stock `notifications@kanboard.local` counts as unset. The Vault
activity view shows the same events either way.

## Development

The PHPUnit suite runs inside the
[Kanboard plugins harness](https://github.com/carmelosantana/kanboard-plugins), next to this checkout:

```sh
./testing/run-plugin-tests.sh Vault                 # SQLite
./testing/run-realdb-tests.sh Vault mariadb         # MariaDB 11.4, throwaway container
./testing/run-realdb-tests.sh Vault postgres        # Postgres 17, throwaway container
node --test Vault/Test/js                           # the browser code, zero dependencies
```

`run-realdb-tests.sh` starts the database in a throwaway container on an internal Docker network (no route out),
mounts only what the suite needs, and removes everything afterwards.

### The KeePassXC gate (CI)

`.github/workflows/kdbx-gate.yml` runs `Test/kdbx-gate/run.sh`. It makes KDBX files with `keepassxc-cli`, imports
them through Vault's real pages in headless Chrome, exports them again, and checks that both `keepassxc-cli` and
`pykeepass` read every entry field for field. `keepassxc-cli` and `pykeepass` run only in a throwaway container. If
the gate fails, export doesn't ship.

Run it locally with Docker, Node 22 and Chrome:

```sh
bash Vault/Test/kdbx-gate/run.sh
```

It builds a throwaway Kanboard from `../testing/Dockerfile.sodium` (override with `KB_DOCKERFILE`) on a random
`127.0.0.1` port, never your dev stack. `CHROME` sets the browser path; `KDBX_GATE_KEEP=1` keeps the work folder.

`Test/fixtures` holds private keys for software authenticators that exist only in the tests. They are not secrets;
the zip leaves `Test/` out.

## License

MIT. Vendored code keeps its own licence; see [Assets/vendor/VENDOR.md](Assets/vendor/VENDOR.md).
