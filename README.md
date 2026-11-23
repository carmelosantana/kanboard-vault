# Vault (Kanboard plugin)

An encrypted password store for Kanboard, modelled on KeePassXC: a groups tree, an entry list, copy to clipboard
and a password generator. Each user has their own keys behind a vault passphrase that is separate from their
Kanboard login. Entries can be shared with teammates (Read or Edit) and with API agents, sent to anyone as a
one-time link, and imported from or exported to KeePassXC.

The server stores secrets only as ciphertext; metadata such as the group structure, grants and audit columns is
plaintext by design. A stolen database backup, `config.php` included, opens nothing without a user's
passphrase (and hardware key, if they enrolled one). The one exception is an entry an owner shared with Server,
and only when the backup also holds the Server key file ([Server sharing](#server-sharing)). The server decrypts
in memory while it serves an unlocked user, so Vault does not defend against a compromised server. [docs/security.md](docs/security.md) has the threat model.

> Status: v1.0.0 is not released yet.

## Requirements

- Kanboard `>=1.2.47` and PHP `>=8.4`.
- SQLite, MySQL 8.0.16 or later, MariaDB 10.3.10 or later, or Postgres. Older MySQL and MariaDB releases have no
  `information_schema.CHECK_CONSTRAINTS`, which the schema migration reads (MySQL before 8.0.16 also ignores CHECK).
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
| Server sharing | Shows whether it is on. Information only. |
| The Server key file is outside `DATA_DIR` | A backup of the data directory must not carry the key with the database. Red until you set `VAULT_SERVER_KEY_FILE`, even while Server sharing is off. While it is on, the file must also be sound and open the Server key. See [Server sharing](#server-sharing). |
| Entries at risk | No entry shared with Server has a disabled owner, or an owner with no other administrator who could claim it. |

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

Deleting a user removes their vault, in two steps:

1. **At once.** Their sessions and wraps go with the user row. Everything they own becomes unreadable to everyone,
   Server included.
2. **At the next purge** (within a minute on a busy install, or at the next `vault:purge`). Their grants and keys go,
   and what they could read is queued for re-key. The vault objects they own are deleted, including entries other
   people added to that user's shared groups (those belong to the group owner).

The one exception is an entry the user shared with Server. The purge keeps it as a quarantined **orphan** (see
[Orphans](#orphans-quarantine-claim-destroy)), with the groups above it that the user owned. Their principal stays as
a tombstone until every orphan is claimed or destroyed.

Kanboard has no hook on the user-removal screen, so there is no warning there: move or re-share anything that should
survive first. Before you delete an owner, check *Entries at risk* on Settings → Vault. Records that only name them as
a contributor survive: grants they made and audit rows keep their data with that user reference set to empty (NULL).

Disabling a user locks their vault sessions. Disabling an agent keeps its "Agent-created" group readable by its owner;
deleting the agent deletes the group.

## Agents

With the Agents plugin, an agent's owner can turn on vault access for it. The owner gets a vault key, shown once as
`KANBOARD_VAULT_KEY=…`. Agents call four JSON-RPC methods (`getVaultEntries`, `getVaultSecret`, `createVaultEntry`,
`updateVaultEntry`) with their API token **and** the `X-Kanboard-Vault-Key` header; a leaked API token alone opens
nothing. Grants to agents are Read only. Agents write only in their own "Agent-created" group, every secret read is
audited, and reads are capped per hour (60 by default, burst 10; the owner can lower it, and the admin sets the
maximum).

An agent owns nothing outside its "Agent-created" group. If the agent's user set up a vault of its own before it
became an agent, vault access can't be turned on while that vault still holds items: they must be deleted first (the
refusal is logged in the owner's activity).

Refusals come back as `{ok: false, reason}`: `not_agent`, `bad_vault_key`, `rate_limited`, `not_found`, `conflict`,
`agents_unavailable`, `payload_invalid`, `payload_too_large`, or `error` for an unexpected failure (logged by class
only).

## Server sharing

Server sharing lets a Kanboard plugin read a secret with nobody unlocked: a nightly scan, a mail poll, a sync job.
The plugin reads through the install's **Server** principal. An owner shares one entry with Server, names the plugins
(consumers) that may read it and the fields they may read, and every read is audited.

This is the one deliberate exception to "a stolen backup decrypts nothing". A backup that holds both the database and
the Server key file opens the entries shared with Server, and only those. Entries shared only with people or agents
stay closed. Keep the key file out of your database backups.

### Turning it on

1. Put the key file outside Kanboard's data directory. In `config.php`:

   ```php
   define('VAULT_SERVER_KEY_FILE', '/etc/kanboard/vault-server.key');
   ```

   The constant holds a path, not a secret. The default is `DATA_DIR/vault-server/server.key`, and the deployment
   check shows it red: a backup of the data directory would carry the key with the database. Make the directory
   (here `/etc/kanboard`) exist and belong to the web server's user, with no group or other write bit. Vault creates
   only the last directory, `0700`, and the file inside.
2. Open Settings → Vault, unlock your vault, enter your vault passphrase and click **Turn Server sharing on**. You
   need to be an app admin. This creates the key file (or keeps a valid one), a new Server keypair and the key that
   hides custom field names (below).

The key file is 32 random bytes, a regular file owned by the web server's user, mode `0600`, with no symbolic link
anywhere in its path. Vault never repairs it and never replaces it: a file that breaks any rule fails closed, and
reads answer `server_key_unavailable`. Back it up on its own, away from the database. Without it, nothing shared with
Server can be read.

Turning Server sharing off needs an admin and a confirmation, not your passphrase. It deletes every Server share, its
key rows and its rate buckets, and queues the entries for re-key. Owners must share each entry again after it is
turned back on. The key file stays where it is.

### Sharing an entry with Server

Open an entry's sharing dialog (you must own it and be unlocked). The Server section shows only for an entry, and only
while Server sharing is on. Fill in:

- **Consumers.** The plugin names that may read it, 1 to 16, each `[A-Za-z][A-Za-z0-9_]*` and at most 64 characters.
  The plugin documents its name.
- **Fields.** The fields they may read, 1 to 32: the top-level `title`, `username`, `password`, `url`, `notes` and
  `otp`, or a custom field by its name.
- **Rates.** Reads per hour (default 60) and burst (default 10). You may lower them. The admin sets the maximum.

A Server share is always Read, always one entry (never a group) and never expires. Revoking it removes Server's key
row and queues the entry for re-key. Then rotate the secret at its provider, since Server could have read it.

Custom field names are never stored in plaintext in grants or the audit log. Vault stores a keyed hash
(`c:` + base32 of BLAKE2b-128 under a field-name key). That key is sealed to Server, made when Server sharing is turned
on and deleted when it is turned off. Top-level names are stored as they are.

### The consumer API

While Server sharing is on, the container has `vaultSecrets`, a
`Kanboard\Plugin\Vault\Secrets\ServiceSecrets`. A consumer stores a ref of the form `vault://<entry_id>/<field>`, such
as `vault://42/password`. The field is percent-encoded; a top-level key wins over a custom field with the same name.

```php
use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;

function cveHunterApiKey($container, string $ref): ?string
{
    if (! isset($container['vaultSecrets'])) {
        return null; // Vault missing or Server sharing off: no key, and no fallback
    }
    try {
        return $container['vaultSecrets']->read('CveHunter', $ref, 'scan:nightly')->reveal();
    } catch (ServiceSecretException $e) {
        $container['logger']->warning('CveHunter: Vault refused the key: '.$e->reason());
        return null;
    }
}
```

- `read(string $consumer, string $ref, ?string $jobRef = null): SecretValue`. The job ref is optional, 1 to 64 of
  `A-Z a-z 0-9 _ . : -`, and lands in the audit row.
- `SecretValue::reveal()` is the only way to the bytes. The value can't be printed, dumped, serialised, cloned or
  cast to a string, so a wrapper can't leak it by accident. The string `reveal()` returns is ordinary PHP data.
- `describe(string $ref): RefStatus` tells a settings page whether a ref would read: `ok` or the refusal reason. It
  shows no title or value, writes no audit row and spends no rate token.
- `available(): bool` is true when Server sharing is on and the key opens now.
- Each request (or process) gets one correlation id in its audit rows. A long-running worker calls
  `Kanboard\Plugin\Vault\Model\Correlation::begin()` at the start of each job.

**Fail closed (SEC-08).** A plugin may fall back to a plain setting or an env value only while no ref is configured.
Once a consumer stores a `vault://` ref, any failure means it has no credential: Vault missing, Server off, the key
unavailable, revoked, not allowed, rate-limited. Show the reason on the plugin's settings page, log it, and never
fall back to an old plain or env value. Plugins list Vault in `recommends`, never `requires`.

### Refusals

Every refusal is a `ServiceSecretException` whose message, and `reason()`, is one of these strings and nothing else.
It carries no title, value, path or previous exception.

| Reason | When |
|---|---|
| `not_found` | The ref doesn't parse (P1 has no `@<version>`), the entry doesn't exist, or it has no such field. |
| `server_off` | Server sharing is off. |
| `revoked` | The entry has no Server share, and its last Server share action was a revoke. |
| `not_shared` | The entry has no Server share (never shared), or Server's key row is missing or stale. |
| `consumer_not_allowed` | The consumer isn't in the share's consumers. |
| `field_not_allowed` | The field isn't in the share's fields. |
| `server_key_unavailable` | The key file is missing, unsafe or not the right one (also when a custom field's name key won't open). |
| `orphaned` | The entry's owner, or the owner of a group above it, was deleted. See [Orphans](#orphans-quarantine-claim-destroy). |
| `rate_limited` | The bucket `srvread:<consumer>:<entry_id>` is empty. |

Vault checks in this order and reports the first step that fails: the ref parses, Server is on, the entry exists, a live Server share (`revoked` or `not_shared`), the
consumer, the field, no owner gone (`orphaned`), a rate token, Server's key row at the entry's key epoch
(`not_shared`), the key opens (`server_key_unavailable`), the entry decrypts and has the field (`not_found`).

### Audit, the first-read email and events

Every read writes `server_read` with the consumer, entry id, field, entry version, job ref and correlation id. Every
refusal writes `server_read_denied` with its reason, in the same transaction as the spent token. A custom field is
recorded only as its keyed hash. The entry's owner sees these rows in their Vault activity.

`rate_limited` refusals are aggregated so a runaway job can't flood the log. The first refusal per bucket and
10-minute window writes a row at once. The rest of that window's refusals become one row with their count, written
once the window has closed.

The first time a consumer reads an entry, its owner is emailed (when Kanboard has mail set up). The email names only
the consumer and the entry as `#<entry_id>`.

Two events fire on Kanboard's dispatcher, after the change commits. They carry ids only:

| Event | Payload | When |
|---|---|---|
| `vault.secret.changed` | `entry_id`, `version` | Any entry was saved. |
| `vault.secret.revoked` | `entry_id` | An entry lost its Server share: revoked, deleted, or Server sharing turned off. |

Listen to them to drop a cached value.

### Rate limits

Each share has a rate per hour and a burst, clamped to the admin's maxima when it is saved and again at every read
(Settings → Vault: *Most secret reads a Server grant may allow per hour*, default 60, and *Largest burst*, default
10). The bucket is per consumer and entry: `srvread:<consumer>:<entry_id>`. The 11th read in a burst is
`rate_limited`, and the bucket refills at the hourly rate. Buckets go when the share is revoked or Server sharing is
turned off.

### Orphans: quarantine, claim, destroy

When an owner's Kanboard user is deleted, each entry they shared with Server becomes an **orphan**. It is
quarantined at once: nobody reads it, Server included (`orphaned`), until an app admin decides. The purge keeps it
and audits `orphan_quarantine`. Settings → Vault lists orphans by entry number only.

- **Claim.** An active app admin who holds a live grant on the entry (directly or through a group), with
  their vault unlocked, takes it over. The entry
  is re-keyed (new key, epoch + 1) under the admin as owner and moved into a group the admin owns. It is sealed again
  to everyone who should read it there, Server included while its share lives. The admin's own grant on it goes,
  since ownership replaces it. Audited `orphan_claim`.
- **Destroy.** An active app admin deletes the entry and everything that points at it. It needs step-up: your vault
  passphrase again. Audited `orphan_destroy`.

Refused claims and destroys are audited too (`orphan_claim_denied`, `orphan_destroy_denied`).

Before it happens, Settings → Vault and each owner's security page list **entries at risk**: shared with Server, and
either the owner is disabled or no other active admin holds a grant who could claim them. The owner's page links each
one to the vault page (`?entry=<id>`).

Known P1 limits:

- An admin who rotates their own keys loses their key row on a quarantined orphan (the owner is gone, so nobody seals
  it to the new key) and can no longer claim it. Another admin with a grant can, or it can be destroyed.
- An admin with hardware keys enrolled can't destroy an orphan from the settings page: step-up for them needs a
  hardware-key assertion, and the form has no field for it. Another admin can destroy it.

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
their agent fails its vault key or hits its read cap, and entry owners the first time a plugin reads an entry they
shared with Server. When an agent gets a new vault key, users who had shared
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
