# Vault security model

This page summarises what Vault protects, how, and what it leaves out. The full design, with every rule and its
reasoning, is the specification:
[Vault design spec](https://github.com/carmelosantana/kanboard-plugins/blob/master/docs/specs/2026-11-18-vault-plugin-design.md)
(see its *Addenda (as built)* section for where the code refines it).

## Threat model

### What Vault defends against

| Threat | What holds |
|---|---|
| **A stolen database backup, with `config.php` and the environment.** | Nothing in a *current* backup decrypts without a user's vault passphrase (and hardware key, if enrolled). There is no app-wide master key: every user's private key is wrapped by a key derived from their own passphrase, and the session table holds the unlocked key only under a random key that lives in the user's cookie. A test dumps a populated database and checks that no fixture plaintext appears in it. |
| **A leaked agent API token.** | On its own it opens nothing. Each agent also needs its vault key (header `X-Kanboard-Vault-Key`), which Vault never stores. Vault requires the Basic-auth password to be the API token, not a login password. Failed vault keys are throttled per agent and client IP, so a leaked token used from another address can't lock out the real agent's vault key. |
| **Curious authenticated users, Kanboard admins included.** | They can't read entries that weren't shared with them, or whose share was revoked or expired. Resetting a user's login password or minting their API token gains nothing. There is no admin vault viewer. The org recovery key, when the admin enables it, is the stated exception. |
| **Interception of a one-time link after use.** | A burned or expired link yields nothing. Knowing only the link's id (from an access log, say) can't burn it, and link previews can't either: revealing needs a click and a capability that lives only in the URL fragment. |
| **Online guessing** of passphrases, recovery codes, agent vault keys and share links. | Atomic rate buckets run before any Argon2 work, with per-user back-off (from one minute, doubling, capped at one hour), per-IP limits, and a cap on concurrent derivations. Failures answer one generic message. |

### What Vault does not defend against

- **A compromised server or PHP process.** The server decrypts in memory for an unlocked user. Anyone with a shell,
  database write access or the right to install plugins can capture passphrases or swap code. Rolling back database
  rows counts as database write; there is no rollback protection.
- **A malicious plugin, or XSS on the Kanboard origin.** Script on the page acts as the unlocked user. Vault escapes
  every value, keeps its scripts page-local and its cookie `HttpOnly`, but other plugins' layout scripts still run on
  Vault pages. For strict isolation, run Vault on a dedicated install.
- **Historical backups.** A backup taken before a passphrase change, a hardware-key enrolment or a revocation stays
  decryptable with the credentials valid at the time. Rotation protects later data only.
- **Metadata.** Row counts, sizes, timestamps, who holds a grant on which object id, and the audit columns (actor ids,
  actions, object ids, truncated IPs, browser and OS family) are stored in plaintext.
- **A recipient who keeps what they read.** Revocation can't un-show a secret.
- **Malware on the user's device.**
- **Availability.** Starving the Argon2 slots, the install-wide vault lock that one-time-link reveals also take, and
  the Kanboard core lockout of agents after failed API logins (see the README) are denial-of-service concerns, not
  confidentiality ones.

### Deployment preconditions

The guarantees above assume HTTPS; `PLUGIN_INSTALLER` off and a plugin directory the web server can't write to;
correctly configured trusted proxies; and ext-sodium. The settings page checks each one. The README explains the
proxy and Cloudflare Tunnel set-up.

## Crypto design, in brief

Everything uses libsodium (ext-sodium) on the server, and WebCrypto plus vendored code in the browser.

- **Principals.** Every user or agent in the vault has an X25519 keypair. The private key exists only inside
  *wraps*: XChaCha20-Poly1305 under a key derived from a factor. Factors: the passphrase (Argon2id, 3 passes, 64 MiB,
  per-wrap salt and parameters), a passphrase plus a hardware key's PRF output, a recovery code (160 random bits),
  an org recovery key (a sealed box to the org public key), or an agent's 256-bit vault key.
- **Objects.** Each entry and group has its own random key, which encrypts its payload (title, username and group
  names included) and is sealed to every principal allowed to read it. Grants live apart from key material, and every
  read re-checks live grants: a key row on its own grants nothing.
- **Associated data.** Every ciphertext binds its row ids, owner, key epoch and format version through one canonical,
  length-prefixed encoding, so ciphertexts can't be swapped between rows.
- **One lock.** Every change to authorisation or ciphertext runs under one install-wide exclusive lock, and every
  decrypting read under the shared lock, so nothing commits against a stale view.
- **Revocation and removal** re-key the affected objects. A removal that happens while nobody is unlocked (an expired
  grant, a deleted user, a disabled agent) deletes keys at once and queues a re-key; until then a write barrier stops
  any new data being written under the old key.
- **Rotation** gives a principal a new keypair through a resumable state machine and re-encrypts everything they can
  read. It runs on every credential change.
- **Sessions.** Unlocking stores the private key encrypted under a random 32-byte key that goes only to the browser,
  in the `__Host-kb_vault` cookie (`HttpOnly; Secure; SameSite=Strict`). Sessions lock on idle (15 minutes by default),
  after 8 hours, at logout, at a new login, on rotation, when the user is disabled, and while a Steward switch-user
  session is active.
- **Hardware keys** (WebAuthn PRF) are verified on the server without a library: a fail-closed CBOR decoder, exact
  `authData` parsing, ES256 and Ed25519 only, single-use challenges, and a pinned origin and RP ID.
- **One-time links** encrypt in the browser with AES-256-GCM. The key, and the burn capability, live only in the URL
  fragment; an optional passphrase adds Argon2id (3 passes, 64 MiB, 1 lane) in a module worker.
- **KeePassXC import and export** run in the browser. Export is checked in CI by two independent readers.

## Security review gates

The specification passed five review rounds before planning (see its *Review log*). The finished implementation is
reviewed again before the 1.0.0 tag, with the adversarial review and the security review, re-run after fixes until
neither reports a critical or high finding.

| Round | Date | Reviews | Critical / high findings | Resolution |
|---|---|---|---|---|
| Security review 1 | 2026-11-20 | Codex (gpt-5.6-sol, daybreak_blue requested): static, read-only review of `e7dba0b..6044fb6`. 0 Critical, 1 High, 0 Medium, 0 Low. | High: a user who set up a vault before being adopted as an agent kept ownership of those items after vault access was turned on, so the agent's API credentials could list and read them. | Fixed in `60123ea`: turning on vault access is refused while the user still owns items outside the agent's "Agent-created" group, and an agent's ownership counts only inside that group. |

## Vendored dependencies

Vault ships no package manager and runs no install scripts. The browser code it vendors is pinned by version and
sha256 in [Assets/vendor/VENDOR.md](../Assets/vendor/VENDOR.md), and tests check those hashes.

| Dependency | Use | Vet |
|---|---|---|
| `kdbxweb` 2.1.1 (non-minified `dist/kdbxweb.js`) | Reading and writing KDBX files on the import and export pages | Registry signature, integrity and shasum verified; the 31 TypeScript sources match the upstream tag blob for blob; the bundle scanned for `eval`, WebAssembly and network calls. Published in 2021, so it has no npm provenance. |
| kdbxweb local patches 01–05 | 01 verifies the final HMAC block; 02 keeps tabs in values; 03 zeroes keys when a load fails; 04 caps decompressed size at 256 MiB; 05 zeroes the save path's keys | Hand-written diffs, each with its own test; a test un-applies them, checks the upstream hash, and re-applies them byte for byte. |
| `@noble/hashes` 2.4.0 (Argon2 and BLAKE2b ESM files, unchanged) | Argon2id in a module worker, for KDBX files and one-time-link passphrases | npm provenance (SLSA v1) and its signature verified; tarball integrity matches; no install scripts or dependencies; checked against RFC 9106 and libsodium. |
| EFF large wordlist | The passphrase generator | sha256 cross-checked against two independent copies. CC BY 3.0. |
| `pykeepass` 4.2.0 (CI only, not shipped) | The export gate's second reader | Installed by hash, wheel only, without dependencies, inside a throwaway container; its dependencies come from Alpine's signed packages. |
| `keepassxc-cli` (CI only, not shipped) | Making gate fixtures and reading exports | Alpine's signed package, inside the same throwaway container. |

## Reporting a vulnerability

Please report security issues privately to the maintainer through the repository's security advisory page rather
than in a public issue.
