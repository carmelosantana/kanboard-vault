# Vendored files

Each file here is byte-identical to its upstream source, except `kdbxweb/kdbxweb.js`, which is upstream plus the reviewed patches in `kdbxweb/patches/` (below). Test/js/vault-generator.test.mjs, Test/js/argon2-worker.test.mjs and Test/js/kdbx-patches.test.mjs check the sha256 values below.

## eff_large_wordlist.txt

| | |
|---|---|
| What | The EFF large wordlist for passphrases: 7776 lines of `<5 dice digits>\t<word>` |
| Source | https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt |
| Retrieved | 2026-11-19 |
| sha256 | `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e` |
| Cross-checked | The same sha256 from the Wayback Machine's 2016 capture of the source URL and from `ulif/diceware` (`diceware/wordlists/wordlist_en_eff.txt` on GitHub) |
| Licence | CC BY 3.0 (https://creativecommons.org/licenses/by/3.0/us/), © Electronic Frontier Foundation, https://www.eff.org/dice |
| Used by | Assets/js/vault-generator.js fetches it on the first passphrase, drops the dice numbers and keeps the 7776 words. It refuses a list that isn't exactly 7776 distinct words in that format. |

The file is unchanged. Vault uses the words only, as data.

## noble-hashes/ (@noble/hashes 2.4.0, Argon2 and BLAKE2b)

| | |
|---|---|
| What | The ESM files Argon2 needs from `@noble/hashes` 2.4.0, unchanged: `argon2.js` and its imports `blake2.js`, `_blake.js`, `_md.js`, `_u64.js`, `utils.js`, plus `LICENSE` |
| Source | `npm pack @noble/hashes@2.4.0 --ignore-scripts` (https://registry.npmjs.org/@noble/hashes/-/hashes-2.4.0.tgz), into a fresh, empty directory; nothing installed or run |
| Retrieved | 2026-11-19 |
| Tarball integrity | `sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==` (shasum `e6a3e98edbed3c8659b28bb8f9b18ca02ec8ea4b`): the local tarball's sha512 equals the registry's `dist.integrity`, and equals the subject digest of both attestations |
| Provenance | npm provenance, SLSA v1 (`https://slsa.dev/provenance/v1`), published by GitHub Actions through npm trusted publishing (OIDC), approved by `paulmillr`. Built from `github.com/paulmillr/noble-hashes` at `refs/tags/2.4.0`, commit `663c2aeeffc308ac0cded59bd32f7c212adacfc2`, workflow `.github/workflows/release.yml` (run 33074534582), via the reusable workflow `paulmillr/jsbt/.github/workflows/release.yml@c138efca67d90dce86a7cc22c01d6b66d193ea7a`. The DSSE signature verifies with the Fulcio certificate's key (`openssl dgst -sha256 -verify`: Verified OK); the certificate is issued by `sigstore.dev / sigstore-intermediate`; Rekor log index 2617382347 |
| Vet (2026-11-19) | Published 2026-08-27 (84 days before vendoring); one maintainer (paulmillr), unchanged; no `preinstall`/`install`/`postinstall` scripts; no dependencies; `type: module`, MIT. Of the files kept, the only imports are relative imports of each other; no `eval`, `new Function`, `WebAssembly`, `fetch` or `importScripts`; `globalThis` is read only for `scheduler.yield`/`setTimeout` and `crypto` |
| Licence | MIT, © 2022 Paul Miller (https://paulmillr.com); `noble-hashes/LICENSE` |
| Used by | `Assets/js/argon2-worker.js`, a module worker (`new Worker(url, {type: 'module'})`) that imports `argon2.js` and `blake2.js` as they are. No build step: Test/js/argon2-worker.test.mjs loads the files as ES modules in a worker-like realm (`node --experimental-vm-modules`, no Node globals) and checks Argon2id against RFC 9106 and libsodium, so the spec's esbuild fallback is not needed |

| File | sha256 |
|---|---|
| `noble-hashes/argon2.js` | `f39753324bdf2f484150731d24b1d71236f26bf10bedd594f7d190fcdfdefdc9` |
| `noble-hashes/blake2.js` | `03f00237bcc0b4d822a80f7c0ac22e42632c48e246c3b6da584e6452186e32f0` |
| `noble-hashes/_blake.js` | `cabbff61d1f373bac45594ad758df7c42e176464ddbb94b44f5533fa977a4f56` |
| `noble-hashes/_md.js` | `60cf3010fda89e3e4d3f0e7ff1ce249e9c467f34b4fd41b6fd6101d9f69be763` |
| `noble-hashes/_u64.js` | `b09da8c07fe8187c07649494cdb7cd0bcf13df90b506a9473d19e4d5f8c2e102` |
| `noble-hashes/utils.js` | `037ad49adb78168b6b699598fd33f85f7877456b1d28b4d032e2a1a16807947c` |
| `noble-hashes/LICENSE` | `4f221aee6e072336700c408c68ab3b96a3fc09f6aebe6f48f1bd99e5ef13faec` |

The README notes that Argon2 is outside noble's audit scope; the RFC 9106 KAT and the libsodium cross-check above are Vault's own check of it.

## kdbxweb/ (kdbxweb 2.1.1, KDBX read and write)

| | |
|---|---|
| What | `dist/kdbxweb.js` from kdbxweb 2.1.1, the **non-minified** webpack UMD build (321,788 bytes upstream), plus `LICENSE`. The spec's choice: non-minified so the local patches stay reviewable |
| Source | `npm pack kdbxweb@2.1.1 --ignore-scripts` (https://registry.npmjs.org/kdbxweb/-/kdbxweb-2.1.1.tgz), into a fresh, empty directory and extracted into another; nothing installed or run |
| Retrieved | 2026-11-19 |
| Tarball integrity | `sha512-z+a2+BEzyK2kUh0xDekY7gwc9CkbzSetUyvc78NKVawxV06UG1KYbg9W9hZCJdQPYizIVePTvQsYUXIO1qtAhQ==` (shasum `d30c6db3741dbc596a84860c46d491c2309f59c6`): the local tarball's sha512 and sha1 equal the registry's `dist.integrity` and `dist.shasum` |
| Provenance | **None** (published 2021, before npm provenance existed; `/-/npm/v1/attestations/kdbxweb@2.1.1` answers 404). Checked instead: the registry's ECDSA P-256 signature over `kdbxweb@2.1.1:<integrity>` verifies with npm's registry key `SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA` (valid until 2025-01-29, so valid for a 2021 publish); all 31 `lib/*.ts` sources in the tarball have the same git blob ids as tag `2.1.1` of github.com/keeweb/kdbxweb (commit `9b86a035a53f1827e427a0fc081bdcccc24f4f1b`, 2021-09-06, antelle). The repository does not commit `dist/`, so the bundle was not rebuilt: it was scanned as below and the regions the patches touch were read in full |
| Vet (2026-11-19) | Published 2021-09-06T19:57:25Z, still `latest` (no release since, so no fresh-publish risk); one maintainer, `antelle`, who also published it; the repo moved to the keeweb org and has had only docs commits since. No `preinstall`/`install`/`postinstall` scripts (build/test only). Dependencies `@xmldom/xmldom ^0.7.4` and `fflate ^0.7.1`: fflate is bundled into `dist/kdbxweb.js`; xmldom and Node's `crypto` are UMD externals the browser branch never loads (`root["crypto"]`, `root["@xmldom/xmldom"]`; kdbxweb uses `globalThis.DOMParser`/`XMLSerializer` and WebCrypto when they exist). Scan of the bundle: no `eval`, `WebAssembly`, `fetch`, `XMLHttpRequest`, `importScripts` or network URL; the only `new Function` is webpack's global-object fallback, reached only if `globalThis` is not an object (never in a supported browser), so the CSP needs no `unsafe-eval`; fflate's Blob-URL worker helpers are bundled but kdbxweb calls only `gzipSync`/`gunzipSync`. No red flag |
| Licence | MIT, © 2021 Antelle; `kdbxweb/LICENSE` (the bundle's first line keeps the notice too). The bundled fflate is MIT (© Arjun Barrett, `101arrowz`); its notice is not in the bundle, so it is recorded here |
| Used by | `Assets/js/vault-kdbx.js` (`window.KBVaultKdbx`), loaded after `kdbxweb.js` as classic scripts on the page. Argon2 is wired through `kdbxweb.CryptoEngine.setArgon2Impl` to `Assets/js/argon2-worker.js` (the noble files above; vetted in T18, see that section). No WebAssembly |

| File | sha256 |
|---|---|
| `kdbxweb/kdbxweb.js (upstream)` | `d3b59272b72c8fc0dc340e2ab68940a54669bdbcc5a92e65ace9cb001d9eb169` |
| `kdbxweb/kdbxweb.js (patched)` | `dd348acda8ed99f9091744856cce7d45ab02a1b79d90f56ee5dd6f7c26db540c` |
| `kdbxweb/LICENSE` | `5328cd70623b0154a3d13ce41d57d6d4e9fda5b6db2e8ed994d29c3598c374a8` |

### Local patches

`kdbxweb/kdbxweb.js` is the upstream file with these five patches applied in order (unified diffs against the bundle, written by hand; each change carries a `Vault patch NN` comment in the file). The `@keenext/kdbxweb` fork (2.2.0-keenext.2, its `FORK.md` and bundle read from `npm pack --ignore-scripts`, never installed) was used only as a reference for what to fix; it rewrites the sources in TypeScript `async`/`await`, so no code was copied. `kdbx-patches.test.mjs` (`vendored file sha256 matches VENDOR.md after patches`) un-applies the patches from the vendored file, checks the result's sha256 against the upstream value above, then re-applies them and compares byte for byte.

| Patch | What and why | Upstream | Test |
|---|---|---|---|
| `kdbxweb/patches/01-verify-final-hmac-block.patch` | In KDBX 4's HMAC block stream, upstream checks every block's HMAC except the final, empty block's. A stream cut at a block boundary and closed with a forged empty block was read as the whole file. The patch verifies that block's HMAC (index, zero length, no data, as `encrypt()` writes it) and refuses a mismatch as `FileCorrupt: invalid hash block` | No upstream issue or PR (none among keeweb/kdbxweb's 63 issues and PRs on 2026-11-19); the code is `decrypt()` in https://github.com/keeweb/kdbxweb/blob/2.1.1/lib/crypto/hmac-block-transform.ts. The keenext `FORK.md` lists the same fix | `final HMAC block is verified` (the `tampered-final-block.kdbx` fixture, one bit flipped in that HMAC, and a forged truncation of a two-block stream) |
| `kdbxweb/patches/02-preserve-tabs.patch` | Before parsing the inner XML, upstream deletes the characters `\x00–\x09`, `\x0B–\x0C`, `\x0E–\x1F`. That range includes tab, which XML 1.0 allows, so every tab vanished from every unprotected value (user name, URL, notes, custom fields). The patch keeps `\x09`; the forbidden characters are still removed. Other whitespace (spaces, LF, CR) was never touched | https://github.com/keeweb/kdbxweb/pull/63 (open; the same one-character range change) | `tabs and whitespace preserved` (KDBX 4 and 3.1 fixtures whose values hold tabs and leading, trailing and doubled spaces, protected and not) |
| `kdbxweb/patches/03-zero-keys-on-failure.patch` | Upstream zeroes keys only on the success path, so a wrong password or a corrupt file left them in memory: the credential hash when the KDF fails or is cancelled, KDBX 3's master key, KDBX 4's cipher and HMAC keys; and it never zeroes the header and per-block HMAC keys or the copy of master seed ‖ derived key hashed into the cipher key. The patch adds a `zeroAfter()` helper that zeroes the given buffers when a step resolves, rejects or throws, and uses it on those keys; a derived key of the wrong length is zeroed too. Not covered here: the inner random stream key and the save path's own key handling, which patch 05 covers | No upstream issue or PR (checked as above); related: https://github.com/keeweb/kdbxweb/issues/9 (2016, zeroing intermediate KDF results, closed). The keenext `FORK.md` lists the same fix | `keys zeroed on failed load` (spies on `Uint8Array.prototype.fill(0)` and WebCrypto digests: KDBX 4 wrong password, tampered final block, KDBX 3.1 wrong password, KDF refused, and a successful load) |

| `kdbxweb/patches/04-cap-inflated-size.patch` (Task 22) | kdbxweb inflates the gzip payload (and KDBX 3's compressed binaries) with the bundled fflate `gunzipSync` on the page, where `KBVaultKdbx.cancel()` can't stop it. `gunzipSync` allocates the size the gzip trailer declares (up to 4 GiB), and with that fixed buffer upstream fflate silently drops output that doesn't fit and keeps inflating, so a stream that lies about its size could spin the page for minutes (T21 review M5). The patch gives each `KdbxFormat.load` an inflate budget, `KdbxFormat.inflateLimit` (256 MiB, about five times the import's 50 MB file limit; 0 outside a load): a declared size past what is left is refused before allocating, as `InflateLimit` (vault-kdbx.js: `too_large`), and inflating past the declared size stops at once as `FileCorrupt`. A legitimate database larger than this when decompressed can't be imported | No upstream issue or PR (checked as above); the code is fflate 0.7's `inflt` and `gunzipSync` as bundled, and `load()` in https://github.com/keeweb/kdbxweb/blob/2.1.1/lib/format/kdbx-format.ts | `inflated size is capped` (a fixture loaded under a 100-byte limit, KDBX 4 and 3.1; a gzip that declares 1 KiB and inflates to 1 MiB; one that declares 4 GiB) |
| `kdbxweb/patches/05-zero-save-path-keys.patch` (Task 23) | The export writes KDBX 4.0 (`saveV4`). Upstream zeroed its cipher and HMAC keys on success only, and never zeroed the inner random-stream key (the header's `protectedStreamKey`, which salts protected values in the XML), the SHA-512 it derives the ChaCha20 stream key and nonce from (the SHA-256 for Salsa20), that stream cipher's state, the data cipher's copy of the cipher key and its state (ChaCha20 runs in JS), or the plaintext inner header + XML and its gzip. The patch: `save()` zeroes `protectedStreamKey` once the save resolves, rejects or throws (`generateSalts` makes a new one for every save); `saveV4` zeroes the cipher and HMAC keys with `zeroAfter`, and the plaintext buffers and the stream cipher's state (new `ProtectSaltGenerator.destroy()`, `ChaCha20.destroy()`, `Salsa20.destroy()`) either way; `ProtectSaltGenerator.create` zeroes the hash once the cipher has copied it; `CryptoEngine.chacha20` zeroes its key copy and state. The XML string itself can't be zeroed (a JS string). `encryptXmlV3` (KDBX 3 writes) is untouched: Vault never writes KDBX 3 | No upstream issue or PR (checked as above); the code is `save()`/`saveV4()` in https://github.com/keeweb/kdbxweb/blob/2.1.1/lib/format/kdbx-format.ts, `lib/crypto/protect-salt-generator.ts`, `lib/crypto/chacha20.ts`, `lib/crypto/salsa20.ts` and `chacha20()` in `lib/crypto/crypto-engine.ts`. Related: https://github.com/keeweb/kdbxweb/issues/9 | `save-path keys and the inner-stream key are zeroed` (spies on `fill(0)` and WebCrypto digests: a successful KDBX 4 save, which then opens and saves again, and a save that fails at the header HMAC), `ProtectSaltGenerator.destroy zeroes the stream cipher state` (ChaCha20 and Salsa20) |

The 4.1 write bug (upstream #49) is not patched: Vault writes KDBX 4.0 (spec). Twofish is not supported upstream, and the import pre-check refuses it (Task 22).

## Test only: pykeepass 4.2.0 (the export gate's second reader; not shipped)

Not vendored and not in the plugin zip: `Test/kdbx-gate/Dockerfile` installs it, inside the throwaway gate container only (R3), because Alpine 3.24 has no `py3-pykeepass`. It is installed by hash, wheel only, without dependencies: `pip install --no-deps --only-binary=:all: --require-hashes` of `pykeepass==4.2.0 --hash=sha256:8d61…086d`. Its dependencies come from Alpine's signed repository (`py3-lxml`, `py3-argon2-cffi`, `py3-pycryptodomex`, `py3-construct`; `importlib.metadata` is in the standard library). Its declared `pyotp` requirement is not installed: no pykeepass module imports it (grep of the wheel). pip itself is removed again in the same layer.

| Check | Command | Result (2026-11-19) |
|---|---|---|
| Publish date | `curl https://pypi.org/pypi/pykeepass/json` | 4.2.0 uploaded 2026-08-09T21:22:56Z (three months old; the previous release, 4.1.1.post1, 2025-03-06). Not a fresh publish |
| Maintainers | `curl https://pypi.org/pypi/pykeepass/4.2.0/json` → `ownership` | Owner `pschmitt`, maintainer `Evidlo`; the GitHub release v4.2.0 (2026-08-09T21:22:42Z) is by `Evidlo` |
| Install scripts | the wheel | A pure-Python wheel (`py3-none-any`): a wheel runs no code at install. No sdist is used |
| Dependencies | `Requires-Dist` in METADATA | `pyotp>=2.9.0`, `importlib-metadata`, `construct>=2.10.53`, `argon2_cffi>=18.1.0`, `pycryptodomex>=3.6.2`, `lxml`. Taken from Alpine as above; pyotp unused |
| Provenance | `curl https://pypi.org/integrity/pykeepass/4.2.0/pykeepass-4.2.0-py3-none-any.whl/provenance` | **None** (404, "No provenance available"); the simple index lists no provenance for either file. Checked instead: the source match below |
| Hashes | `curl` of the wheel, `sha256sum` | wheel `8d6100788422eb8a43710b227fde873f7684d08bf0117eb43c8ae346644b086d` (= PyPI's digest; pinned in the Dockerfile); sdist `0e40eabdac19a511a2be4e550984cbf01f1fd8ec9d9055456136fab266e5cc66` (not used) |
| Source match | `gh api repos/libkeepass/pykeepass/git/trees/<v4.2.0>?recursive=1` + `git hash-object` per file | **19/19** files of the wheel's `pykeepass/` package have the same git blob ids as tag `v4.2.0` (commit `940665ff4f11c6f34dbdfbcfb14ec63bd6161ebf`) |
| Content | grep of the extracted wheel | No `subprocess`, `os.system`, `socket`, `urllib`, `requests`, `http.client`, `exec(` or `eval(`. It reads and writes KeePass files only |
| Licence | METADATA | GPL-3.0. A test tool run in a container; nothing of it ships with Vault |

No red flag. The gate runs it with `python3 -I`, no network, and only the gate's scratch folder mounted (read-only).
