# Vendored files

Each file here is byte-identical to its upstream source. Test/js/vault-generator.test.mjs and Test/js/argon2-worker.test.mjs check the sha256 values below.

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
