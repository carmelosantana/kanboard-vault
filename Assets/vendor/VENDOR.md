# Vendored files

Each file here is byte-identical to its upstream source. Test/js/vault-generator.test.mjs checks the sha256 below.

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
