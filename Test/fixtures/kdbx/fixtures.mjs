// The KDBX test fixtures in this folder: their passwords and the values make-fixtures.mjs wrote into them. Shared by
// make-fixtures.mjs (which writes the files) and Test/js/kdbx-patches.test.mjs (which reads them). Test-only secrets.
export const PASSWORD = 'vault fixture password';
export const WRONG_PASSWORD = 'not the fixture password';

// Every value has tabs and leading, trailing or doubled spaces; unprotected and protected fields both.
export const WHITESPACE_ENTRY = {
  Title: 'Whitespace',
  UserName: '\tuser\twith tabs\t',
  Password: '\tpa ss\tword  ',
  URL: 'https://example.test/',
  Notes: ' two  spaces\n\tindented line\nend\t',
  'Plain custom': 'a\tb  c ',
  'Secret custom': '\tsecret\t',
};
export const PROTECTED_FIELDS = ['Password', 'Secret custom'];

export const FILES = {
  // KDBX 4.0, Argon2id (1 MiB, 2 passes, 1 lane), ChaCha20, GZip; holds WHITESPACE_ENTRY.
  whitespace: 'whitespace.kdbx',
  // whitespace.kdbx with one bit flipped in the HMAC of the final, empty block (the file's last 36 bytes are that
  // block: a 32-byte HMAC and a zero length). Nothing else changed.
  tamperedFinalBlock: 'tampered-final-block.kdbx',
  // KDBX 3.1, AES-KDF (1000 rounds), AES-256-CBC, Salsa20 inner stream; holds WHITESPACE_ENTRY.
  kdbx3: 'kdbx3-aes.kdbx',
  // KDBX 4.0, Argon2d (1 MiB, 2, 1), AES; PASSWORD plus the XML (v2.0) key file keyfile.keyx; one entry "Keyed".
  keyfile: 'keyfile.kdbx',
  keyfileKey: 'keyfile.keyx',
  // KDBX 4.0, Argon2d with version 0x10 (older KeePass files), AES; one entry "Version 0x10".
  argon2v10: 'argon2-v10.kdbx',
  // KDBX 4.0 Argon2d files whose KDF parameters are past Vault's import caps (m ≤ 1 GiB, t ≤ 100, p ≤ 8). Their key
  // material was made with a stand-in KDF, so no real key opens them; only the header matters.
  hostileM: 'hostile-argon2-m.kdbx', // M = 2 GiB
  hostileT: 'hostile-argon2-t.kdbx', // I = 1,000,000
  hostileP: 'hostile-argon2-p.kdbx', // P = 9
  // Within the caps but slow in pure JS (Argon2d, M = 64 MiB, I = 100): for cancel and timeout. Same stand-in KDF.
  slow: 'slow-argon2.kdbx',
};
