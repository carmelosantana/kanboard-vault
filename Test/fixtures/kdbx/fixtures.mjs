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

// --- KeePassXC fixtures (Task 22, R3) ------------------------------------------------------------------------------
// make-fixtures.sh writes these with keepassxc-cli in the throwaway container from Test/kdbx-gate/Dockerfile. The
// content comes from KPXC_XML (a KeePass XML file keepassxc-cli imports); the KDBX 3.1 and ChaCha20 files are made
// by merging that import into an empty seed with the wanted header (make-seeds.mjs), so KeePassXC writes them.
// The cases, with the header each one must have:
export const KPXC = {
  kdbx3: { file: 'kpxc-kdbx3-aes.kdbx', version: '3.1', kdf: 'aes', cipher: 'aes' },
  argon2d: { file: 'kpxc-argon2d-aes.kdbx', version: '4.0', kdf: 'argon2d', cipher: 'aes' },
  argon2id: { file: 'kpxc-argon2id-chacha20.kdbx', version: '4.0', kdf: 'argon2id', cipher: 'chacha20' },
  // keepassxc-cli import's own defaults (KDBX 3.1, AES-KDF with 1,000,000 rounds), plus a key file it generated.
  keyfile: { file: 'kpxc-keyfile.kdbx', version: '3.1', kdf: 'aes', cipher: 'aes', keyFile: 'kpxc-keyfile.keyx' },
};

// The content of every KeePassXC fixture: groups (by path below the root) and entries, as KeePass fields. A field
// listed in `protect` is written with ProtectInMemory="True". `attachments` and `history` are dropped by the import.
export const KPXC_EXPIRES = '2030-01-02T03:04:05Z';
export const KPXC_ENTRIES = [
  {
    path: [],
    fields: {
      Title: 'Mail',
      UserName: 'mail user',
      Password: 'Mail\tpass word ',
      URL: 'https://mail.example.test/login',
      Notes: 'line one\n\tline two  ',
      'Plain custom': 'plain\tvalue ',
      'Secret custom': ' secret value\t',
      otp: 'otpauth://totp/Example:mail?secret=JBSWY3DPEHPK3PXP&issuer=Example',
    },
    protect: ['Password', 'Secret custom'],
    tags: ['mail', 'work'],
    expires: KPXC_EXPIRES,
    attachments: { 'note.txt': 'attachment text' },
    history: [{ Title: 'Mail', Password: 'old password' }],
  },
  {
    path: ['Servers', 'Linux'],
    fields: { Title: 'Ünïcødé ✓ host', UserName: 'root', Password: 'pässwörd ✓', URL: 'ssh://host.example.test', Notes: '' },
    protect: ['Password'],
    tags: [],
  },
  { path: ['Servers'], fields: { Title: 'Empty', UserName: '', Password: '', URL: '', Notes: '' }, protect: ['Password'], tags: [] },
  // Two sibling groups with the same name stay apart: the second becomes "Dup (2)" in Vault.
  { path: ['Dup'], fields: { Title: 'In the first Dup', UserName: 'one', Password: 'p1', URL: '', Notes: '' }, protect: ['Password'], tags: [], group: 0 },
  { path: ['Dup'], fields: { Title: 'In the second Dup', UserName: 'two', Password: 'p2', URL: '', Notes: '' }, protect: ['Password'], tags: [], group: 1 },
];

// What Vault must store for each entry above, in tree order (a group's entries, then its subgroups): the entry payload (spec: Entries, groups and grants) and the Vault
// group path below "Imported <date>". `otp` becomes a protected custom field; other custom fields keep their
// protection; attachments and history are gone.
export const KPXC_EXPECTED = [
  {
    path: [],
    payload: {
      title: 'Mail', username: 'mail user', password: 'Mail\tpass word ', url: 'https://mail.example.test/login',
      notes: 'line one\n\tline two  ', tags: ['mail', 'work'], expires_at: Date.parse(KPXC_EXPIRES) / 1000, otp: '',
      fields: [
        { name: 'Plain custom', value: 'plain\tvalue ', protected: false },
        { name: 'Secret custom', value: ' secret value\t', protected: true },
        { name: 'otp', value: 'otpauth://totp/Example:mail?secret=JBSWY3DPEHPK3PXP&issuer=Example', protected: true },
      ],
    },
  },
  { path: ['Servers'], payload: { title: 'Empty', username: '', password: '', url: '', notes: '', tags: [], expires_at: null, otp: '', fields: [] } },
  {
    path: ['Servers', 'Linux'],
    payload: { title: 'Ünïcødé ✓ host', username: 'root', password: 'pässwörd ✓', url: 'ssh://host.example.test', notes: '', tags: [], expires_at: null, otp: '', fields: [] },
  },
  { path: ['Dup'], payload: { title: 'In the first Dup', username: 'one', password: 'p1', url: '', notes: '', tags: [], expires_at: null, otp: '', fields: [] } },
  { path: ['Dup (2)'], payload: { title: 'In the second Dup', username: 'two', password: 'p2', url: '', notes: '', tags: [], expires_at: null, otp: '', fields: [] } },
];
export const KPXC_SKIPPED_ATTACHMENTS = 1;

// The import batches vault-import.js builds from each KeePassXC fixture, as the server receives them (one file for
// all four, keyed by KPXC case). Written by make-mapped.mjs; ImportControllerTest posts them, and the JS tests check
// that the page still builds exactly these.
export const MAPPED = 'kpxc-mapped.json';

// Crafted hostile or broken files (make-headers.mjs, from the files above): one per kdbx-header reason.
export const CRAFTED = {
  aesRounds3: 'hostile-aes-rounds-kdbx3.kdbx', // KDBX 3.1, TransformRounds = 100,000,001
  aesRounds4: 'hostile-aes-rounds-kdbx4.kdbx', // KDBX 4.0 AES-KDF, R = 100,000,001
  twofish: 'hostile-twofish.kdbx', // KDBX 4.0 whose cipher is Twofish
  truncated: 'truncated.kdbx', // whitespace.kdbx cut inside its HMAC block stream
  trailing: 'trailing-bytes.kdbx', // whitespace.kdbx with 100 bytes after the final block
  challengeResponse: 'challenge-response.kdbx', // KDBX 4.0 whose key also needs a (simulated) YubiKey response
};
// The simulated YubiKey's HMAC-SHA1 secret for challenge-response.kdbx (KeePassXC's scheme: the response to the
// KDF seed is hashed into the composite key).
export const CR_SECRET_HEX = '00112233445566778899aabbccddeeff00112233';
