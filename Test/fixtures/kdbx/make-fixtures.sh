#!/bin/sh
# Writes the KeePassXC fixtures (fixtures.mjs: KPXC) with the real keepassxc-cli, then the crafted files
# (make-headers.mjs) and the import batches the page builds from them (make-mapped.mjs). Run it from anywhere:
#   Vault/Test/fixtures/kdbx/make-fixtures.sh
# keepassxc-cli runs in a throwaway container built from Test/kdbx-gate/Dockerfile (R3): no build context, no network,
# only a fresh temporary folder mounted, run as the calling user. Nothing is installed on the host; node runs only
# this folder's scripts. Re-running makes new salts and keys, so the bytes change but the contents do not.
# (make-fixtures.mjs, Task 21's kdbxweb-written fixtures, is separate and not re-run here.)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
vault=$(cd "$here/../../.." && pwd)
work=$(mktemp -d)
cleanup() { case "$work" in /tmp/tmp.*) rm -rf -- "$work" ;; esac; }
trap cleanup EXIT

image=vault-kdbx-gate:local
docker build -q -t "$image" - < "$vault/Test/kdbx-gate/Dockerfile" >/dev/null

node "$here/make-seeds.mjs" "$work"
PW=$(node --input-type=module -e "import('$here/fixtures.mjs').then((m) => process.stdout.write(m.PASSWORD))")

cat > "$work/in-container.sh" <<'IN'
set -eu
cd /work
pw() { printf '%s\n' "$PW"; }
pw2() { printf '%s\n%s\n' "$PW" "$PW"; }
# The content, imported by KeePassXC itself (its defaults: KDBX 3.1, AES-KDF, AES-256).
pw2 | keepassxc-cli import -q -p entries.xml imported.kdbx
# Merged into each seed, so KeePassXC writes the seed's format, KDF and cipher.
for seed in kdbx3 argon2d chacha; do
  cp "seed-$seed.kdbx" "out-$seed.kdbx"
  pw | keepassxc-cli merge -q -s "out-$seed.kdbx" imported.kdbx
done
# A password plus a key file KeePassXC generates (KeePassXC's own defaults otherwise).
pw2 | keepassxc-cli import -q -p --set-key-file out-keyfile.keyx entries.xml out-keyfile.kdbx
for f in kdbx3 argon2d chacha; do
  echo "== out-$f.kdbx"; pw | keepassxc-cli db-info -q "out-$f.kdbx" | grep -E '^(Cipher|KDF):'
done
echo "== out-keyfile.kdbx"; pw | keepassxc-cli db-info -q -k out-keyfile.keyx out-keyfile.kdbx | grep -E '^(Cipher|KDF):'
keepassxc-cli --version
IN

docker run --rm --network none --user "$(id -u):$(id -g)" -e PW="$PW" -v "$work:/work" "$image" sh /work/in-container.sh

cp "$work/out-kdbx3.kdbx" "$here/kpxc-kdbx3-aes.kdbx"
cp "$work/out-argon2d.kdbx" "$here/kpxc-argon2d-aes.kdbx"
cp "$work/out-chacha.kdbx" "$here/kpxc-argon2id-chacha20.kdbx"
cp "$work/out-keyfile.kdbx" "$here/kpxc-keyfile.kdbx"
cp "$work/out-keyfile.keyx" "$here/kpxc-keyfile.keyx"
chmod 0644 "$here"/kpxc-*.kdbx "$here/kpxc-keyfile.keyx"

node "$here/make-headers.mjs"
node "$here/make-mapped.mjs"
