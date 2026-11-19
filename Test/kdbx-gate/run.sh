#!/usr/bin/env bash
# The KeePassXC export gate (spec: KeePassXC import and export → CI gate; R3, R68). Prints `kdbx gate: PASS` and
# exits 0 only if every check passes:
#   1. keepassxc-cli writes the gate's databases (Unicode and tabs; 10,000 entries) in a throwaway container built
#      from Dockerfile here (no build context, no network, only a fresh temporary folder mounted), and
#      gate-fixtures.mjs crafts the broken ones from them: truncated, a bad block HMAC, a hostile KDF header.
#   2. A throwaway Kanboard container, built from the harness's testing/Dockerfile.sodium with this Vault copied in,
#      runs on a random 127.0.0.1 port with its own data (never the :8081 dev stack's) and is removed afterwards.
#   3. gate.mjs drives headless Chrome over raw CDP through the real import and export pages (import, refusals,
#      export with a fresh re-auth, download).
#   4. verify.py opens the export with pykeepass and keepassxc-cli (ls, show, export), inside the gate container, and
#      compares every group and entry, field for field.
# Run from anywhere: bash Vault/Test/kdbx-gate/run.sh
# Env: CHROME (default /usr/bin/google-chrome); KB_DOCKERFILE (default ../testing/Dockerfile.sodium next to this
# Vault checkout, as in the plugins harness); KDBX_GATE_KEEP=1 keeps the work folder (it holds the export and its
# password: test data only).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
vault=$(cd "$here/../.." && pwd)
dockerfile=${KB_DOCKERFILE:-$(cd "$vault/.." && pwd)/testing/Dockerfile.sodium}
work=$(mktemp -d)
chmod 0755 "$work"
name="vault-kdbx-gate-$$-$RANDOM"
gate_image=vault-kdbx-gate:local
kb_image=vault-kdbx-gate-kanboard:local
status=1

cleanup() {
  docker rm -f -v "$name" >/dev/null 2>&1 || true
  if [ "${KDBX_GATE_KEEP:-}" = 1 ]; then
    echo "kept: $work"
  else
    case "$work" in /tmp/tmp.*) rm -rf -- "$work" ;; esac
  fi
  if [ "$status" -eq 0 ]; then echo 'kdbx gate: PASS'; else echo 'kdbx gate: FAIL'; fi
}
trap cleanup EXIT

[ -f "$dockerfile" ] || { echo "no Kanboard Dockerfile at $dockerfile (set KB_DOCKERFILE)"; exit 1; }

echo '== 1. fixtures (keepassxc-cli in the gate container)'
docker build -q -t "$gate_image" - < "$here/Dockerfile" >/dev/null
node "$here/gate-fixtures.mjs" sources "$work"
pw=$(node --input-type=module -e "import('$here/gate-fixtures.mjs').then((m) => process.stdout.write(m.PASSWORD))")
cat > "$work/in-container.sh" <<'IN'
set -eu
cd /work
pw() { printf '%s\n' "$PW"; }
pw2() { printf '%s\n%s\n' "$PW" "$PW"; }
# Unicode and tabs: KDBX 4.0, Argon2id + ChaCha20 (merged into the seed, so KeePassXC writes the seed's header).
pw2 | keepassxc-cli import -q -p unicode.xml unicode-imported.kdbx
cp seed-chacha.kdbx gate-unicode.kdbx
pw | keepassxc-cli merge -q -s gate-unicode.kdbx unicode-imported.kdbx
# 10,000 entries, with keepassxc-cli import's own defaults.
pw2 | keepassxc-cli import -q -p bulk.xml gate-10000.kdbx
for f in gate-unicode gate-10000; do
  echo "   $f.kdbx: $(pw | keepassxc-cli db-info -q "$f.kdbx" | grep -E '^(Cipher|KDF):' | tr '\n' ' ')"
done
echo "   gate-10000.kdbx: $(pw | keepassxc-cli ls -q -R -f gate-10000.kdbx | grep -vc '/$') entries"
IN
docker run --rm --network none --user "$(id -u):$(id -g)" -e PW="$pw" -v "$work:/work" "$gate_image" sh /work/in-container.sh
node "$here/gate-fixtures.mjs" craft "$work"

echo '== 2. throwaway Kanboard'
docker build -q -t "$kb_image" - < "$dockerfile" >/dev/null
docker create --name "$name" -p 127.0.0.1::80 -e VAULT_DEV_INSECURE_LOCALHOST=1 "$kb_image" >/dev/null
# php-fpm passes only whitelisted variables (clear_env): the image's list plus the Vault dev opt-in.
docker run --rm --entrypoint cat "$kb_image" /etc/php84/php-fpm.d/env.conf > "$work/env.conf"
printf '\nenv[VAULT_DEV_INSECURE_LOCALHOST] = $VAULT_DEV_INSECURE_LOCALHOST\n' >> "$work/env.conf"
docker cp "$work/env.conf" "$name:/etc/php84/php-fpm.d/env.conf"
tar -C "$vault/.." --exclude="$(basename "$vault")/.git" -cf - "$(basename "$vault")" \
  | docker cp - "$name:/var/www/app/plugins/"
docker start "$name" >/dev/null
port=$(docker port "$name" 80/tcp | head -1 | sed 's/.*://')
echo "   $name on http://localhost:$port"

echo '== 3. import and export in headless Chrome (CDP)'
KB_URL="http://localhost:$port" KB_CONTAINER="$name" GATE_WORK="$work" node "$here/gate.mjs"

echo '== 4. readers: pykeepass and keepassxc-cli'
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$work:/work:ro" -v "$here/verify.py:/gate/verify.py:ro" "$gate_image" python3 -I /gate/verify.py /work

status=0
