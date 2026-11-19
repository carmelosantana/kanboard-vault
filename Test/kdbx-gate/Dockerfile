# Throwaway container for the KeePassXC gates (R3): keepassxc-cli and pykeepass, nothing installed on the host. Build
# it with no build context and run it with only a scratch folder mounted and no network:
#   ./Test/fixtures/kdbx/make-fixtures.sh       (T22: the import fixtures)
#   ./Test/kdbx-gate/run.sh                      (T23: the export gate; it builds and runs this image)
# The base image is pinned by digest (alpine:3.24, pulled 2026-11-19); everything else comes from Alpine's signed
# repository, except pykeepass, which Alpine 3.24 doesn't package (`apk search -x py3-pykeepass` is empty).
# pykeepass 4.2.0 is installed from PyPI by hash only (--require-hashes, --no-deps, wheel only), after the supply-chain
# vet recorded in Assets/vendor/VENDOR.md. Its dependencies come from Alpine (lxml, argon2-cffi, pycryptodomex,
# construct; importlib.metadata is in the standard library). Its pyotp requirement is never imported by pykeepass, so
# it isn't installed.
FROM alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache keepassxc=2.7.12-r1 python3 py3-pip py3-lxml py3-argon2-cffi py3-pycryptodomex py3-construct \
 && printf '%s\n' 'pykeepass==4.2.0 --hash=sha256:8d6100788422eb8a43710b227fde873f7684d08bf0117eb43c8ae346644b086d' > /tmp/pykeepass.txt \
 && pip install --no-cache-dir --no-deps --only-binary=:all: --require-hashes --break-system-packages -r /tmp/pykeepass.txt \
 && rm /tmp/pykeepass.txt \
 && apk del --no-cache py3-pip \
 && adduser -D -u 1000 gate
USER gate
WORKDIR /work
