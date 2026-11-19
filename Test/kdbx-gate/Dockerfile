# Throwaway container for the KeePassXC fixture gate (R3): keepassxc-cli from Alpine's signed repository, nothing
# installed on the host. Build it with no build context and run it with only the fixture folder mounted:
#   ./Test/fixtures/kdbx/make-fixtures.sh       (from the Vault folder; it builds and runs this image)
# The base image is pinned by digest (alpine:3.24, pulled 2026-11-19). py3-pykeepass isn't packaged for Alpine 3.24;
# the export gate (T23) adds it after a supply-chain vet.
FROM alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache keepassxc=2.7.12-r1 \
 && adduser -D -u 1000 gate
USER gate
WORKDIR /work
