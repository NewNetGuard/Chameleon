#!/usr/bin/env bash
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Build the Chameleon Linux binaries. Requires exactly Go 1.27.4 (or set $GO);
# ensure-go.sh provisions it when missing.
#
#   ./build.sh            # server (amd64) + Linux clients for amd64 and arm64
#   ./build.sh arm64      # server (amd64) + arm64 client
#   ./build.sh amd64      # server (amd64) + amd64 client
#
# Outputs:
#   bin/chameleon-server-amd64   -> your VPS, deployed by the panel
#   bin/chameleon-client-amd64   -> Linux computer (x86-64)
#   bin/chameleon-client-arm64   -> Linux computer (arm64)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# systemd-run and other non-login installers may intentionally have no HOME.
# Give Go private, per-build caches rather than falling back to a shared or
# caller-controlled location. This also prevents a privileged build from
# consuming modules or compiled objects selected through inherited env.
GO_BUILD_CACHE="$(mktemp -d "${TMPDIR:-/tmp}/chameleon-go.XXXXXX")"
# Go keeps its module cache read-only; make it writable again so a build
# without root can remove it.
cleanup() { chmod -R u+w -- "${GO_BUILD_CACHE}" 2>/dev/null; rm -rf -- "${GO_BUILD_CACHE}"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
export GOPATH="${GO_BUILD_CACHE}/gopath"
export GOMODCACHE="${GO_BUILD_CACHE}/gomodcache"
export GOCACHE="${GO_BUILD_CACHE}/gocache"
mkdir -p "${GOPATH}" "${GOMODCACHE}" "${GOCACHE}"

# Helpers are invoked through bash rather than relying on their executable bit.
GO="$(bash "${ROOT}/ensure-go.sh")" || { echo "[build] no usable Go toolchain available" >&2; exit 1; }
FLOW_MODFILE="$(bash "${ROOT}/tools/prepare_http2_modfile.sh" "${GO}")" || {
  echo "[build] failed to prepare browser-like HTTP/2 flow module" >&2
  exit 1
}
OUT="$ROOT/bin"
mkdir -p "$OUT"
cd "$ROOT"

TARGET_ARCH="${1:-all}"
case "$TARGET_ARCH" in
  aarch64|arm64) CLIENT_ARCHES=(arm64) ;;
  x86_64|amd64) CLIENT_ARCHES=(amd64) ;;
  all) CLIENT_ARCHES=(amd64 arm64) ;;
  *) echo "[build] unsupported target architecture: $TARGET_ARCH" >&2; exit 1 ;;
esac

echo "Using: $("$GO" version)"
build() { # $1=goarch $2=outname $3=pkg
  echo "  building $2 ($1)"
  # -buildvcs=false: no VCS revision or dirty state is stamped into the binaries.
  CGO_ENABLED=0 GOOS=linux GOARCH="$1" "$GO" build -modfile="$FLOW_MODFILE" -trimpath -buildvcs=false -o "$OUT/$2" "$3"
}
rm -f -- "$OUT/chameleon-server-amd64"
build amd64 chameleon-server-amd64 ./server
for client_arch in "${CLIENT_ARCHES[@]}"; do
  rm -f -- "$OUT/chameleon-client-${client_arch}"
  build "$client_arch" "chameleon-client-${client_arch}" ./cmd/chameleon-client
done
chmod 0755 "$OUT/chameleon-server-amd64" "${CLIENT_ARCHES[@]/#/$OUT/chameleon-client-}"
echo "Done. Binaries in $OUT:"
ls -la "$OUT/chameleon-server-amd64" "${CLIENT_ARCHES[@]/#/$OUT/chameleon-client-}"
