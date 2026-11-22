#!/usr/bin/env bash
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Prepare an isolated build copy of pinned x/net and patch only the HTTP/2
# WINDOW_UPDATE batching threshold. No module-cache or tracked dependency files
# are modified.
set -euo pipefail

GO_BINARY="${1:?path to Go binary is required}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Same build-cache location rule as ensure-go.sh.
BUILD_ROOT="${CHAMELEON_BUILD_ROOT:-${ROOT}/.build}"
BUILD_DIR="${BUILD_ROOT}/chameleon-http2-flow"
PATCHED_MODULE="${BUILD_DIR}/xnet"
MODFILE="${BUILD_DIR}/chameleon.mod"
SUMFILE="${BUILD_DIR}/chameleon.sum"
EXPECTED='const inflowMinRefresh = 4 << 10'

cd "${ROOT}"
"${GO_BINARY}" mod download golang.org/x/net
XNET_DIR="$("${GO_BINARY}" list -mod=mod -m -f '{{.Dir}}' golang.org/x/net)"
SOURCE="${XNET_DIR}/http2/flow.go"
[[ -f "${SOURCE}" ]] || { echo "missing x/net/http2 flow source: ${SOURCE}" >&2; exit 1; }
matches="$(grep -Fxc "${EXPECTED}" "${SOURCE}" || true)"
[[ "${matches}" == 1 ]] || {
  echo "x/net/http2 flow threshold changed upstream; refusing a blind patch" >&2
  exit 1
}

mkdir -p "${BUILD_DIR}"
case "${PATCHED_MODULE}" in
  "${BUILD_DIR}/xnet") rm -rf -- "${PATCHED_MODULE}" ;;
  *) echo "unsafe patched module path" >&2; exit 1 ;;
esac
cp -R "${XNET_DIR}" "${PATCHED_MODULE}"
chmod -R u+w "${PATCHED_MODULE}"
sed -i 's/^const inflowMinRefresh = 4 << 10$/const inflowMinRefresh = 8 << 20/' \
  "${PATCHED_MODULE}/http2/flow.go"

cp "${ROOT}/go.mod" "${MODFILE}"
cp "${ROOT}/go.sum" "${SUMFILE}"
# Relative to the module root, which Go resolves it against: the binaries record
# the replacement path, and a relative one leaves no local directory in them.
REPLACE_PATH="$(realpath --relative-to="${ROOT}" "${PATCHED_MODULE}")"
case "${REPLACE_PATH}" in
  ../*) ;;
  *) REPLACE_PATH="./${REPLACE_PATH}" ;;
esac
printf '\nreplace golang.org/x/net => %s\n' "${REPLACE_PATH}" >> "${MODFILE}"
echo "${MODFILE}"
