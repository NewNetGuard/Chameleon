#!/bin/bash
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Build the Chameleon Panel release archive (run on Linux; needs Node.js/npm,
# Go is provisioned by ../ensure-go.sh when missing).
#
#   panel/build-release.sh            -> dist/chameleon-panel-<version>.tar.gz
#
# The archive holds everything install.sh needs; the server needs no build tools.
# Unpack it and double-click start_chameleon.bat in it (or run sudo ./install.sh).
set -euo pipefail

PANEL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$PANEL/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
NAME="chameleon-panel-$VERSION"
OUT="$ROOT/dist"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

echo "[release] Go binaries"
bash "$ROOT/build.sh" >/dev/null

if [[ "${PANEL_WEB_PREBUILT:-0}" == "1" ]]; then
  # The web UI was built on another machine (panel/frontend: npm run build).
  [[ -f "$PANEL/frontend/dist/index.html" ]] || { echo "no prebuilt web UI" >&2; exit 1; }
else
  echo "[release] web UI"
  (cd "$PANEL/frontend" && npm ci --no-audit --no-fund >/dev/null && npm run build >/dev/null)
fi

echo "[release] assembling $NAME"
R="$WORK/$NAME"
install -d "$R/bin" "$R/server" "$R/panel" "$R/root" "$R/systemd"
for binary in chameleon-client-amd64 chameleon-client-arm64 chameleon-server-amd64; do
  install -m 0755 "$ROOT/bin/$binary" "$R/bin/$binary"
done
cp -R "$ROOT/server/site" "$ROOT/server/nginx" "$R/server/"
cp -R "$PANEL/frontend/dist" "$R/web"
cp -R "$PANEL/backend/chameleon_panel" "$R/panel/"
find "$R/panel" -name __pycache__ -type d -prune -exec rm -rf {} +
install -m 0644 "$PANEL/backend/requirements.txt" "$R/panel/requirements.txt"
find "$PANEL/root" -maxdepth 1 -type f ! -name "*.pyc" -exec cp {} "$R/root/" \;
cp "$PANEL/systemd/"*.service "$R/systemd/"
install -m 0755 "$PANEL/install.sh" "$PANEL/uninstall.sh" "$ROOT/start_chameleon.bat" "$R/"
install -m 0644 "$ROOT/VERSION" "$ROOT/LICENSE" "$ROOT/NOTICE" "$R/"
bash "$ROOT/panel/source-notice.sh" "$VERSION" > "$R/SOURCE.txt"
GO="$(bash "$ROOT/ensure-go.sh")"
MODFILE="$(bash "$ROOT/tools/prepare_http2_modfile.sh" "$GO")"
# License texts of every third-party component in the package.
(cd "$ROOT" && PATH="$(dirname "$GO"):$PATH" python3 tools/third_party_licenses.py \
  "$R/THIRD_PARTY_LICENSES.txt" --modfile "$MODFILE" \
  --go linux:./cmd/chameleon-client --go linux:./server --npm "$PANEL/frontend" \
  --notices "$ROOT/third_party/notices")

python3 "$ROOT/tools/check_release_contents.py" "$R"
install -d "$OUT"
tar -C "$WORK" --owner=0 --group=0 -czf "$OUT/$NAME.tar.gz" "$NAME"
(cd "$OUT" && sha256sum "$NAME.tar.gz") | tee "$OUT/$NAME.tar.gz.sha256"
