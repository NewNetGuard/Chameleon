#!/bin/bash
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Build the Chameleon release for Windows (run in Git Bash on Windows or on
# Linux; needs Python 3 with pip, Node.js/npm unless PANEL_WEB_PREBUILT=1, and
# network access the first time):
#
#   panel/build-windows.sh            -> dist/chameleon-windows-<version>.zip
#
# The archive is complete: unpack it and double-click start_chameleon.bat in it, on
# a computer that has nothing else (no WSL, no Python, no Go).
set -euo pipefail

PANEL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$PANEL/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT/VERSION")"
NAME="chameleon-windows-$VERSION"
OUT="$ROOT/dist"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

# Same build-cache rule as ensure-go.sh.
if [[ -n "${CHAMELEON_BUILD_ROOT:-}" ]]; then
  BUILD_ROOT="$CHAMELEON_BUILD_ROOT"
elif [[ -e "$ROOT/.git" ]]; then
  BUILD_ROOT="$ROOT/.build"
else
  BUILD_ROOT="$(cd "$ROOT/.." && pwd)/.build"
fi
DOWNLOADS="$BUILD_ROOT/downloads"

# Pinned third-party runtime pieces, verified against the published hashes.
WINTUN_URL="https://www.wintun.net/builds/wintun-0.14.1.zip"
WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
PYTHON_VERSION="3.14"
PYTHON_RELEASE="3.14.10"
PYTHON_URL="https://www.python.org/ftp/python/$PYTHON_RELEASE/python-$PYTHON_RELEASE-embed-amd64.zip"
PYTHON_SHA256="90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159"

# A real interpreter (Windows also has a "python3" Store shortcut that is not).
PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
      PY="$(command -v "$candidate")"; break
    fi
  done
fi
[[ -n "$PY" ]] || { echo "Python 3 is required" >&2; exit 1; }
native_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

fetch() { # $1=url $2=sha256 -> prints the cached file path
  local file="$DOWNLOADS/$(basename "$1")"
  mkdir -p "$DOWNLOADS"
  if [[ ! -f "$file" ]] || ! echo "$2  $file" | sha256sum -c --status; then
    echo "[windows] downloading $(basename "$1")" >&2
    curl -sSfL -o "$file.part" "$1"
    mv -f -- "$file.part" "$file"
  fi
  echo "$2  $file" | sha256sum -c --status || { echo "checksum mismatch: $file" >&2; exit 1; }
  printf '%s' "$file"
}

unzip_to() { # $1=zip $2=dir [$3=member prefix]
  "$PY" - "$(native_path "$1")" "$(native_path "$2")" "${3:-}" <<'PYZIP'
import pathlib, sys, zipfile
archive, target, prefix = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
with zipfile.ZipFile(archive) as z:
    for info in z.infolist():
        if info.is_dir() or not info.filename.startswith(prefix):
            continue
        rel = pathlib.PurePosixPath(info.filename[len(prefix):])
        if rel.is_absolute() or ".." in rel.parts:
            raise SystemExit("unsafe archive member: " + info.filename)
        dest = target.joinpath(*rel.parts)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(z.read(info))
PYZIP
}

R="$WORK/$NAME"
mkdir -p "$R/bin" "$R/server" "$R/panel" "$R/python"

echo "[windows] Go binaries"
GO="$(bash "$ROOT/ensure-go.sh")"
MODFILE="$(native_path "$(bash "$ROOT/tools/prepare_http2_modfile.sh" "$GO")")"
(cd "$ROOT" &&
  CGO_ENABLED=0 GOOS=windows GOARCH=amd64 "$GO" build -modfile="$MODFILE" -trimpath -buildvcs=false \
    -ldflags "-s -w" -o "$(native_path "$R/chameleon-svc.exe")" ./cmd/chameleon-windows &&
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "$GO" build -modfile="$MODFILE" -trimpath -buildvcs=false \
    -o "$(native_path "$R/bin/chameleon-server-amd64")" ./server)

if [[ "${PANEL_WEB_PREBUILT:-0}" == "1" ]]; then
  [[ -f "$PANEL/frontend/dist/index.html" ]] || { echo "no prebuilt web UI" >&2; exit 1; }
else
  echo "[windows] web UI"
  (cd "$PANEL/frontend" && npm ci --no-audit --no-fund >/dev/null && npm run build >/dev/null)
fi

echo "[windows] Wintun"
WINTUN_ZIP="$(fetch "$WINTUN_URL" "$WINTUN_SHA256")"
unzip_to "$WINTUN_ZIP" "$WORK/wintun" "wintun/"
cp "$WORK/wintun/bin/amd64/wintun.dll" "$R/wintun.dll"
cp "$WORK/wintun/LICENSE.txt" "$R/LICENSE.Wintun.txt"

echo "[windows] Python $PYTHON_VERSION runtime and panel dependencies"
PYTHON_ZIP="$(fetch "$PYTHON_URL" "$PYTHON_SHA256")"
unzip_to "$PYTHON_ZIP" "$R/python"
# The embedded interpreter reads its module path only from this file.
printf 'python314.zip\r\n.\r\nLib\\site-packages\r\n..\\panel\r\n' > "$R/python/python314._pth"
"$PY" -m pip install --quiet --disable-pip-version-check --no-compile \
  --target "$(native_path "$R/python/Lib/site-packages")" \
  --platform win_amd64 --python-version "$PYTHON_VERSION" --implementation cp --only-binary=:all: --require-hashes \
  -r "$(native_path "$PANEL/backend/requirements.txt")"
# pip's console-script launchers (fastapi.exe, uvicorn.exe, ...) start the build
# machine's Python by its absolute path: unusable on another computer, and the
# panel never runs them (it starts python.exe -m), so they are not shipped.
rm -rf -- "$R/python/Lib/site-packages/bin"

echo "[windows] assembling $NAME"
cp -R "$ROOT/server/site" "$ROOT/server/nginx" "$R/server/"
cp -R "$PANEL/frontend/dist" "$R/web"
cp -R "$PANEL/backend/chameleon_panel" "$R/panel/"
find "$R" -name __pycache__ -type d -prune -exec rm -rf {} +
cp "$ROOT/VERSION" "$ROOT/LICENSE" "$ROOT/NOTICE" "$ROOT/start_chameleon.bat" "$R/"
bash "$ROOT/panel/source-notice.sh" "$VERSION" > "$R/SOURCE.txt"
cp "$ROOT/cmd/chameleon-windows/winfw/LICENSE.WireGuard" "$R/LICENSE.WireGuard.txt"
# License texts of every third-party component in the package (Wintun,
# WireGuard and Python's own LICENSE.txt are shipped as they come, too).
(cd "$ROOT" && PATH="$(dirname "$GO"):$PATH" "$PY" tools/third_party_licenses.py \
  "$(native_path "$R/THIRD_PARTY_LICENSES.txt")" --modfile "$MODFILE" \
  --go windows:./cmd/chameleon-windows --go linux:./server \
  --npm "$(native_path "$PANEL/frontend")" --python "$(native_path "$R/python/Lib/site-packages")" \
  --python-version "$PYTHON_RELEASE" --notices "$(native_path "$ROOT/third_party/notices")")

"$PY" "$ROOT/tools/check_release_contents.py" "$(native_path "$R")"
mkdir -p "$OUT"
rm -f -- "$OUT/$NAME.zip"
"$PY" - "$(native_path "$WORK")" "$NAME" "$(native_path "$OUT/$NAME.zip")" <<'PYZIP'
import os, sys, zipfile
base, name, out = sys.argv[1], sys.argv[2], sys.argv[3]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for folder, _, files in sorted(os.walk(os.path.join(base, name))):
        for f in sorted(files):
            path = os.path.join(folder, f)
            z.write(path, os.path.relpath(path, base).replace(os.sep, "/"))
PYZIP
(cd "$OUT" && sha256sum "$NAME.zip") | tee "$OUT/$NAME.zip.sha256"
