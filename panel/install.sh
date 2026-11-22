#!/bin/bash
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Install or update the Chameleon Panel on a Debian or Ubuntu server.
#
#   sudo ./install.sh
#
# Run from an unpacked release (see build-release.sh). The panel is reachable
# from the local network only: https://<server LAN address>:8443
# State (tunnel keys, VPS credentials, panel password) survives an update.
set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/opt/chameleon"
LIBEXEC="/usr/lib/chameleon"
STATE="/var/lib/chameleon-panel"
CONF="/etc/chameleon"
LOGDIR="/var/log/chameleon"
UNITS=(chameleon-panel-firewall.service chameleon-guard.service chameleon-dns.service
       chameleon-resume.service chameleon-panel.service)

say() { printf '\033[1;36m[chameleon]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[chameleon]\033[0m %s\n' "$*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || die "run as root: sudo ./install.sh"
[[ -d /run/systemd/system ]] || die "systemd is required"
command -v apt-get >/dev/null 2>&1 || die "only Debian and Ubuntu are supported"
for item in VERSION bin/chameleon-server-amd64 server/site server/nginx web/index.html \
    panel/chameleon_panel panel/requirements.txt root/chameleon-runner root/chameleon-netctl \
    systemd/chameleon-panel.service; do
  [[ -e "$HERE/$item" ]] || die "incomplete release: $item is missing"
done
VERSION="$(tr -d '[:space:]' < "$HERE/VERSION")"

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported CPU architecture $(uname -m)" ;;
esac
[[ -x "$HERE/bin/chameleon-client-$ARCH" ]] || die "release has no client for $ARCH"

say "installing Chameleon Panel $VERSION ($ARCH)"

# ── packages ────────────────────────────────────────────────────────────────
say "updating Ubuntu/Debian package lists"
DEBIAN_FRONTEND=noninteractive apt-get update
say "installing system packages"
# Keep package output visible and avoid a nested dpkg terminal under sudo.
DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Use-Pty=0 install -y --no-install-recommends \
  python3 python3-venv iptables iproute2 kmod openssl sudo openssh-client \
  ca-certificates
command -v systemd-creds >/dev/null 2>&1 \
  || say "warning: systemd-creds is missing (systemd 250+ needed); VPS credentials cannot be stored"

# ── accounts ────────────────────────────────────────────────────────────────
ensure_account() { # name
  getent group "$1" >/dev/null 2>&1 || groupadd --system "$1"
  if ! id -u "$1" >/dev/null 2>&1; then
    useradd --system --gid "$1" --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin "$1"
  fi
}
ensure_account chameleon        # the panel
ensure_account chameleon-client # the tunnel daemon
ensure_account chameleon-dns    # the fail-closed resolver

# ── product files (root-owned, read-only for services) ──────────────────────
say "installing files"
STAGE="$(mktemp -d "${PREFIX}.new.XXXXXX")"
trap 'rm -rf -- "$STAGE"' EXIT
install -d -m 0755 "$STAGE/bin" "$STAGE/server" "$STAGE/panel"
install -m 0755 "$HERE/bin/chameleon-client-$ARCH" "$STAGE/bin/chameleon-client"
install -m 0755 "$HERE/bin/chameleon-server-amd64" "$STAGE/bin/chameleon-server-amd64"
cp -R "$HERE/server/site" "$HERE/server/nginx" "$STAGE/server/"
cp -R "$HERE/web" "$STAGE/web"
cp -R "$HERE/panel/chameleon_panel" "$STAGE/panel/"
install -m 0644 "$HERE/panel/requirements.txt" "$HERE/VERSION" "$STAGE/"
chown -R root:root "$STAGE"
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f ! -path "$STAGE/bin/*" ! -name easypi-chameleon-nginx -exec chmod 0644 {} +
chmod 0755 "$STAGE/server/nginx/easypi-chameleon-nginx"

# Python environment: reuse when the requirements did not change.
if [[ -x "$PREFIX/venv/bin/python" ]] && cmp -s "$PREFIX/requirements.txt" "$STAGE/requirements.txt"; then
  mv "$PREFIX/venv" "$STAGE/venv"
else
  say "creating the Python environment"
  python3 -m venv "$STAGE/venv"
  say "installing Python panel dependencies"
  "$STAGE/venv/bin/pip" install --disable-pip-version-check --no-cache-dir \
    --only-binary=:all: --require-hashes \
    -r "$STAGE/requirements.txt"
fi
chown -R root:root "$STAGE/venv"

systemctl stop chameleon-panel.service >/dev/null 2>&1 || true
if [[ -d "$PREFIX" ]]; then
  rm -rf -- "${PREFIX}.old"
  mv "$PREFIX" "${PREFIX}.old"
fi
mv "$STAGE" "$PREFIX"
chmod 0755 "$PREFIX"
trap - EXIT
rm -rf -- "${PREFIX}.old"

# Root helpers: the only privileged entry points.
install -d -o root -g root -m 0755 "$LIBEXEC"
for script in chameleon-runner chameleon-netctl chameleon-secrets chameleon-panel-firewall; do
  install -o root -g root -m 0755 "$HERE/root/$script" "$LIBEXEC/$script"
done
for module in privileged_timeout.py chameleon_dns.py; do
  install -o root -g root -m 0644 "$HERE/root/$module" "$LIBEXEC/$module"
done

# ── state, logs, configuration ──────────────────────────────────────────────
install -d -o chameleon -g chameleon -m 0700 "$STATE"
install -d -o root -g chameleon -m 0750 "$LOGDIR"
install -d -o root -g root -m 0755 "$CONF"
install -d -o root -g chameleon -m 0750 "$CONF/panel"
if [[ ! -f "$CONF/panel.env" ]]; then
  printf 'CHAMELEON_PANEL_PORT=8443\n' > "$CONF/panel.env"
  chmod 0644 "$CONF/panel.env"
fi
# shellcheck disable=SC1091
. "$CONF/panel.env"
PORT="${CHAMELEON_PANEL_PORT:-8443}"

if [[ ! -s "$CONF/panel/tls.key" || ! -s "$CONF/panel/tls.crt" ]]; then
  say "creating the panel TLS certificate"
  san="DNS:$(hostname),DNS:localhost,IP:127.0.0.1"
  for address in $(ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]}'); do
    san="$san,IP:$address"
  done
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
    -subj "/CN=Chameleon Panel" -addext "subjectAltName=$san" \
    -keyout "$CONF/panel/tls.key" -out "$CONF/panel/tls.crt" >/dev/null 2>&1
fi
chown root:chameleon "$CONF/panel/tls.key" "$CONF/panel/tls.crt"
chmod 0640 "$CONF/panel/tls.key"
chmod 0644 "$CONF/panel/tls.crt"

# ── sudo: exactly one command ───────────────────────────────────────────────
SUDOERS="/etc/sudoers.d/chameleon-panel"
printf 'chameleon ALL=(root) NOPASSWD: %s/chameleon-runner\n' "$LIBEXEC" > "$SUDOERS.new"
chmod 0440 "$SUDOERS.new"
visudo -cf "$SUDOERS.new" >/dev/null || die "generated sudoers rule is invalid"
mv -f "$SUDOERS.new" "$SUDOERS"

# Command line: chameleon-panel setup-code / reset-password / disable, as the panel user.
cat > /usr/local/sbin/chameleon-panel <<EOF
#!/bin/bash
# Chameleon Panel command line (runs as the panel user).
exec runuser -u chameleon -- env PYTHONPATH=$PREFIX/panel \\
  $PREFIX/venv/bin/python -m chameleon_panel "\$@"
EOF
chmod 0755 /usr/local/sbin/chameleon-panel

# ── services ────────────────────────────────────────────────────────────────
say "installing services"
for unit in "${UNITS[@]}"; do
  install -o root -g root -m 0644 "$HERE/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable "${UNITS[@]}" >/dev/null 2>&1
systemctl restart chameleon-panel-firewall.service
systemctl start chameleon-guard.service chameleon-dns.service
say "starting the panel"
systemctl restart chameleon-panel.service

# The password is created in the panel; this one-time code proves it is the
# owner doing it. Lost password: sudo chameleon-panel reset-password
SETUP_CODE=""
if [[ ! -s "$STATE/panel_password.json" ]]; then
  SETUP_CODE="$(/usr/local/sbin/chameleon-panel setup-code)"
fi

fingerprint="$(openssl x509 -in "$CONF/panel/tls.crt" -noout -fingerprint -sha256 | cut -d= -f2)"
# Only local-network addresses: the panel firewall drops every other source.
local_addresses="$(ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]}' |
  grep -E '^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)' || true)"
say "installation complete. Open the panel on this computer:"
printf '    https://localhost:%s\n' "$PORT"
if [[ -z "$local_addresses" ]]; then
  say "for a headless server without a local network address, forward the panel over SSH:"
  printf '    ssh -L %s:127.0.0.1:%s root@<server address>\n' "$PORT" "$PORT"
  printf '    then https://localhost:%s\n' "$PORT"
fi
say "compare the browser certificate's SHA-256 fingerprint before accepting it or entering credentials."
say "certificate SHA-256 fingerprint:"
printf '    %s\n' "$fingerprint"
if [[ -n "$SETUP_CODE" ]]; then
  say "first-time setup code: $SETUP_CODE"
  say "use this code if you set up the panel from another device."
fi
