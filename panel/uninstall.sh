#!/bin/bash
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# Remove the Chameleon Panel from this server.
#
#   sudo ./uninstall.sh          stop the tunnel, remove the panel, keep its state
#   sudo ./uninstall.sh --purge  also delete tunnel keys, VPS credentials and the password
#
# The Chameleon server on the VPS is not touched; remove it from the panel's
# Server tab first if it should go too.
set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
PURGE=false
[[ "${1:-}" == "--purge" ]] && PURGE=true

[[ "$EUID" -eq 0 ]] || { echo "run as root: sudo ./uninstall.sh" >&2; exit 1; }

# Tunnel, routing and every guard down first, while the helpers still exist.
if [[ -x /usr/lib/chameleon/chameleon-runner ]]; then
  /usr/lib/chameleon/chameleon-runner chameleon-netctl down >/dev/null 2>&1 || true
fi

UNITS=(chameleon-panel.service chameleon-resume.service chameleon-dns.service
       chameleon-guard.service chameleon-panel-firewall.service
       chameleon-client.service chameleon-tcp.socket)
for unit in "${UNITS[@]}"; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$unit" "/run/systemd/system/$unit"
done
systemctl daemon-reload

rm -f /etc/sudoers.d/chameleon-panel /usr/local/sbin/chameleon-panel
rm -rf /opt/chameleon /usr/lib/chameleon /run/chameleon

if [[ "$PURGE" == "true" ]]; then
  rm -rf /var/lib/chameleon-panel /var/lib/chameleon /etc/chameleon /var/log/chameleon \
    /run/chameleon-credentials
  for account in chameleon chameleon-client chameleon-dns; do
    userdel "$account" >/dev/null 2>&1 || true
    groupdel "$account" >/dev/null 2>&1 || true
  done
  echo "Chameleon Panel removed, including its state."
else
  echo "Chameleon Panel removed. State kept in /var/lib/chameleon-panel and /etc/chameleon;"
  echo "remove it with: sudo ./uninstall.sh --purge"
fi
