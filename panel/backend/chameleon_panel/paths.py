# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Filesystem layout of an installed Chameleon Panel.

Every path can be moved for development and tests through environment
variables; an installation uses the defaults written by the installer.
"""

from __future__ import annotations

import os
from pathlib import Path

# Read-only product files: server binary, VPS site and nginx assets, web UI.
INSTALL_ROOT = Path(os.environ.get("CHAMELEON_PANEL_ROOT", "/opt/chameleon"))
# Writable state owned by the panel user: tunnel keys, settings, sessions.
DATA_DIR = Path(os.environ.get("CHAMELEON_PANEL_DATA", "/var/lib/chameleon-panel"))
# Root-owned privileged entry point, the only command the panel may sudo.
RUNNER = Path(os.environ.get("CHAMELEON_PANEL_RUNNER", "/usr/lib/chameleon/chameleon-runner"))
# Client log written by the root-managed client service.
CLIENT_LOG = Path(os.environ.get("CHAMELEON_CLIENT_LOG", "/var/log/chameleon/client.log"))


def data_dir() -> Path:
    return DATA_DIR


def server_binary() -> Path:
    """The amd64 server uploaded to the VPS."""
    return INSTALL_ROOT / "bin" / "chameleon-server-amd64"


def server_assets() -> Path:
    """`server/` of the Chameleon tree: the VPS site and the nginx tool."""
    return INSTALL_ROOT / "server"


def web_root() -> Path:
    return INSTALL_ROOT / "web"
