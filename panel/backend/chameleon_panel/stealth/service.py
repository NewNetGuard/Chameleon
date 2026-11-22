# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Chameleon Panel service."""

# ruff: noqa: F401

# ruff: noqa: F401

from chameleon_panel.stealth.context import (
    Any,
    CLIENT_LOG,
    CONFIG_NAME,
    Dict,
    Ed25519PrivateKey,
    List,
    META_NAME,
    Optional,
    Path,
    REMOTE_SERVER_DIR,
    SCRIPT_REL,
    SECRET_SCRIPT_REL,
    SERVER_BIN,
    X25519PrivateKey,
    _DUCKDNS_DOMAIN,
    _DeploymentLease,
    _HEX32,
    _deployment_locked,
    _friendly_ssh_err,
    _gen_psk,
    _gen_x25519_public,
    _normalize_server_addr,
    asyncio,
    base64,
    hashlib,
    hmac,
    httpx,
    io,
    ipaddress,
    json,
    logger,
    logging,
    os,
    paths,
    posixpath,
    re,
    require_public_ipv4,
    serialization,
    socket,
    ssl,
    subprocess,
    time,
    wraps,
)

from chameleon_panel.stealth.client import StealthClientMixin
from chameleon_panel.stealth.deployment import StealthDeploymentMixin
from chameleon_panel.stealth.runtime import StealthRuntimeMixin
from chameleon_panel.stealth.ssh import StealthSshMixin
from chameleon_panel.stealth.tls import StealthTlsMixin


class StealthService(
    StealthClientMixin,
    StealthSshMixin,
    StealthTlsMixin,
    StealthDeploymentMixin,
    StealthRuntimeMixin,
):
    def __init__(self) -> None:
        self._data_dir = paths.data_dir()
        self._conf_path = self._data_dir / CONFIG_NAME
        self._meta_path = self._data_dir / META_NAME
        # Serialize client lifecycle changes with the watchdog reconciliation.
        # Concurrent privileged up/down operations can otherwise replace the
        # protected runtime config while systemd is opening it.
        self._runtime_lock = asyncio.Lock()


_service: Optional[StealthService] = None


def get_stealth_service() -> StealthService:
    global _service
    if _service is None:
        _service = StealthService()
    return _service
