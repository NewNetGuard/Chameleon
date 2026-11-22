# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""The deployment endpoint check names the actual problem to the user."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_panel.stealth.ssh import StealthSshMixin  # noqa: E402

VPS = "8.8.8.8"


def _address(server_address, ssh_host=VPS):
    return StealthSshMixin._ip_shield_address(
        {"server_address": server_address, "ssh": {"host": ssh_host}}
    )


@pytest.mark.parametrize("missing", ["", "   ", None])
def test_missing_client_address_points_to_the_client_tab(missing):
    with pytest.raises(ValueError, match="No VPS address is saved yet.*Save client"):
        _address(missing)


def test_wrong_port_names_the_saved_address():
    with pytest.raises(ValueError, match=r"must use port 443 \(saved: 8\.8\.8\.8:8443\)"):
        _address(f"{VPS}:8443")


def test_valid_endpoint_is_accepted():
    assert _address(f"{VPS}:443") == VPS


def test_endpoint_must_match_the_ssh_host():
    with pytest.raises(ValueError, match="must match the VPS SSH address"):
        _address("1.1.1.1:443")
