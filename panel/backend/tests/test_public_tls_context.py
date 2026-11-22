# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""The panel checks the VPS certificate with its own root set, so a fresh
Windows without Let's Encrypt roots in its store still verifies it, and the
check stays strict."""

from __future__ import annotations

import ssl
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chameleon_panel.stealth.tls import _public_tls_context  # noqa: E402


def _root_names(context: ssl.SSLContext) -> set[str]:
    names = set()
    for cert in context.get_ca_certs():
        subject = dict(item[0] for item in cert["subject"])
        names.add(subject.get("commonName", ""))
    return names


def test_lets_encrypt_roots_are_trusted_without_the_system_store():
    roots = _root_names(_public_tls_context())
    assert {"ISRG Root X1", "ISRG Root X2"} <= roots


def test_verification_stays_strict():
    context = _public_tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
