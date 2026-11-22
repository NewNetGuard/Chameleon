# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Command line of the Chameleon Panel.

    chameleon-panel serve           run the panel (HTTPS, local network only)
    chameleon-panel setup-code      print a new one-time code for creating the
                                    panel password (only while none is set)
    chameleon-panel reset-password  forget the panel password, sign everybody
                                    out and print a new one-time code
    chameleon-panel disable         turn the tunnel off, like Disable in the
                                    panel: direct internet again

The password itself is only ever created in the panel, with the code.

``serve`` listens on HTTPS (8443 by default) and answers the local network only.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from chameleon_panel import paths


async def _serve_all(args: argparse.Namespace) -> None:
    import uvicorn

    from chameleon_panel.app import create_app

    cert = os.environ.get("CHAMELEON_PANEL_TLS_CERT", "/etc/chameleon/panel/tls.crt")
    key = os.environ.get("CHAMELEON_PANEL_TLS_KEY", "/etc/chameleon/panel/tls.key")
    server = uvicorn.Server(uvicorn.Config(
        create_app(), host=args.host, port=args.port, ssl_certfile=cert, ssl_keyfile=key,
        proxy_headers=False, server_header=False, date_header=False,
        log_level="info", access_log=False))
    await server.serve()


def _serve(args: argparse.Namespace) -> int:
    asyncio.run(_serve_all(args))
    return 0


def _stores():
    from chameleon_panel.security import PasswordStore, SetupCodeStore

    return (PasswordStore(paths.data_dir() / "panel_password.json"),
            SetupCodeStore(paths.data_dir() / "setup_code.json"))


def _setup_code(_args: argparse.Namespace) -> int:
    passwords, codes = _stores()
    if passwords.is_set():
        print("The panel password already exists.", file=sys.stderr)
        return 3
    print(codes.create())
    return 0


def _reset_password(_args: argparse.Namespace) -> int:
    passwords, codes = _stores()
    passwords.delete()
    print(codes.create())
    return 0


def _disable(_args: argparse.Namespace) -> int:
    from chameleon_panel.stealth.service import get_stealth_service

    result = asyncio.run(get_stealth_service().disable())
    if result.get("running") or result.get("killswitch"):
        print(f"Chameleon is still on: {result.get('error') or 'unknown error'}", file=sys.stderr)
        return 1
    print("Chameleon is off; this computer uses the internet directly.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="chameleon-panel")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run the panel")
    serve.add_argument("--host", default=os.environ.get("CHAMELEON_PANEL_HOST", "0.0.0.0"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("CHAMELEON_PANEL_PORT", "8443")))
    serve.set_defaults(func=_serve)
    sub.add_parser("setup-code", help="print a one-time code for the first password"
                   ).set_defaults(func=_setup_code)
    sub.add_parser("reset-password", help="forget the password and print a new setup code"
                   ).set_defaults(func=_reset_password)
    sub.add_parser("disable", help="turn the tunnel off, like Disable in the panel"
                   ).set_defaults(func=_disable)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
