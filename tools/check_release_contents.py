#!/usr/bin/env python3
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
"""Reject private-key files and private PEM blocks before packaging/signing."""
from __future__ import annotations

import argparse
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

PRIVATE_BLOCK = re.compile(rb"(?m)^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\r?$")


def check_name(name: str) -> None:
    path = PurePosixPath(name.replace("\\", "/"))
    parts = [p.lower() for p in path.parts]
    if path.is_absolute() or ".." in parts or any(":" in p for p in parts):
        raise ValueError(f"Unsafe release path: {name}")
    if any(p in {"chameleon-keys", "secrets", ".git"} for p in parts):
        raise ValueError(f"Private directory in release: {name}")
    if parts and (parts[-1].startswith(".env") or
                  parts[-1] in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"} or
                  path.suffix.lower() in {".key", ".p12", ".pfx", ".keystore", ".pk8", ".p8", ".private"}):
        raise ValueError(f"Private file in release: {name}")


def check_stream(name: str, stream) -> None:
    check_name(name)
    tail = b""
    while chunk := stream.read(1024 * 1024):
        data = tail + chunk
        if PRIVATE_BLOCK.search(data):
            raise ValueError(f"Private PEM key in release: {name}")
        tail = data[-512:]


def check_release(path: Path) -> None:
    if path.is_dir():
        for item in path.rglob("*"):
            name = item.relative_to(path).as_posix()
            check_name(name)
            if item.is_symlink():
                raise ValueError(f"Symlink in release: {name}")
            if item.is_file():
                with item.open("rb") as stream:
                    check_stream(name, stream)
    elif path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                check_name(item.filename)
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError(f"Symlink in release: {item.filename}")
                if not item.is_dir():
                    with archive.open(item) as stream:
                        check_stream(item.filename, stream)
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            for item in archive:
                check_name(item.name)
                if item.isfile():
                    with archive.extractfile(item) as stream:
                        check_stream(item.name, stream)
                elif not item.isdir():
                    raise ValueError(f"Special file in release: {item.name}")
    else:
        raise ValueError("Expected a staging directory, .zip or .tar.gz archive")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        for path in args.paths:
            check_release(path)
            print(f"Release contents OK: {path.name}")
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
