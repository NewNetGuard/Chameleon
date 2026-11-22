#!/usr/bin/env python3
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""License notices for the Rust code compiled into binary Python wheels.

    tools/rust_wheel_notices.py OUTDIR PACKAGE==VERSION [...]

Some Python packages the panel ships on Windows (cryptography, bcrypt,
pydantic-core) contain native modules built from Rust crates, and their wheels
carry only the package's own license. For each PACKAGE==VERSION this tool
downloads the source archive from PyPI (checked against PyPI's SHA-256), reads
its Cargo.lock, downloads every crates.io crate listed there (checked against
the Cargo.lock checksum) and writes OUTDIR/python-<package>-<version>-rust.txt
with each crate's declared license and its license files.

Cargo.lock also lists build-time and other-platform crates; they are included,
so the notice covers more than strictly needed rather than less. Run it again
whenever one of these packages changes version (panel/backend/requirements.txt);
tools/third_party_licenses.py refuses a notice that does not match the shipped
version. Downloads are cached in .build/downloads.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".build" / "downloads"
LICENSE_NAMES = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|AUTHORS?|UNLICENSE)([.\-_].*)?$", re.I)
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def fetch(url: str, path: Path, sha256: str) -> bytes:
    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == sha256:
        return path.read_bytes()
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != sha256:
        raise SystemExit(f"checksum mismatch: {url}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def sdist_cargo_lock(package: str, version: str) -> dict:
    meta = json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{package}/{version}/json", timeout=30))
    sdist = next(u for u in meta["urls"] if u["packagetype"] == "sdist")
    data = fetch(sdist["url"], CACHE / "pypi" / sdist["filename"], sdist["digests"]["sha256"])
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        locks = sorted((m for m in archive.getmembers() if m.name.endswith("/Cargo.lock")), key=lambda m: m.name.count("/"))
        if not locks:
            raise SystemExit(f"{package} {version}: no Cargo.lock in the source archive")
        return tomllib.loads(archive.extractfile(locks[0]).read().decode("utf-8"))


def crate_notice(name: str, version: str, checksum: str) -> tuple[str, list[tuple[str, str]]]:
    data = fetch(f"https://static.crates.io/crates/{name}/{name}-{version}.crate",
                 CACHE / "crates" / f"{name}-{version}.crate", checksum)
    declared, texts = "", []
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            parts = member.name.split("/")
            if len(parts) != 2 or not member.isfile():
                continue
            if parts[1] == "Cargo.toml":
                manifest = tomllib.loads(archive.extractfile(member).read().decode("utf-8", "replace"))
                package = manifest.get("package", {})
                declared = package.get("license") or (f"see {package['license-file']}" if package.get("license-file") else "")
            elif LICENSE_NAMES.match(parts[1]):
                texts.append((parts[1], archive.extractfile(member).read().decode("utf-8", "replace").strip()))
    if not texts:
        supplement = ROOT / "third_party" / "licenses" / "rust" / f"{name}-{version}"
        for path in sorted(supplement.glob("LICENSE*")):
            texts.append((path.name, path.read_text(encoding="utf-8").strip()))
    if not texts:
        raise SystemExit(f"{name} {version}: missing license text; add a version-specific upstream supplement")
    return declared or "not declared", sorted(texts)


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    outdir = Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)
    for spec in sys.argv[2:]:
        package, version = spec.split("==", 1)
        lock = sdist_cargo_lock(package, version)
        crates = sorted((p for p in lock.get("package", []) if p.get("source") == CRATES_IO),
                        key=lambda p: (p["name"].lower(), p["version"]))
        summary, bodies = [], []
        for crate in crates:
            declared, texts = crate_notice(crate["name"], crate["version"], crate["checksum"])
            note = "" if texts else " (the crate ships no license file)"
            summary.append(f"  {crate['name']} {crate['version']} — {declared}{note}")
            if texts:
                body = "\n\n".join(f"--- {fname} ---\n{text}" for fname, text in texts)
                bodies.append(f"\n{'-' * 78}\n{crate['name']} {crate['version']}\n{'-' * 78}\n\n{body}\n")
        header = (f"Component: Rust crates compiled into the Python package {package}\n"
                  f"Applies-To: {package}=={version}\n\n"
                  f"The native module of {package} {version} is built from the crates below, as listed\n"
                  f"in the Cargo.lock of its source distribution (build-time and other-platform crates\n"
                  f"included). Each keeps its own license.\n")
        target = outdir / f"python-{package}-{version}-rust.txt"
        target.write_text(header + "\n" + "\n".join(summary) + "\n" + "".join(bodies), encoding="utf-8", newline="\n")
        print(f"{target}: {len(crates)} crates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
