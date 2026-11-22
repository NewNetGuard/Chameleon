#!/usr/bin/env python3
# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Collect the license texts of every third-party component in a release package.

    tools/third_party_licenses.py OUTPUT --go GOOS:PKG [...] [--modfile FILE]
                                         [--npm DIR] [--python SITE_PACKAGES]

--go       Go packages built into the package, as GOOS:package (repeatable);
           their module dependencies are listed with `go list -deps`.
--modfile  the modfile the binaries are built with (the patched x/net copy).
--npm      the web UI directory; its production dependencies (package-lock.json,
           without dev-only packages) are bundled into the web UI.
--python   a site-packages directory shipped in the package.
--python-version  the version of the Python runtime shipped with it.
--notices  a directory of notices for code that the components above contain
           without shipping its license (third_party/notices/): OpenSSL inside
           the Python runtime and cryptography, Rust crates inside binary wheels.
           A notice applies when every `Applies-To: name==version` it names is
           shipped, or always with `Applies-To: any`; a notice for a shipped
           package of another version stops the build (regenerate it with
           tools/rust_wheel_notices.py).

The output names every component with its version and license kind, followed by
the full license texts. The build fails when a component has no license text.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LICENSE_NAMES = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|AUTHORS?)([.\-_].*)?$", re.I)


def kind(text: str) -> str:
    t = " ".join(text.split()).lower()
    if "apache license" in t and "version 2.0" in t:
        return "Apache-2.0"
    if "mozilla public license" in t and "2.0" in t:
        return "MPL-2.0"
    if "gnu lesser general public license" in t:
        return "LGPL-2.1" if "version 2.1" in t else "LGPL"
    if "python software foundation license" in t or "psf license" in t:
        return "PSF-2.0"
    if "permission to use, copy, modify, and/or distribute" in t:
        return "ISC"
    if "permission is hereby granted, free of charge" in t:
        return "MIT"
    if "redistribution and use in source and binary forms" in t:
        return "BSD-3-Clause" if "neither the name" in t or "may not be used to endorse" in t else "BSD-2-Clause"
    if "unlicense" in t:
        return "Unlicense"
    return "see text"


def license_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    files = [p for p in sorted(directory.iterdir()) if p.is_file() and LICENSE_NAMES.match(p.name)]
    for sub in ("licenses", "LICENSES"):
        if (directory / sub).is_dir():
            files += [p for p in sorted((directory / sub).rglob("*")) if p.is_file()]
    return files


def go_components(targets: list[str], modfile: str | None, root: Path) -> dict[str, tuple[str, Path]]:
    found: dict[str, tuple[str, Path]] = {}
    fmt = "{{with .Module}}{{.Path}}\t{{.Version}}\t{{if .Replace}}{{if .Replace.Dir}}{{.Replace.Dir}}{{else}}{{.Dir}}{{end}}{{else}}{{.Dir}}{{end}}\t{{.Main}}{{end}}"
    for target in targets:
        goos, pkg = target.split(":", 1)
        cmd = ["go", "list", "-deps", "-buildvcs=false", "-f", fmt]
        if modfile:
            cmd.append("-modfile=" + modfile)
        cmd.append(pkg)
        env = dict(os.environ, GOOS=goos, CGO_ENABLED="0")
        out = subprocess.run(cmd, cwd=root, env=env, check=True, capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) != 4 or parts[3] == "true" or not parts[2]:
                continue
            version = parts[1] or "?"
            if parts[0] == "golang.org/x/net" and modfile:
                version += " (build copy: http2 inflowMinRefresh changed to 8 MiB)"
            found[parts[0]] = (version, Path(parts[2]))
    # The Go standard library and runtime are compiled into every program too.
    goroot = subprocess.run(["go", "env", "GOROOT"], check=True, capture_output=True, text=True).stdout.strip()
    goversion = subprocess.run(["go", "env", "GOVERSION"], check=True, capture_output=True, text=True).stdout.strip()
    found["Go standard library and runtime"] = (goversion, Path(goroot))
    return found


def npm_components(web: Path) -> dict[str, tuple[str, Path]]:
    lock = json.loads((web / "package-lock.json").read_text(encoding="utf-8"))
    found = {}
    for key, meta in lock.get("packages", {}).items():
        if not key.startswith("node_modules/") or meta.get("dev") or meta.get("devOptional"):
            continue
        name = key.split("node_modules/")[-1]
        found[name] = (meta.get("version", "?"), web / key)
    return found


def python_components(site: Path) -> dict[str, tuple[str, Path]]:
    found = {}
    for info in sorted(site.glob("*.dist-info")):
        meta = (info / "METADATA").read_text(encoding="utf-8", errors="replace")
        name = re.search(r"(?m)^Name: (.+)$", meta)
        version = re.search(r"(?m)^Version: (.+)$", meta)
        found[name.group(1).strip() if name else info.name] = (version.group(1).strip() if version else "?", info)
    return found


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def applicable_notices(directory: Path, shipped: dict[str, str]) -> tuple[list[tuple[str, str]], list[str]]:
    """Notices whose Applies-To packages are all shipped; stale ones as errors."""
    notices, stale = [], []
    for path in sorted(directory.glob("*.txt")):
        text = path.read_text(encoding="utf-8")
        component = re.search(r"(?m)^Component: (.+)$", text)
        applies = re.search(r"(?m)^Applies-To: (.+)$", text)
        if not component or not applies:
            stale.append(f"{path.name}: no Component/Applies-To header")
            continue
        if applies.group(1).strip() == "any":  # shipped in every package
            notices.append((component.group(1).strip(), text))
            continue
        wanted = dict(item.split("==", 1) for item in applies.group(1).split())
        present = {canonical(n): v for n, v in wanted.items() if canonical(n) in shipped}
        if len(present) < len(wanted):
            continue  # this package does not contain the component
        wrong = [f"{n} {v} (shipped {shipped[n]})" for n, v in present.items() if shipped[n] != v]
        if wrong:
            stale.append(f"{path.name} is for " + ", ".join(wrong))
            continue
        notices.append((component.group(1).strip(), text))
    return notices, stale


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("output")
    ap.add_argument("--go", action="append", default=[])
    ap.add_argument("--modfile")
    ap.add_argument("--npm")
    ap.add_argument("--python")
    ap.add_argument("--python-version")
    ap.add_argument("--notices")
    args = ap.parse_args()
    root = Path(__file__).resolve().parent.parent

    groups = []
    if args.go:
        groups.append(("Go modules compiled into the Chameleon programs", go_components(args.go, args.modfile, root)))
    if args.npm:
        groups.append(("JavaScript packages bundled into the web panel", npm_components(Path(args.npm))))
    if args.python:
        groups.append(("Python packages shipped with the panel", python_components(Path(args.python))))

    missing = []
    summary, texts = [], []
    for title, comps in groups:
        summary.append(f"\n{title}\n" + "-" * len(title))
        for name in sorted(comps, key=str.lower):
            version, directory = comps[name]
            files = license_files(directory)
            if not files:
                files = license_files(root / "third_party" / "licenses" / "npm" / f"{name}-{version}")
                if not files:
                    missing.append(f"{name} {version} ({directory})")
                    continue
            body = "\n\n".join(f.read_text(encoding="utf-8", errors="replace").strip() for f in files)
            summary.append(f"  {name} {version} — {kind(body)}")
            texts.append(f"\n{'=' * 78}\n{name} {version}\n{'=' * 78}\n\n{body}\n")
    if missing:
        print("no license text found for:\n  " + "\n  ".join(missing), file=sys.stderr)
        return 1

    notice_count = 0
    if args.notices:
        shipped = {}
        if args.python:
            shipped = {canonical(n): v for n, (v, _) in python_components(Path(args.python)).items()}
        if args.python_version:
            shipped["python"] = args.python_version
        notices, stale = applicable_notices(Path(args.notices), shipped)
        if stale:
            print("stale third-party notices:\n  " + "\n  ".join(stale), file=sys.stderr)
            return 1
        if notices:
            title = "Other third-party code in this package (notices from third_party/notices)"
            summary.append(f"\n{title}\n" + "-" * len(title))
            for component, text in notices:
                summary.append(f"  {component}")
                texts.append(f"\n{'=' * 78}\n{component}\n{'=' * 78}\n\n{text.strip()}\n")
            notice_count = len(notices)
    header = ("Third-party components in this Chameleon package and their licenses.\n"
              "Chameleon itself is licensed under the terms in LICENSE.\n")
    Path(args.output).write_text(header + "\n".join(summary) + "\n\n\nLICENSE TEXTS\n" + "".join(texts), encoding="utf-8", newline="\n")
    print(f"{args.output}: {sum(len(c) for _, c in groups)} components, {notice_count} notices")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
