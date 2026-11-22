# Third-party notices

Chameleon's own code is licensed under the Mozilla Public License 2.0
([LICENSE](LICENSE)), with the exceptions in [NOTICE](NOTICE). It is built with,
and its release packages contain, the third-party components below; each keeps
its own license, which MPL-2.0 does not replace.

Every release package carries **`THIRD_PARTY_LICENSES.txt`** with the full list,
exact versions and complete license texts. It is generated during the build by
[`tools/third_party_licenses.py`](tools/third_party_licenses.py) from the exact
dependencies compiled or shipped, and the build stops when a component has no
license text. Code that a component contains without shipping its license —
OpenSSL inside the Python runtime and inside `cryptography`, Rust crates inside
binary Python wheels — is covered by the notices in
[`third_party/notices/`](third_party/notices/) (Rust crates collected by
[`tools/rust_wheel_notices.py`](tools/rust_wheel_notices.py)); the build stops
when such a notice does not match the version shipped. Version-specific upstream
license supplements are preserved in `third_party/licenses/`, including README
license sections and workspace-level Rust licenses. Collectors require full
license texts, not only license declarations.

## Bundled programs and runtimes

| Component | License | Where |
|---|---|---|
| [Wintun](https://www.wintun.net/) 0.14.1 (`wintun.dll`) | Prebuilt Binaries License (redistributable, unmodified) — `LICENSE.Wintun.txt` | Windows package |
| [Python](https://www.python.org/) 3.14.10, embeddable distribution | PSF License 2.0 — `python/LICENSE.txt` | Windows package |
| [OpenSSL](https://www.openssl.org/) 3.5.9 (`libcrypto-3.dll`, `libssl-3.dll` of the embedded Python) and 4.0.3 (linked into `cryptography`) | Apache-2.0 — `third_party/notices/openssl.txt` | Windows package |
| libffi, SQLite (inside the embedded Python) | MIT; public domain | Windows package |
| Microsoft Visual C++ runtime (`vcruntime140.dll`, `vcruntime140_1.dll` of the embedded Python) | redistributable under Microsoft's terms, as part of the Python distribution | Windows package |
| WFP kill-switch code adapted from [WireGuard for Windows](https://git.zx2c4.com/wireguard-windows/) | MIT — `LICENSE.WireGuard.txt`, `cmd/chameleon-windows/winfw/LICENSE.WireGuard` | Windows client |

## Go modules (compiled into the Chameleon programs)

| Module | License |
|---|---|
| Go standard library and runtime (compiled into every program) | BSD-3-Clause + PATENTS |
| github.com/refraction-networking/utls | BSD-3-Clause |
| golang.org/x/crypto, x/net (a copy with one changed constant, see `tools/prepare_http2_modfile.sh`), x/sys, x/text, x/time | BSD-3-Clause |
| golang.zx2c4.com/wireguard, wireguard/windows, wintun | MIT |
| gvisor.dev/gvisor | Apache-2.0 |
| github.com/google/btree | Apache-2.0 |
| github.com/klauspost/compress | Apache-2.0, BSD-3-Clause and others (see its license text) |
| github.com/andybalholm/brotli | MIT |
| github.com/songgao/water | BSD-3-Clause |

## Python packages (the panel; shipped in the Windows package, installed from PyPI on Linux)

| Package | License |
|---|---|
| fastapi, pydantic, pydantic-core, anyio, h11, annotated-types, annotated-doc, typing-inspection, cffi | MIT |
| starlette, uvicorn, httpx, httpcore, idna, click, pycparser | BSD-3-Clause |
| invoke | BSD-2-Clause |
| cryptography, bcrypt, PyNaCl, sniffio | Apache-2.0 (cryptography: Apache-2.0 or BSD-3-Clause) |
| paramiko | LGPL-2.1 — used unmodified as a separate library |
| certifi | MPL-2.0 |
| typing-extensions | PSF-2.0 |
| Rust crates inside `cryptography`, `bcrypt` and `pydantic-core` (32, 42 and 101 crates) | mostly MIT or Apache-2.0 (dual), also Unicode-3.0, BSD-3-Clause, Apache-2.0 with LLVM exception and Unlicense-or-MIT; where a crate offers a choice (for example Apache-2.0 or GPL-2.0), the permissive option applies — every crate listed with its texts in `third_party/notices/python-*-rust.txt` |

## JavaScript packages (bundled into the web panel)

| Package | License |
|---|---|
| react, react-dom, scheduler, react-router, react-router-dom, @tanstack/react-query, axios, react-hot-toast, goober and their dependencies | MIT |
| lucide-react | ISC |

## nginx (on your VPS)

Deploy & Start installs nginx from your server's own Ubuntu or Debian packages
and, with `easypi-chameleon-nginx`, builds it there with Chameleon's patch
[`server/nginx/h2-unbuffered-window-update-threshold.patch`](server/nginx/h2-unbuffered-window-update-threshold.patch)
(18 changed lines in `src/http/v2/ngx_http_v2.c`). nginx is licensed under the
BSD-2-Clause license (Copyright (C) Igor Sysoev, Copyright (C) Nginx, Inc.); its
copyright file stays in `/usr/share/doc/nginx*/copyright` on the server. The
release packages contain neither nginx nor its sources — only the patch, whose
context lines come from nginx; nginx's license travels with the patch as
[`server/nginx/LICENSE.nginx`](server/nginx/LICENSE.nginx) and is also part of
`THIRD_PARTY_LICENSES.txt`.

## Programs used, not shipped

iptables / ip6tables, iproute2, systemd, sudo, OpenSSL's `openssl` command,
apt, certbot (installed on the VPS from PyPI, Apache-2.0), and on Windows
`netsh`, `sc.exe`, PowerShell and `tar.exe` are run as separate programs and are
not part of Chameleon.

Development-only tools (Vite, TypeScript, Tailwind CSS, Go and Node toolchains)
are not part of the release packages.
