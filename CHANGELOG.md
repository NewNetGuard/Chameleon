# Changelog

All notable changes to Chameleon. Versions follow the `VERSION` file.

## 1.2.1 — 2026-11-21

Licensing, release packaging and a source tree that holds Chameleon only. The
protocol, the transport and the behaviour of the Windows and Linux clients, the
server and the panel are the same as in 1.2.0.

### Removed

- **Parts that only EasyPi used**: the PrismLink UDP tunnel and the Mobile Link
  relay and agent (EasyPi's home tunnel for phones), with the server's
  `prism_link_listen` setting (an old configuration that still has it is
  accepted and the setting is ignored), the arm64 server build for EasyPi and
  the EasyPi technical audit.
- **The unused Android API of the client core** (`PullPacket`, `PushPacketBatch`,
  `SendTestPacket` and others), which no Windows or Linux client called.

### Changed

- **License: Mozilla Public License 2.0.** Chameleon's own code moves from the
  EasyPi Source Available License to MPL-2.0; every source file carries the
  MPL-2.0 notice. `NOTICE` lists what MPL-2.0 does not cover: the WireGuard
  files (MIT), the nginx context of the server patch (BSD-2-Clause), the banner
  and icon (made with the ChatGPT image generator) and the names.
- **Release packages** also carry `NOTICE` and `SOURCE.txt` with the address of
  the version's source code. `THIRD_PARTY_LICENSES.txt` now also covers the Go
  standard library, OpenSSL inside the Python runtime and `cryptography`, the
  Rust crates inside binary Python wheels and nginx's license for the server
  patch; the build stops when such a notice does not match the version shipped.
  Components that ship no license text of their own get the upstream text from
  `third_party/licenses/`; the build stops when a full text is missing.
- **Release signatures.** `tools/release_sign.py` signs the finished archives
  with Ed25519 and verifies them; see `docs/RELEASE_SIGNING.md`. Both builds
  refuse a package that contains private key material
  (`tools/check_release_contents.py`).
- **No local build paths in the programs.** The patched x/net copy is referenced
  by a path relative to the source tree, so the binaries no longer record the
  build machine's directories; the Windows package no longer ships pip's
  console-script launchers, which pointed to the build machine's Python and were
  never used.
- The `.sha256` files name the archive without a directory, so
  `sha256sum -c` works next to the downloaded archive.
- Build caches always stay in the source tree's `.build/` (or in
  `CHAMELEON_BUILD_ROOT`), also when the tree has no `.git`.

## 1.2.0 — 2026-11-20

The first release of Chameleon as a product of its own: a client and a panel for
your computer, on Windows and on Linux, with your own server.

### New

- **Chameleon Panel.** A web panel of its own, separated from EasyPi
  (`panel/`): generate keys, enter the server, deploy it over SSH with
  **Deploy & Start**, turn the tunnel on and off, watch status and logs.
  - The password is created in the panel itself on first open; from this
    computer no code is needed, from another device a one-time setup code.
  - **Forgot password? Reset** works only from the same computer;
    `sudo chameleon-panel reset-password` on a machine without a desktop.
  - Reachable only from this computer and the local network, enforced by a
    firewall rule and by the panel itself; HTTPS with its own certificate.
  - New design: the Chameleon banner on the sign-in screens, Chameleon colours,
    English throughout; the kill switch state is also shown on the Server tab.
- **Chameleon for Windows** (`cmd/chameleon-windows/`), no WSL needed:
  - two Windows services: the tunnel (LocalSystem) and the panel (an
    unprivileged virtual account, embedded Python 3.11);
  - a Wintun adapter with routes that send **all traffic of the computer**
    through the tunnel and a route to the server that follows network changes;
  - a **persistent kill switch** on the Windows Filtering Platform: it holds
    while the tunnel starts or fails, while the service is stopped or has
    crashed, and across reboots;
  - DNS only through the tunnel, QUIC blocked, the local IPv4 network reachable;
  - SSH credentials encrypted with DPAPI;
  - `chameleon-svc.exe install | recover | uninstall [--purge]`.
- **Whole-device mode on Linux** (host mode): the computer Chameleon runs on
  sends all its internet traffic through the tunnel, with a kill switch that is
  in place from boot, DNS only through the tunnel and QUIC blocked. Replaces the
  former gateway mode with its device list.
- **TCP streams on Windows.** A userspace TCP stack (gVisor netstack) terminates
  the applications' connections so each travels as its own stream, like on Linux:
  download on a ~150 Mbit/s line rose from 8 to 124–156 Mbit/s.
- **`tcprelay`** — the stream relay is now one package shared by the Linux and
  Windows clients.
- **One-file start.** `start_chameleon.bat` is a Windows batch file and a Linux
  shell script at once and ships inside both packages: unpack, double-click. On
  Windows it asks for administrator rights only to install, update or start.
- **`sudo chameleon-panel disable`** on Linux turns the tunnel off without the
  panel's web page, like **Disable**.
- **Release packages** for both systems: `panel/build-windows.sh` and
  `panel/build-release.sh`, with pinned and checked downloads (Wintun, Python)
  and third-party license texts included.

### Changed

- **IPv6 is closed completely** while Chameleon is enabled — on the internet and
  in the local network — on Windows and on Linux. The tunnel carries IPv4 only.
- The DNS resolver of the Linux client listens on `127.0.0.1` only and answers
  only this computer's own addresses (it is never reachable from the network).
- The Linux installer shows only local-network addresses for the panel; on a
  server without one it explains how to open the panel through SSH.
- Documentation: a new README for users; the technical description moved to
  `docs/ARCHITECTURE.md`, with new sections on the Linux and Windows clients.

### Fixed

- Linux client: DNS did not resolve when the system's resolver was not
  `127.0.0.1` (for example the WSL DNS stub `10.255.255.254`): replies left from
  the wrong address and were dropped.
- Windows `recover` now also marks the tunnel as disabled in the panel's
  settings, so the panel no longer turns it back on within 30 seconds.
- The Linux release build no longer fails when a Python cache directory is
  present in `panel/root`.
- Non-root builds can remove their temporary Go module cache.

## 1.1.5 — 2026-11-19

The last version developed inside EasyPi.

- Connection openings are less predictable: random-length cache-busting query
  on session setup, server answers after a random 4–44 ms with random padding,
  Chromium's four SETTINGS entries only.
- Bulk writes are no longer padded packet by packet at random: framing overhead
  19% → 13%.
- TCP streams for device TCP whenever the tunnel is on; TLS handshakes inside
  streams are masked; streams survive epoch rotations.
- nginx WINDOW_UPDATE threshold patch, kept through Ubuntu updates, with raised
  limits; load-tested on a 1 vCPU stand.
- The client presents itself as Chrome 157; Chrome-like keepalive, records and
  HTTP/2 flow control.
- The tunnel recovers on its own after a server restart; a client's previous
  sessions are freed when it starts again.
