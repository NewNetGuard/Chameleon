# Chameleon — architecture and protocol

This document describes how Chameleon works inside: the protocol, the carrier,
TCP streams, masking, the clients for Linux and Windows, the server on the VPS,
the build, the tests and the measurements. For installation and everyday use see
the [README](../README.md); for the panel see [PANEL.md](PANEL.md).

Chameleon is an encrypted tunnel disguised as an ordinary HTTPS website. It
carries the internet traffic of the computer it runs on (Chameleon for Windows
and Linux) to the user's own VPS and from there to the internet. To a filtering
system (DPI, the Russian TSPU) the connection looks like Chrome working with one
nginx website for a long time.

The wire protocol keeps its `easypi/...` key-derivation and authentication
labels: they are part of the protocol, and renaming them would cut off every
installed client and server. Some file and unit names on the VPS keep the
`easypi-` prefix for the same reason.

Labels used below:

- **[Measured]** — measured on a test stand or on the live system;
- **[Code]** — follows from the code;
- **[Estimate]** — expert estimate, not verified by measurement.

## Contents

1. [How it works](#1-how-it-works)
2. [Components and where they run](#2-components-and-where-they-run)
3. [Protocol: session, encryption, carrier](#3-protocol-session-encryption-carrier)
4. [TCP streams — the main transport](#4-tcp-streams--the-main-transport)
5. [Masking](#5-masking)
6. [Chameleon on Linux](#6-chameleon-on-linux)
7. [Chameleon for Windows](#7-chameleon-for-windows)
8. [Server on the VPS](#8-server-on-the-vps)
9. [Build and release](#9-build-and-release)
10. [Tests and tools](#10-tests-and-tools)
11. [Measured results](#11-measured-results)
12. [Limits and possible improvements](#12-limits-and-possible-improvements)
13. [Operations](#13-operations)
14. [Documents](#14-documents)

---

## 1. How it works

```
 client: this computer (Chameleon for Windows / Linux)
                        │  TCP → local termination → Chameleon stream
                        │  everything else (UDP, ICMP) → TUN → packet tunnel
                        ▼
              one TLS 1.3 + HTTP/2 connection
              (Chrome ClientHello, no SNI or the server's domain)
                        ▼
 VPS: nginx :443 (real TLS, cover website, secret path prefix)
                        │  proxy_pass to 127.0.0.1:9080
                        ▼
      chameleon-server ── TCP streams: dials the website itself
                       └─ packets: TUN chameleon0 + NAT
                        ▼
                     internet
```

Key properties:

- **Real TLS and a real website.**
  - TLS on the VPS is terminated by Ubuntu's ordinary nginx with a Let's Encrypt
    certificate.
  - Without the secret path it serves an ordinary website, and a tunnel route
    answers an outsider with nginx's standard 404.
  - A prober opening the server in a browser or scanner sees a website on nginx.
- **One carrier.** All of a device's data travels inside one long-lived HTTP/2
  connection, like a browser working with one site.
- **Two encryption layers.** The outer layer is nginx's TLS. The inner layer is
  Chameleon's end-to-end XChaCha20-Poly1305 between client and server, so nginx
  only ever sees encrypted request bodies.
- **Two data paths:**
  - device TCP travels as separate HTTP/2 streams (the main mode);
  - everything else travels through the packet tunnel over TUN: UDP, ICMP, and
    TCP whenever the server does not offer streams.

## 2. Components and where they run

| Directory | Binary | Runs on | Purpose |
|---|---|---|---|
| `cmd/chameleon-client/` | `chameleon-client` | Linux: `/opt/chameleon/bin/` | Linux client: TUN `cham0`, accepts TCP streams (socket from systemd), stream route |
| `cmd/chameleon-windows/` | `chameleon-svc.exe` | Windows: `C:\Program Files\Chameleon\` | Windows client and services: Wintun adapter, routes, WFP kill switch, TCP streams through a userspace TCP stack, the panel host |
| `tcprelay/` | — | library | carries locally terminated TCP connections as streams; shared by the Linux and Windows clients |
| `panel/` | `chameleon_panel` (Python) + web UI | the client computer | the Chameleon Panel: settings, server deployment, on/off ([PANEL.md](PANEL.md)) |
| `server/` | `chameleon-server` | VPS, `/opt/chameleon-server/chameleon-server` | tunnel server: sessions, TCP streams, packet tunnel, DNS |
| `clientcore/` | — | library | client core: transport, session, epochs, streams, fingerprint |
| `shared/` | — | library | shared code: cryptography, formats, stream frames, record shaping |
| `server/nginx/` | `easypi-chameleon-nginx` + patch | VPS, `/usr/local/sbin/` | builds and maintains nginx with the WINDOW_UPDATE patch |
| `server/site/` | — | VPS, `/opt/chameleon-server/site` | cover website |
| `tools/` | — | development | test stands and measurements (section 10) |

The launcher `start_chameleon.bat` (one file for Windows and Linux) ships inside the
release packages.

## 3. Protocol: session, encryption, carrier

### Session

- The client fetches a one-time server challenge (`/sync`) and establishes a
  session. The previous protocol is never accepted as a fallback.
- **Keys.** HKDF-SHA256 derives separate keys from the installation key, two
  fresh nonces, the session ID and the client process ID:
  - a request-authentication key;
  - a client→server key;
  - a server→client key;
  - a stream key (`StreamKey`).
- **Data.** Every tunnel packet and every DNS query is encrypted with
  XChaCha20-Poly1305.
- **Replay protection.** 64-bit counters and a sliding window.
- **Request authentication.** HTTP authenticators are bound to the session,
  method and path.
- **A server restart** invalidates old sessions.
- **Credentials.**
  - The client authenticates with `client_auth_key`.
  - Further clients can each have their own key
    `HMAC(client_auth_key, "easypi/mobile-auth/v1/" + id)` from the
    `mobile_clients.json` registry (the name is kept for compatibility); the
    load test uses it for many clients.
  - The registry holds at most 200 clients, with addresses in the tunnel /24.
  - One credential has one live session: a new client process replaces the old
    one.

### Routes

The path prefix is derived from `psk_key`: `HMAC(psk, "chameleon-route-prefix-v1")`,
8 characters. Without it nginx answers 404.

| Path | Purpose |
|---|---|
| `/sync` | challenge, session establishment, capability exchange |
| `/upload` | persistent uplink stream (request body) |
| `/stream` | persistent downlink stream (response body) |
| `/push`, `/poll` | fallback mode with separate requests |
| `/tcp` | one device TCP stream (section 4) |
| `/dns` | DNS through the tunnel |

nginx turns authorization errors (401) into 404, so the tunnel path cannot be told
apart from a missing page. On the tunnel path the client treats 401 and 404 as a
rejected session and negotiates a new one after 3 s. After a server restart the
tunnel recovers on its own within 2–6 s [Measured].

### Carrier and epochs

- **One HTTP/2 connection:**
  - uplink is the body of a long `/upload` request;
  - downlink is the body of a long `/stream` response;
  - every device TCP stream has its own `/tcp` request in the same connection.
- **Acknowledgements are batched:** one per 400–1200 ms or per 768 packets,
  piggybacked on useful uplink data where possible [Code].
- **No heartbeat.** There are no empty keepalive packets and no periodic HTTP/2
  PINGs. After a long silence there is one check with a random delay.
- **Epochs.** From time to time the connection is replaced by a new one, as a
  browser would:
  - the replacement age is random, from 20–40 min up to 90 min – 4 h;
  - the data budget is 256 MB to 1 GB;
  - a replacement happens only in a quiet pause of 3–15 s [Code];
  - the new connection is authenticated first and only then replaces the old
    one; a failed attempt leaves the old one untouched.
- **Epochs and open streams:**
  - an old connection is not cut while device TCP streams are open in it;
  - it closes when its last stream ends, or after 2 h without traffic;
  - at most 4 old connections are kept [Code];
  - stream bytes count only toward their own epoch's budget.
- **Network changes.** The client can move its session to a new address once the
  old path has been silent for 5 s. Unacknowledged downlink data is kept for
  retransmission.

## 4. TCP streams — the main transport

All traffic used to travel as IP packets through TUN. Now every device TCP
connection travels as its own HTTP/2 stream: the client terminates the TCP
connection locally and the server dials the website itself. This means:

- no TCP inside TCP, so no double retransmissions and no sawtooth throughput;
- uploads and downloads run at full speed;
- device packets are not visible as TLS inside TLS.

### On the client: Linux (see also section 6)

- **Data path.**
  - Rule `5092` sends the computer's TCP to table `51824`.
  - From there it goes through veth `chtcp0` (169.254.77.1) into network
    namespace `chameleon-chtcp` (`chtcp1`, 169.254.77.2).
  - Inside, TPROXY hands the connection to port 15080.
- **Accepting connections.**
  - systemd creates the listener: unit `chameleon-tcp.socket` with
    `NetworkNamespacePath=` and `Transparent=yes`.
  - systemd passes the socket to the client, so the client needs no extra
    privileges.
- **TCP to the VPS itself** (rule `5091`) uses `cham0`, not a stream.
- **The client manages the stream route.**
  - The client installs the route in table `51824` only while the server offers
    streams, and checks every 2 s.
  - Without the route, TCP falls through to the ordinary device rule (`5096`) and
    uses the packet tunnel, so a server without stream support never cuts the
    network.
  - The route is removed when the client stops.
- **Early data.** The client waits up to 20 ms for the device's first bytes and
  sends them together with the stream request. For TLS that is the ClientHello:
  one request instead of an "open → data" exchange.
- **Where the namespace is created.**
  - It is created and removed through `systemd-run` in the host mount namespace.
  - The panel runs `chameleon-netctl` with `PrivateTmp=yes`, and an `ip netns`
    mount made there would be invisible to systemd, so the listener could not
    open inside it.

### On the client: Windows

- The Wintun adapter delivers every IPv4 packet to `chameleon-svc.exe`.
- While the server offers streams, IPv4 TCP goes to a userspace TCP stack
  (gVisor netstack) in promiscuous and spoofing mode: it accepts a connection to
  any address and answers from that address, so the connection's local address
  is the destination the application dialled — the same thing TPROXY gives on
  Linux.
- `tcprelay` then carries it exactly like on Linux, with the same 20 ms early
  data.
- Without streams (an older server) TCP stays on the packet tunnel; the switch is
  checked every second.

### On the wire

- The request body starts with a 16-byte random stream nonce.
- Frames follow: `[4-byte length][ciphertext]`, at most 16 KB of data per frame.
- Every stream has its own keys: HKDF over `StreamKey`, the session ID and the
  stream nonce, so cipher counters of different streams never overlap.
- The first frame names the destination address.
- **Handshake masking** (header `X-Chameleon-Tcp-Shape: 1`):
  - it applies to the first 4 frames in each direction;
  - small frames are padded to 512–576 bytes;
  - the first large frame is padded to a random size: up to 4 KB upstream
    (ClientHello) and up to 8 KB downstream (the server's reply);
  - the frame format is `[2-byte length][data][padding]`;
  - bulk transfer goes unpadded, in full frames.

### On the server

- **Destinations.** The server dials only public IPv4 addresses. Private and
  special-purpose networks and the VPS's own addresses are refused
  (`deniedTCPStreamPrefixes`).
- **Limits.**
  - At most 256 streams per session.
  - Streams do not use the tunnel's request slots (`max_requests_per_session`):
    a browser opens dozens of connections.
  - A session with open streams counts as busy and is never removed as idle.
- **The response** starts at once (`EnableFullDuplex`); the stream is
  bidirectional.

## 5. Masking

| What | How | Verified |
|---|---|---|
| First TLS message | uTLS with its own Chrome 157 profile (cipher suites, extensions, groups, GREASE, shuffled order, X25519MLKEM768, ALPN h2) | [Measured] matches real Chrome 158 by JA4 `t13d1517h2_8daaf6152771` |
| TCP keepalive | 45 s, as in Chrome | [Measured] from socket timers |
| TLS records | full-size records for bulk transfer, no record-size warm-up | [Measured] 97% full-size records with a large window |
| HTTP/2 window | as in Chromium: 6 MB per stream, 15 MB per connection; credit returned in large batches (`inflowMinRefresh` 8 MB in a private copy of `x/net`) | [Code] |
| HTTP/2 opening | the client's opening SETTINGS carry Chromium's four entries: the record shaper drops the default `MAX_FRAME_SIZE` that `x/net` repeats | [Measured] first record after the handshake 87 bytes, as in Chrome (was 93) |
| Connection opening | session setup requests carry a cache-busting query of random length; the server answers them after a random 4–44 ms with padding of random length, so the client's SETTINGS acknowledgement precedes the answer | [Measured] 80 openings: request sizes 11 → 50 distinct values, answer sizes 6 → 74 |
| Record shaping | negotiated after authentication; adds random padding of at most 2 KB to records that carry payload | [Code] |
| Packet path | packets are padded to sizes from a fixed set of buckets; in a write carrying less than 4 KB of packets, where single packet sizes could show, the bucket is also raised at random | [Measured] bulk transfer on the Pi: framing overhead 19% → 13%, download 15 → 17 MB/s on a 21 MB/s line |
| TLS inside TLS | the website handshake inside a stream is masked (section 4) | [Measured] the exact ClientHello size leak is gone |
| Server replies during upload | nginx patch: window credit returned in portions of at least 256 KB | [Measured] ~80 WINDOW_UPDATE per 25 MB instead of ~1500 |
| Active probing | real nginx and website, 404 on the tunnel path, Let's Encrypt certificate for a domain | [Measured] |
| Marker in SessionID | `HMAC(psk, pub ‖ nonce)[:16]` with a fresh random nonce every time; used only in `direct` mode (not needed behind nginx) | [Code] |
| Background traffic | none is generated: an idle connection stays silent | [Code] |

## 6. Chameleon on Linux

Chameleon for Linux (`panel/`, installed by `install.sh` from the release
package) routes **all internet traffic of the computer it runs on** through the
tunnel. It needs Debian or Ubuntu with systemd.

### Pieces

- `chameleon-panel.service` — the panel (Python, user `chameleon`), HTTPS on
  port 8443, local network only.
- `/usr/lib/chameleon/chameleon-runner` — the only command the panel may run with
  `sudo`; it allows exactly `chameleon-netctl` and `chameleon-secrets`.
- `chameleon-netctl` — turns the tunnel on and off: `up`, `down`, `status`,
  `guard`, `resume`.
- `chameleon-secrets` — SSH credentials for the VPS, encrypted with
  `systemd-creds` (with the TPM when there is one).
- `chameleon-dns.service` — the local resolver (user `chameleon-dns`) on
  `127.0.0.1:15353`; it answers only this computer's own addresses and reaches the
  internet only through the tunnel.
- `chameleon-guard.service` and `chameleon-resume.service` — at boot, put the kill
  switch back before the network is up and then restore an enabled tunnel.
- `chameleon-panel-firewall.service` — accepts the panel port only from loopback
  and private networks, independently of the panel's own address check.

### Routing (`ip rule`, lowest priority first)

| Priority | Traffic | Goes to |
|---|---|---|
| 5080 | the client process itself (its own user) | the ordinary uplink |
| 5081 | the panel's SSH/HTTPS to its own server | the ordinary uplink |
| 5082, 5083 | the DNS resolver's user | table `51823`: the tunnel only, blackhole behind it |
| 5089 | Tailscale | its own table |
| 5090 | private networks | the ordinary uplink: the LAN always stays reachable |
| 5091 | TCP to the server itself | the packet tunnel |
| 5092 | TCP | table `51824`: TCP streams while the server offers them |
| 5096 | everything else | table `51821`: `cham0`, blackhole behind it |

### Protection

- **Kill switch** — OUTPUT chains `CHAMELEON_HOST` and `CHAMELEON_HOST6`. While
  Chameleon is enabled nothing leaves the computer directly: not while the tunnel
  starts, not after it fails, not after a reboot before the tunnel is back.
- **DNS** — every query to port 53, whatever the destination, is redirected to
  the local resolver, and that resolver can only use the tunnel.
- **IPv6** — closed completely except loopback, in the local network too: the
  tunnel carries IPv4 only.
- **QUIC** (UDP 443) — blocked by default (`CHAMELEON_QUIC`), so browsers use TCP,
  that is, streams.
- The persistent intent lives in `/var/lib/chameleon/policy/dns-policy.json`; the
  client log is `/var/log/chameleon/client.log`.

## 7. Chameleon for Windows

`chameleon-svc.exe` (`cmd/chameleon-windows/`) is one executable that serves as
two Windows services, the control client and the installer.

### Services

| Service | Account | Role |
|---|---|---|
| `Chameleon` | LocalSystem, unrestricted service SID | the tunnel: Wintun adapter, routes, kill switch, DNS, client core, control pipe |
| `ChameleonPanel` | `NT SERVICE\ChameleonPanel` (virtual account, no privileges) | runs the panel on the embedded Python 3.11 |

- The panel reaches the tunnel service only through the named pipe
  `\\.\pipe\ChameleonControl`; its ACL admits SYSTEM, Administrators and the
  panel's account. The requests are the same as `chameleon-netctl` /
  `chameleon-secrets` on Linux.
- SSH credentials are encrypted with DPAPI under SYSTEM in
  `C:\ProgramData\Chameleon\credentials` (SYSTEM and Administrators only).
- Data lives in `C:\ProgramData\Chameleon` with per-directory access lists; the
  client log is `C:\ProgramData\Chameleon\logs\client.log`.
- A Windows Firewall rule admits the panel port (8443) from the local subnet only.

### Routing

- Adapter `Chameleon` (Wintun, fixed GUID), address `10.10.0.2/32`, MTU 1420,
  interface metric 0, DNS `1.1.1.1` and `9.9.9.9`.
- Routes `0.0.0.0/1` and `128.0.0.0/1` through the adapter: more specific than any
  default route, whatever its metric.
- A host route to the server through the current uplink; it follows a change of
  network (Wi-Fi ↔ cable) within 3 s.

### Kill switch (Windows Filtering Platform)

- One provider, one sublayer and every filter are **persistent** with fixed keys:
  they stay in force while the service is stopped or has crashed and across
  reboots, until Chameleon is disabled. A policy change replaces everything in
  one transaction.
- Filters, highest weight first:
  - the tunnel service itself (by executable and service SID) — unrestricted;
  - the panel's account — only to the server's address;
  - DNS — only through the tunnel adapter; DNS anywhere else is blocked, including
    to the router;
  - loopback;
  - QUIC (UDP 443) — blocked;
  - the tunnel adapter, the local IPv4 network (10/8, 172.16/12, 192.168/16,
    169.254/16, multicast, broadcast) and DHCPv4 — allowed;
  - everything else — blocked. IPv6 is closed completely except loopback.
- `chameleon-svc.exe recover` (as administrator) disables Chameleon and removes
  the kill switch when the panel cannot be used.
- Adapted from WireGuard for Windows (MIT); see `cmd/chameleon-windows/winfw/`.

### Install, update, remove

- `start_chameleon.bat` asks for administrator rights only to install, update or
  start the services, then runs `chameleon-svc.exe install --source <package>`:
  files to `C:\Program Files\Chameleon`, services, access lists, the panel's TLS
  certificate, the firewall rule. An update replaces the files atomically; the
  persistent kill switch keeps the computer offline meanwhile if Chameleon is
  enabled.
- `chameleon-svc.exe uninstall [--purge]` removes everything (`--purge` also the
  settings and keys).

## 8. Server on the VPS

The panel installs and updates the server with **Deploy & Start**
(`panel/backend/chameleon_panel/stealth/deployment.py`). New installs and
updates use the same idempotent procedure.

### What Deploy & Start installs

1. `iptables`, certbot 5.4 in its own environment, `flock`, and the
   `easypi-vps-guard` (port 80 closed except while a certificate is issued).
2. A Let's Encrypt certificate for a domain or an IP, renewed twice a day by
   `chameleon-cert-renew.timer`.
3. nginx from the Ubuntu package, the config `/etc/nginx/conf.d/easypi-chameleon.conf`
   and the cover website.
4. `easypi-chameleon-nginx install` — nginx with the patch (below).
5. `chameleon-server` with `server_config.json` and the units `chameleon-server`
   and `chameleon-network` (TUN `chameleon0`, NAT).

### nginx configuration (template in `panel/backend/chameleon_panel/stealth/tls.py`)

- `listen 443 ssl http2`, TLS 1.2–1.3, session cache.
- Tunnel location `^~ /<prefix>/` → `http://127.0.0.1:9080`:
  - `proxy_request_buffering off`, `proxy_buffering off`;
  - `client_body_buffer_size 1m` — the size the patch was measured with;
  - `client_body_timeout 24h` — long request bodies;
  - `keepalive_requests 1000000` — no GOAWAY in the middle of work;
  - `proxy_buffer_size 16k`, `proxy_buffers 8 16k` — downlink records are not all
    4122 bytes;
  - the client address is not passed to the server (`X-Real-IP ""`);
  - 401/403/404/405 → 404.
- All other paths serve the cover website or 404.

### nginx with the WINDOW_UPDATE patch

**The problem.** With an unbuffered request body, nginx returns flow-control credit
to the client after every portion it forwards. A 25 MB upload produced ~1500–2800
short control records. Chrome talking to Cloudflare produces ~1, and an ordinary
nginx website produces 0 [Measured].

**The patch** `server/nginx/h2-unbuffered-window-update-threshold.patch`:

- changes only two nginx functions
  (`ngx_http_v2_read_client_request_body_handler` and
  `ngx_http_v2_read_unbuffered_request_body`);
- credit is sent once at least min(half the buffer, 256 KB) has accumulated;
- result: about 80–96 records per 25 MB at the same speed, with no stalls on
  small, final or intermittent portions of data [Measured].

**How it lives on the VPS** — `easypi-chameleon-nginx`:

- **Diversion.** `dpkg-divert` moves the packaged `/usr/sbin/nginx` to
  `/usr/sbin/nginx.distrib`. Ubuntu updates put the new binary there and leave
  the patched one alone.
- **Build.** The patch is built from the source of the installed package version
  (`apt-get source` with private source lists, so the system's own apt runs never
  download source indexes). Configure options come from `nginx.distrib -V`,
  without the dynamic modules. Ubuntu's security fixes stay in the binary.
- **Ubuntu updates.** After every package change the apt hook
  `80easypi-chameleon-nginx` runs the new packaged nginx at once, and
  `easypi-chameleon-nginx-rebuild.service` rebuilds the patch in the background.
- **Failed build.** If the patch no longer applies or builds, the packaged nginx
  keeps running: the tunnel works, just without the patch. A daily timer retries.
- **Archive ahead of the VPS.** The Ubuntu archive keeps only the current source.
  If the archive already has a newer version while the package has not been
  updated yet, the patch is built after the update lands.
- **Limits:**
  - `worker_connections 4096`, `worker_rlimit_nofile 16384`;
  - nginx memory ceiling: MemoryHigh 25%, MemoryMax 35% of RAM;
  - past the ceiling the nginx master replaces the worker, and the VPS and SSH
    stay reachable.
- **Commands:** `status`, `rebuild`, `remove` (the last one puts the packaged
  nginx back).

[Measured] On 2026-11-19 on the VPS: nginx updated from `.12` to `.13`; the hook
ran the packaged `.13` at once, and the patch was built on the VPS itself (1 vCPU)
in about 95 s.

### Server configuration (template in `panel/backend/chameleon_panel/stealth/tls.py`)

- `frontend_mode nginx`, backend `127.0.0.1:9080`.
- `max_connections 4096` — the session ceiling. The real limit is the registry:
  one live session per device, at most 201 devices.
- `max_requests_per_session 8`, `max_sessions_per_source 8`.
- **Source quota** (fixed in `96fde48`):
  - behind nginx or a relay every client arrives from `127.0.0.1`;
  - that address used to count as one subscriber network, and the ninth device
    was refused;
  - a local source no longer counts as a subscriber network; real networks keep
    the quota.
- **VPS isolation.** Tunnel clients cannot reach the VPS's internal networks
  (Docker, WireGuard, the tunnel subnet) or its own services. This comes from
  the `chameleon-network-setup` rules and the same list of refused destinations
  used for streams.
- **Unit `chameleon-server`:**
  - user `chameleon`, no privileges (`CapabilityBoundingSet=`);
  - `MemoryHigh=60%`, `MemoryMax=75%`, `TasksMax=512`, `LimitNOFILE=65536`.

## 9. Build and release

### Binaries

```sh
./build.sh          # server (amd64) + Linux clients for amd64 and arm64
./build.sh arm64    # server (amd64) + arm64 client
GO=/path/to/go ./build.sh
```

- Go 1.27.4 is required. If it is missing, `ensure-go.sh` downloads the official
  toolchain into `.build/` and verifies its SHA256.
- Build caches (`.build/`: toolchain, patched `x/net`) live in the source tree's
  own `.build/`; `CHAMELEON_BUILD_ROOT` overrides the location.
- `tools/prepare_http2_modfile.sh` makes a private copy of `golang.org/x/net` and
  changes only `inflowMinRefresh` to 8 MB (a Chromium-like window). If that line
  changes in a new version, the build stops and asks for review.
- Flags: `CGO_ENABLED=0 -trimpath -buildvcs=false`.

| File in `bin/` | Used for |
|---|---|
| `chameleon-server-amd64` | uploaded to the VPS by Deploy & Start |
| `chameleon-client-amd64` / `-arm64` | the Linux client |

`build.sh` does not work under Git Bash on Windows: Go for Windows does not
understand `/c/...` paths in the `replace` directive. `panel/build-windows.sh`
converts them and works in Git Bash as well as on Linux.

### Release packages

```sh
panel/build-release.sh   # Linux: dist/chameleon-panel-<version>.tar.gz   (run on Linux)
panel/build-windows.sh   # Windows: dist/chameleon-windows-<version>.zip  (Git Bash or Linux)
```

- `PANEL_WEB_PREBUILT=1` reuses a web UI already built with `npm run build` in
  `panel/frontend`.
- The Windows package downloads Wintun 0.14.1 and the Python 3.14.10 embeddable
  distribution once into `.build/downloads` and checks both against pinned SHA-256
  values; the panel's Python dependencies are installed for `win_amd64` from
  wheels only.
- Both packages carry `start_chameleon.bat` at the top, `VERSION`, `LICENSE`
  (MPL-2.0), `NOTICE`, `THIRD_PARTY_LICENSES.txt` and `SOURCE.txt`, written by
  `panel/source-notice.sh` with the address of this version's source code
  (`CHAMELEON_SOURCE_URL` overrides the repository). The version comes only
  from the `VERSION` file.

## 10. Tests and tools

### Tests

```sh
go test ./...                                       # Go tests (Linux and Windows parts on their platform)
python -m pytest panel/backend/tests                # panel: local-network access, CSRF, passwords, sessions
cd panel/frontend && npx tsc --noEmit               # web UI type check
```

- On Windows `go test ./cmd/chameleon-windows/ ./tcprelay` covers the userspace
  TCP path (a connection to any address carried as a stream) and the relay.
- Linux-only tests (`tcprelay`, `cmd/chameleon-client`) can be compiled on
  Windows with `GOOS=linux go test -c` and run in WSL.

### Test stands (`tools/`)

- **`tools/nginx-h2-window/`** — the nginx patch:
  - `build.py`, `build_tls.sh`, `build_ubuntu.sh` — builds without installation;
  - `bench.py` — h2c stand: speed, WINDOW_UPDATE, slow receiver, pauses, final
    portions;
  - `run_tls.sh` — TLS stand with the real client (`TestNginxWindowBench`);
  - `run_mem.sh` — nginx memory (`TestNginxMemoryBench`);
  - `test_vps_tool.sh` — end-to-end check of `easypi-chameleon-nginx` on Ubuntu:
    install, redeploy, package update, failed build, removal.
- **`tools/chameleon-load/`** — load:
  - `run_load.sh` — isolated stand in WSL: 1 vCPU and 1 or 2 GB in a cgroup,
    separate network namespaces for devices and for "the internet", 30 ms RTT,
    the real server and nginx;
  - the generator is `TestChameleonLoad`: a device is a separate Chameleon
    session with several TCP streams.
- **`tools/connection-opening/`** — how connections open:
  - `run_opening.sh` — WSL stand on the prepared `chameleon-load` directory:
    many fresh sessions and epoch changes one after another
    (`TestOpeningCapture`), captured next to the client and next to the server;
  - `evaluate.py` — runs CensorLab detectors over the capture and reports the
    share of openings each one acts on.

The stand tests are skipped by a plain `go test`: they need the stand's
environment variables.

## 11. Measured results

**Speed** through the tunnel, Linux client on a Raspberry Pi 5 routing a computer's
traffic, VPS 1 vCPU / 2 GB, 2026-11-19 [Measured].

| | Download 50 MB | Upload 25 MB | WINDOW_UPDATE per 25 MB |
|---|---|---|---|
| Packet tunnel (no streams) | 12.5–13.8 MB/s | 1.6–1.7 MB/s | — |
| Streams, unpatched nginx | 17–19 MB/s | 6.6–9.3 MB/s | ~1500 |
| **Streams + nginx patch (current)** | **16.6–19.4 MB/s** | **8.8–9.6 MB/s** | **~80** |

**Comparison with real Chrome 158** (Chrome → Cloudflare versus Chrome through
Chameleon) [Measured]:

- the first TLS message matches up to JA4;
- speed and volume per phase match;
- remaining differences: server control replies during uploads (reduced by the
  patch) and activity on one connection caused by the computer's background
  traffic.

**Load** — stand with 1 vCPU, 30 ms RTT [Measured]:

| | 100 active devices | 200 active | 200 idle |
|---|---|---|---|
| CPU of one core (avg / peak) | 21% / 35% | 41% / 62% | 2% |
| nginx + server memory | 219 MB | 414 MB | 253 MB |
| Errors | 0 | 0 with `worker_connections` 4096 | 0 |

- With `worker_connections 768` (the Ubuntu default) 84–90% of streams were
  refused at 200 devices. The limit is now 4096.
- 2 GB of RAM brings nothing over 1 GB up to 200 devices.
- [Estimate] On a slower real VPS vCPU a reasonable limit is about 150
  simultaneously active devices.

**nginx memory** with 128 concurrent streams [Measured]:

| State | unpatched nginx, 512 KB buffer | patched nginx, 1 MB buffer |
|---|---|---|
| Idle | +3 MB | +3 MB |
| Active upload | +20 MB | +22 MB |
| Worst case: the receiver does not read | +44–66 MB | up to +121 MB |

The worst case is bounded by the nginx memory ceiling.

**Chameleon for Windows and Linux**, VPS in Zurich, 2026-11-20 [Measured]:

| Client | Download | Upload |
|---|---|---|
| Windows, home connection of ~150 Mbit/s, TCP streams | 124–156 Mbit/s | 34–57 Mbit/s |
| Windows, same line, packet tunnel only (before streams on Windows) | 8.4 Mbit/s | 6.4 Mbit/s |
| Linux server in a Moscow data center | 168–178 Mbit/s | 68 Mbit/s |

- **Kill switch on Windows:** with the service stopped, and with its process
  killed and not restarted, no internet and no DNS (system or direct to 1.1.1.1),
  no bypass through Wi-Fi; the local network and the panel stay reachable; after
  a crash Windows restarts the service and the tunnel is back in 5–14 s.
- **IPv6** on a real IPv6 mobile network: websites over IPv6, NAT64 addresses
  (`64:ff9b::`), connections from the computer's own IPv6 address, DNS to IPv6
  servers and the local IPv6 network are all blocked; Teredo, 6to4, ISATAP and
  IP-HTTPS are inactive.
- **Blocked websites:** from the Moscow server LinkedIn and telegram.org do not
  open directly and open through the tunnel; 18 of 18 checks over 3 minutes.
- **The route to the VPS matters:** on Deutsche Telekom mobile data the Zurich
  VPS lost 39–67% of its packets towards the client on the Cogent → Telekom
  handover — with and without Chameleon — while Cloudflare reached 32 Mbit/s on
  the same connection. MTU and MSS were not the cause (the carrier clamps MSS to
  1300 in both directions).


## 12. Limits and possible improvements

**Limits:**

- The tunnel carries IPv4 only; IPv6 is closed while Chameleon is enabled.
- A VPS reaches some networks badly or not at all (its provider's routes, blocks
  on its side); choose it by testing the route to your own networks first.
- The tunnel network is a /24.
- The nginx patch is rebuilt on the VPS after every Ubuntu update, so build tools
  are installed there (marked as automatically installed).

**Improvements, by value for effort:**

1. A Firefox profile.
2. An own domain instead of DuckDNS.
3. Tests on several Russian ISPs, especially mobile ones.
4. A CDN mode — a large piece of work, but the only one that survives
   "whitelist" filtering.

## 13. Operations

**Linux client:**

```sh
sudo /usr/lib/chameleon/chameleon-netctl status         # JSON: running, connected, killswitch, dns_protected, tcp_streams
sudo tail -f /var/log/chameleon/client.log
sudo chameleon-panel reset-password                      # forget the panel password, print a new setup code
sudo chameleon-panel disable                             # like Disable in the panel: direct internet again
```

**Windows client** (PowerShell as administrator):

```powershell
& "C:\Program Files\Chameleon\chameleon-svc.exe" recover   # disable without the panel: direct internet again
Get-Service Chameleon, ChameleonPanel
Get-Content C:\ProgramData\Chameleon\logs\client.log -Tail 50
```

**VPS:**

```sh
systemctl status nginx chameleon-server chameleon-network
/usr/local/sbin/easypi-chameleon-nginx status   # running=patched / packaged
journalctl -u chameleon-server -n 50
journalctl -t easypi-chameleon-nginx -n 20      # patch builds and switches
grep -E 'worker_(connections|rlimit)' /etc/nginx/nginx.conf
```

**Back to the packaged nginx:**

```sh
/usr/local/sbin/easypi-chameleon-nginx remove
```

**Common problems:**

- **`tcp_streams: false` while the tunnel runs:**
  - the server does not offer streams — look for `TCP streams negotiated` in the
    client log;
  - or the stream socket did not start — `systemctl status chameleon-tcp.socket`.

  TCP then uses the packet tunnel, which is slower.

## 14. Documents

| Document | Topic |
|---|---|
| [`PANEL.md`](PANEL.md) | the Chameleon Panel: access, password, security |
| [`../CHANGELOG.md`](../CHANGELOG.md) | changes by version |
| [`docs/CHAMELEON_TLS_IN_TLS_STREAMS.md`](CHAMELEON_TLS_IN_TLS_STREAMS.md) | TLS-in-TLS masking inside streams |
| [`docs/CHAMELEON_CHROME_COMPARISON.md`](CHAMELEON_CHROME_COMPARISON.md) | paired comparison with real Chrome |
| [`docs/CHAMELEON_H2_FLOW_CONTROL_OPTIONS.md`](CHAMELEON_H2_FLOW_CONTROL_OPTIONS.md) | nginx WINDOW_UPDATE: options, patch, measurements |
| [`docs/CHAMELEON_LOAD_TEST.md`](CHAMELEON_LOAD_TEST.md) | load test and limits |
| [`docs/CHAMELEON_TCP_STREAMS_COMPARISON.md`](CHAMELEON_TCP_STREAMS_COMPARISON.md) | streams versus the packet tunnel |
| [`docs/CHAMELEON_TRANSPORT_BASELINE.md`](CHAMELEON_TRANSPORT_BASELINE.md) | transport baseline measurements |
| [`docs/CHAMELEON_SHAPE_BENCH_RESULT.md`](CHAMELEON_SHAPE_BENCH_RESULT.md) | traffic shape on the wire |
| [`tools/nginx-h2-window/README.md`](../tools/nginx-h2-window/README.md) | nginx patch test stands |
