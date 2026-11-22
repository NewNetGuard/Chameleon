# Chameleon Panel

The panel is where you set Chameleon up and use it: keys, your server, its
deployment, the tunnel on and off, status and logs. It runs on the computer that
Chameleon protects, on Windows and on Linux, and opens in the browser at
`https://localhost:8443` (from other devices in your network:
`https://<LAN address>:8443`).

The panel began as the **Stealth** section of EasyPi, moved out with its proven
security details intact: SSH host-key trust, deployment leases, ACME HTTP-01
with a guarded port 80, an encrypted credential broker and fail-closed DNS.

## Tabs

| Tab | What it is for |
|---|---|
| **Client** | generate the PSK and the public marker, enter the VPS address, save; **Enable** / **Disable** at the top right |
| **Server** | SSH access to the VPS, host-key trust, **Deploy & Start**, optional **Domain & TLS**, server logs, stop and uninstall; the kill switch state |
| **Profile** | the live connection: browser profile, identity, behaviour, kill switch, traffic, runtime log |

## First start and the password

Verify the [panel certificate](#verify-the-panel-certificate) before entering
a password or setup code.

- On first open the panel asks you to **create a password** (at least 10
  characters; it is stored as an scrypt hash).
- **From this computer** no code is needed: a connection from loopback can only
  come from someone already using this computer.
- **From another device** you also enter a one-time **setup code**: the Linux
  installer prints it, and `sudo chameleon-panel setup-code` prints a new one
  while no password is set.
- **Forgot password? Reset** on the sign-in page works only from this computer.
  On a machine without a desktop: `sudo chameleon-panel reset-password` — it
  forgets the password, signs everybody out and prints a new setup code.

## Local network only

Every layer refuses the internet on its own:

1. **Application.** Every request is checked against the TCP peer address; only
   loopback and private networks (10/8, 172.16/12, 192.168/16, 169.254/16) are
   served. `X-Forwarded-For` is never trusted.
2. **Firewall.** Linux: the `CHAMELEON_PANEL` chain accepts the panel port only
   from loopback and those private ranges. Windows: a Windows Firewall rule
   admits the port from the local subnet only.
3. **Sign-in.** Server-side sessions, at most 24 hours, ended when the password
   changes. The cookie is HttpOnly, Secure and SameSite=Strict. Every changing
   request needs the CSRF header and a same-origin request; forms from other
   sites are refused. At most 5 attempts per address in 5 minutes, with the
   counter cleared after successful authentication. Only two password hashes
   can run at once.
4. **TLS.** HTTPS with the panel's own certificate, created at installation; the
   Linux installer prints its SHA-256 fingerprint.

A server without a local network (a VPS) never shows the panel to the internet;
open it through SSH: `ssh -L 8443:127.0.0.1:8443 root@<server>`, then
`https://localhost:8443`.

## Verify the panel certificate

Get the SHA-256 fingerprint **on the machine running the panel**, by local
console or through an SSH connection whose host key you already trust.

On Linux, use the fingerprint printed by the installer or run:

```sh
openssl x509 -in /etc/chameleon/panel/tls.crt -noout -fingerprint -sha256
```

On Windows, run in an administrator PowerShell on the machine running the panel:

```powershell
& "$env:ProgramFiles\Chameleon\chameleon-svc.exe" panel-fingerprint
```

On the device opening the panel, inspect the presented certificate in the
browser's certificate viewer and compare its SHA-256 fingerprint. Ignore
letter case and colons when comparing. Accept the certificate and enter
credentials only after verifying a match. If the browser cannot show the
fingerprint before accepting the connection, use the browser on the host
itself or connect through a trusted SSH tunnel.

## Privileges

| | Linux | Windows |
|---|---|---|
| Panel runs as | system user `chameleon`, no capabilities | virtual account `NT SERVICE\ChameleonPanel` |
| Privileged actions | `sudo -n /usr/lib/chameleon/chameleon-runner <tool> ...`: one sudoers rule, root-owned runner that accepts only `chameleon-netctl` and `chameleon-secrets` and validates every argument | the named pipe `\\.\pipe\ChameleonControl`, open only to SYSTEM, Administrators and the panel's account |
| SSH credentials for the VPS | `systemd-creds` (with the TPM if present) | DPAPI under SYSTEM, in a directory only SYSTEM and Administrators can open |

The VPS SSH password or key never appears on a command line, in the environment
or in a log.

## Command line (Linux)

```sh
sudo chameleon-panel setup-code       # one-time code for the first password (while none is set)
sudo chameleon-panel reset-password   # forget the password, sign everybody out, print a new code
sudo chameleon-panel disable          # turn the tunnel off, like Disable in the panel
```

On Windows, `chameleon-svc.exe recover` (as administrator) disables the tunnel
when the panel cannot be used.

## On the VPS

Deployment keeps the names EasyPi used (`easypi-vps-guard`,
`/etc/nginx/conf.d/easypi-chameleon.conf`, `/var/lib/easypi-chameleon`), so the
panel can take over a VPS that EasyPi deployed without a migration. What
**Deploy & Start** installs is described in
[ARCHITECTURE.md](ARCHITECTURE.md#8-server-on-the-vps).
