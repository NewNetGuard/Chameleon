# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""StealthClientMixin implementation."""

from __future__ import annotations

import signal
from urllib.parse import urlsplit

# ruff: noqa: F401

from chameleon_panel.stealth.context import (
    Any,
    CLIENT_LOG,
    CONFIG_NAME,
    Dict,
    Ed25519PrivateKey,
    List,
    META_NAME,
    Optional,
    Path,
    REMOTE_SERVER_DIR,
    SCRIPT_REL,
    SECRET_SCRIPT_REL,
    SERVER_BIN,
    X25519PrivateKey,
    _DUCKDNS_DOMAIN,
    _DeploymentLease,
    _HEX32,
    _deployment_locked,
    _friendly_ssh_err,
    _gen_psk,
    _gen_x25519_public,
    _normalize_server_addr,
    asyncio,
    base64,
    hashlib,
    hmac,
    httpx,
    io,
    ipaddress,
    json,
    logger,
    logging,
    os,
    paths,
    posixpath,
    re,
    require_public_ipv4,
    serialization,
    socket,
    ssl,
    subprocess,
    time,
    wraps,
)

class StealthClientMixin:
    @staticmethod
    async def _stop_timed_out_process(proc: Any) -> None:
        """Stop and reap the complete privileged command group before returning."""
        if proc.returncode is not None:
            return
        if os.name == "nt":
            # The Windows control client holds no privileges itself: the
            # service finishes or abandons the request on its own.
            proc.kill()
            await proc.communicate()
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError:
            proc.terminate()
        try:
            await asyncio.wait_for(proc.communicate(), timeout=2)
            return
        except asyncio.TimeoutError:
            pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except OSError:
            proc.kill()
        await proc.communicate()

    async def _run(self, action: str, *args: str, timeout: int = 60) -> Dict[str, Any]:
        runner = paths.RUNNER
        if not runner.exists():
            return {"success": False, "error": f"runner not found: {runner}"}
        timeout_seconds = max(0.1, float(timeout))
        safety_margin = min(1.0, timeout_seconds / 2)
        privileged_deadline_ns = time.monotonic_ns() + int(
            max(0.05, timeout_seconds - safety_margin) * 1_000_000_000
        )
        if os.name == "nt":
            # Windows: the runner is the Chameleon service's control client.
            cmd = [str(runner), "ctl", SCRIPT_REL, action, *[str(a) for a in args]]
        else:
            cmd = [
                "sudo",
                "-n",
                str(runner),
                "--deadline-monotonic-ns",
                str(privileged_deadline_ns),
                SCRIPT_REL,
                action,
                *[str(a) for a in args],
            ]
        proc: Any = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name != "nt",
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            if proc is not None:
                await self._stop_timed_out_process(proc)
            return {"success": False, "error": f"timeout running '{action}'"}
        except Exception as e:  # noqa: BLE001
            return {"success": False, "error": str(e)}
        if proc.returncode == 124:
            return {"success": False, "error": f"timeout running '{action}'"}
        out = (stdout or b"").decode(errors="ignore").strip()
        parsed = self._last_json(out)
        if parsed is None:
            err = (stderr or b"").decode(errors="ignore").strip() or out
            return {"success": proc.returncode == 0, "error": err[:300]}
        return parsed

    def _secret_command(
        self, action: str, name: str, value: Optional[str] = None
    ) -> str:
        """Call the root credential broker without exposing secret material in argv."""
        runner = paths.RUNNER
        if os.name == "nt":
            cmd = [str(runner), "ctl", SECRET_SCRIPT_REL, action, name]
        else:
            cmd = ["sudo", "-n", str(runner), SECRET_SCRIPT_REL, action, name]
        try:
            completed = subprocess.run(
                cmd,
                input=None if value is None else value.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
        except Exception as exc:
            raise RuntimeError("Secure credential storage is unavailable") from exc
        if completed.returncode != 0:
            raise RuntimeError("Secure credential storage rejected the operation")
        return completed.stdout.decode("utf-8", errors="strict").rstrip("\n")

    def _secret_store(self, name: str, value: str) -> str:
        self._secret_command("store", name, value)
        return self._secret_command("mode", name)

    def _secret_read(self, name: str) -> str:
        return self._secret_command("read", name)

    def _secret_delete(self, name: str) -> None:
        self._secret_command("delete", name)

    @staticmethod
    def _credential_label(mode: str) -> str:
        return "TPM + system encryption" if "tpm2" in mode else "system encryption"

    @staticmethod
    def _last_json(text: str) -> Optional[Dict[str, Any]]:
        found: Optional[Dict[str, Any]] = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    found = json.loads(line)
                except Exception:
                    continue
        return found

    # ── meta ──────────────────────────────────────────────────────────────────
    def _defaults(self) -> Dict[str, Any]:
        return {
            "server_address": "",
            "transport": "http2",
            "cert_mode": "reality",
            "shield_preset": "ip",
            "doh_domain": "",
            "buffer_size": 1000,
            "reconnect_interval": 5,
            "block_quic": True,
            "fingerprint_mode": "auto",
            "psk_key": "",
            "client_auth_key": "",
            "reality_public": "",
            "enabled": False,
            # Digest of the mobile registry last published to the VPS.
            "mobile_registry_digest": "",
            "ssh": {
                "host": "",
                "user": "root",
                "port": 22,
                "password": "",
                "ssh_password_stored": False,
                "ssh_key_installed": False,
                "ssh_key_verified": False,
                "ssh_key_fingerprint": "",
                "credential_protection": "",
                "acme_terms_accepted": False,
                "ip_shield_deployed": False,
                "domain": "",
                "domain_tls_deployed": False,
                "host_key_type": "",
                "host_key_data": "",
                "host_key_sha256": "",
                "remote_path": REMOTE_SERVER_DIR,
            },
        }

    def _meta(self) -> Dict[str, Any]:
        d = self._defaults()
        try:
            if self._meta_path.exists():
                stored = json.loads(self._meta_path.read_text(encoding="utf-8"))
                if isinstance(stored, dict):
                    for k, v in d.items():
                        if k == "ssh" and isinstance(stored.get("ssh"), dict):
                            v.update({kk: stored["ssh"].get(kk, v[kk]) for kk in v})
                        elif k in stored:
                            d[k] = stored[k]
        except Exception:
            pass
        return d

    def _save_meta(self, meta: Dict[str, Any]) -> None:
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            self._meta_path.write_text(json.dumps(meta), encoding="utf-8")
            self._meta_path.chmod(
                0o600
            )  # holds tunnel keys and non-secret deployment metadata
        except Exception as e:  # noqa: BLE001
            logger.debug(f"stealth meta save failed: {e}")

    def _write_client_conf(self, meta: Dict[str, Any]) -> None:
        conf = {
            "server_address": meta["server_address"],
            # The privileged runner validates this public VPS address and uses it
            # only to bootstrap the TCP route. TLS identity and HTTP Host remain
            # bound to server_address, so domain mode does not depend on local DNS.
            "server_route_ip": self._ip_shield_address(meta),
            "psk_key": meta.get("client_auth_key") or meta["psk_key"],
            "transport_key": meta["psk_key"],
            "protocol": "http2",
            "reality_server_public_key": meta.get("reality_public", ""),
            "reality_shield_preset": "ip",
            "verify_server_certificate": True,
            "doh_domain": meta.get("doh_domain", ""),
            "buffer_size": int(meta.get("buffer_size") or 1000),
            "reconnect_interval": int(meta.get("reconnect_interval") or 5),
            "fingerprint_mode": meta.get("fingerprint_mode") or "auto",
            "tun_name": "cham0",
            "tun_addr": "10.10.0.2/32",
            "mtu": 1420,
            "configure_tun": True,
            "status_file": "/run/chameleon/status/status.json",
        }
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._conf_path.write_text(json.dumps(conf), encoding="utf-8")
        try:
            self._conf_path.chmod(0o600)
        except Exception:
            pass

    # ── key generation (Client tab "Generate") ────────────────────────────────
    def generate_psk(self) -> Dict[str, Any]:
        meta = self._meta()
        meta["psk_key"] = _gen_psk()
        self._save_meta(meta)
        return {"success": True, "psk_key": meta["psk_key"]}

    def generate_reality(self) -> Dict[str, Any]:
        meta = self._meta()
        pub = _gen_x25519_public()
        meta["reality_public"] = pub
        meta.pop("reality_private", None)
        self._save_meta(meta)
        return {"success": True, "reality_public": pub}

    # ── client settings ───────────────────────────────────────────────────────
    def save_client(self, **fields: Any) -> Dict[str, Any]:
        meta = self._meta()
        if "server_address" in fields:
            new_address = _normalize_server_addr(str(fields["server_address"] or ""))
            if new_address != meta.get("server_address"):
                meta["ssh"]["ip_shield_deployed"] = False
            meta["server_address"] = new_address
        if fields.get("psk_key"):
            if not _HEX32.match(str(fields["psk_key"]).strip()):
                raise ValueError("PSK must be 64 hex characters")
            meta["psk_key"] = str(fields["psk_key"]).strip()
        if fields.get("reality_public"):
            if not _HEX32.match(str(fields["reality_public"]).strip()):
                raise ValueError("REALITY public key must be 64 hex characters")
            meta["reality_public"] = str(fields["reality_public"]).strip()
        if "shield_preset" in fields and fields["shield_preset"] is not None:
            if str(fields["shield_preset"]).strip() != "ip":
                raise ValueError("Only IP Shield is supported")
            meta["shield_preset"] = "ip"
        if "doh_domain" in fields and fields["doh_domain"] is not None:
            meta["doh_domain"] = str(fields["doh_domain"]).strip()
        for k in ("buffer_size", "reconnect_interval"):
            if fields.get(k) is not None:
                try:
                    meta[k] = int(fields[k])
                except Exception:
                    pass
        if fields.get("block_quic") is not None:
            meta["block_quic"] = bool(fields["block_quic"])
        if fields.get("fingerprint_mode") is not None:
            fingerprint_mode = str(fields["fingerprint_mode"]).strip().lower()
            if fingerprint_mode not in {"auto", "mobile", "desktop"}:
                raise ValueError("fingerprint_mode must be auto, mobile, or desktop")
            meta["fingerprint_mode"] = fingerprint_mode
        self._save_meta(meta)
        if meta.get("server_address") and meta.get("psk_key"):
            self._write_client_conf(meta)
        return {"success": True, **self.client_state()}

    async def save_client_and_apply(self, **fields: Any) -> Dict[str, Any]:
        """Save settings and restart an already-enabled tunnel with the new config."""
        async with self._runtime_lock:
            was_enabled = bool(self._meta().get("enabled"))
            saved = self.save_client(**fields)
            if not was_enabled:
                return saved
            if saved.get("shield_preset") == "ip" and not self._meta()["ssh"].get(
                "ip_shield_deployed"
            ):
                saved["warning"] = (
                    "Deploy IP Shield to the VPS before applying it to the active tunnel"
                )
                return saved
            return await self._enable_locked()

    def client_state(self) -> Dict[str, Any]:
        m = self._meta()
        return {
            "configured": bool(
                m["server_address"] and m["psk_key"] and m["reality_public"]
            ),
            "server_address": m["server_address"],
            "transport": m["transport"],
            "cert_mode": m["cert_mode"],
            "shield_preset": m["shield_preset"],
            "reality_public": m["reality_public"],
            "has_psk": bool(m["psk_key"]),
            "doh_domain": m["doh_domain"],
            "buffer_size": m["buffer_size"],
            "reconnect_interval": m["reconnect_interval"],
            "block_quic": m["block_quic"],
            "fingerprint_mode": m["fingerprint_mode"],
            "enabled": m["enabled"],
            "shield_migration_required": m.get("shield_preset") != "ip",
        }
