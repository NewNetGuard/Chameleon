# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""StealthRuntimeMixin implementation."""

from __future__ import annotations

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

class StealthRuntimeMixin:
    # ── client lifecycle ──────────────────────────────────────────────────────
    async def enable(self) -> Dict[str, Any]:
        async with self._runtime_lock:
            return await self._enable_locked()

    async def _enable_locked(self) -> Dict[str, Any]:
        meta = self._meta()
        if not (meta.get("server_address") and meta.get("psk_key")):
            return {
                "success": False,
                "error": "Set the server address + generate keys first",
            }
        if not meta.get("ssh", {}).get("ip_shield_deployed"):
            return {
                "success": False,
                "error": "Deploy IP Shield to the VPS before enabling Chameleon",
            }
        self._write_client_conf(meta)
        # Persist the requested protection before entering the privileged
        # startup path. If the tunnel cannot start, boot and reconcile still
        # know that this device must stay fail-closed.
        meta["enabled"] = True
        self._save_meta(meta)
        block_quic = "true" if meta.get("block_quic", True) else "false"
        res = await self._run("up", str(self._conf_path), block_quic, timeout=45)
        if not (res.get("running") or res.get("killswitch")) and res.get("error"):
            return res
        # Both launchers already return the runtime snapshot after startup.
        return self._format_status(res)

    async def disable(self) -> Dict[str, Any]:
        async with self._runtime_lock:
            return await self._disable_locked()

    async def _disable_locked(self) -> Dict[str, Any]:
        res = await self._run("down", timeout=30)
        if res.get("success") is True:
            meta = self._meta()
            meta["enabled"] = False
            self._save_meta(meta)
            # Return the same complete, authoritative state shape as enable().
            # The UI can then update without a racy follow-up GET.
            return await self.status()
        return res

    async def reconcile_if_needed(self) -> None:
        # Re-read both intent and runtime only after any manual transition has
        # completed. This prevents the watchdog from observing the intentional
        # startup gap and launching a second privileged `up` in parallel.
        async with self._runtime_lock:
            meta = self._meta()
            if not meta.get("enabled"):
                return
            runtime = await self._run("status", timeout=15)
            if not runtime.get("running"):
                # Persisted strict intent survives panel restarts and full boots.
                # Startup failure leaves the privileged kill switch in place.
                await self._enable_locked()

    @staticmethod
    def _log_tail(n: int = 40) -> str:
        try:
            data = (
                Path(CLIENT_LOG)
                .read_text(encoding="utf-8", errors="ignore")
                .splitlines()
            )
            return "\n".join(data[-n:])
        except Exception:
            return ""

    async def status(self) -> Dict[str, Any]:
        return self._format_status(await self._run("status", timeout=15))

    def _format_status(self, runtime: Dict[str, Any]) -> Dict[str, Any]:
        st = dict(runtime)
        st.update(self.client_state())
        st.update(self.server_state())
        if st.get("health_error") and not st.get("connected"):
            code = st.get("failure_code") or "server_connection_failed"
            st["health_title"] = "Chameleon server unavailable"
            if code == "server_unavailable":
                st["health_hint"] = (
                    "The VPS refused the connection. Chameleon Server is probably stopped or removed. "
                    "Open Server, check SSH, then run Deploy & Start."
                )
            elif code == "server_timeout":
                st["health_hint"] = (
                    "The VPS did not answer. Check its network, firewall and SSH, then deploy the server again."
                )
            elif code == "server_tls_failed":
                st["health_hint"] = (
                    "The server identity or TLS certificate is invalid. Do not bypass verification; deploy again."
                )
            elif code == "server_auth_failed":
                st["health_hint"] = (
                    "The client and server credentials do not match. Deploy the server again to synchronize them."
                )
            elif code == "server_route_failed":
                st["health_hint"] = (
                    "The authenticated Chameleon HTTPS route is missing on the VPS. Deploy the server again."
                )
            elif code == "server_protocol_failed":
                st["health_hint"] = (
                    "The installed Chameleon client and server are incompatible. Update Chameleon and deploy the server again."
                )
            else:
                st["health_hint"] = (
                    "The tunnel could not reach a working Chameleon Server. Check SSH and deploy the server again."
                )
        st["runtime_log"] = self._log_tail()
        return st

    @_deployment_locked("config-delete")
    async def delete_config(self) -> Dict[str, Any]:
        async with self._runtime_lock:
            disabled = await self._disable_locked()
            if disabled.get("success") is not True:
                return disabled
            try:
                for credential_name in (
                    "ssh-private-key",
                    "ssh-password",
                ):
                    self._secret_delete(credential_name)
                self._conf_path.unlink(missing_ok=True)
                self._meta_path.unlink(missing_ok=True)
            except Exception as e:  # noqa: BLE001
                return {"success": False, "error": str(e)}
            return {"success": True, "configured": False}
