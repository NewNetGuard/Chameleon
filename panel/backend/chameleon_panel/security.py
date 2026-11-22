# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Access control of the Chameleon Panel: local network only, login, CSRF.

Every layer refuses on its own:

* ``LocalNetworkOnly`` serves only TCP peers in loopback, private, link-local
  or unique-local ranges. The peer address comes from the socket; forwarding
  headers are never trusted (the panel is not meant to sit behind a proxy).
* ``PasswordStore`` keeps one panel password as an scrypt hash, 0600.
* The first password, and a reset, are done from the computer Chameleon runs
  on (a loopback client): being at that computer is the proof of ownership.
  Another device on the network needs the one-time code of
  ``SetupCodeStore``, which only the installer or ``chameleon-panel
  reset-password`` prints at the server. The panel never shows it.
* ``SessionStore`` keeps random session tokens in memory with an idle and an
  absolute lifetime; a panel restart signs everybody out, and a session ends
  as soon as the password it was opened with is reset or changed.
* ``LoginLimiter`` slows down password guessing per client address.
* Mutating requests need the panel's CSRF header and a same-origin ``Origin``.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from starlette.types import ASGIApp, Receive, Scope, Send

SESSION_COOKIE = "chameleon_session"
CSRF_HEADER = "x-chameleon-csrf"
SESSION_IDLE_SECONDS = 2 * 3600
SESSION_MAX_SECONDS = 24 * 3600

_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def is_local_client(host: Optional[str]) -> bool:
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(address in network for network in _LOCAL_NETWORKS)


def is_same_machine(host: Optional[str]) -> bool:
    """True for loopback peers: a browser on the computer Chameleon runs on.

    Under WSL, Windows forwards only its own localhost into WSL, where such
    connections arrive from 127.0.0.1; the local network cannot reach them.
    """
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


class LocalNetworkOnly:
    """ASGI middleware: close every request that does not come from the LAN."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            client = scope.get("client")
            if not client or not is_local_client(client[0]):
                if scope["type"] == "http":
                    await send({"type": "http.response.start", "status": 403,
                                "headers": [(b"content-type", b"text/plain"),
                                            (b"connection", b"close")]})
                    await send({"type": "http.response.body",
                                "body": b"The Chameleon Panel is available on the local network only.\n"})
                else:
                    await send({"type": "websocket.close", "code": 1008})
                return
        await self.app(scope, receive, send)


# ── password ─────────────────────────────────────────────────────────────────
_SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1, "maxmem": 64 * 1024 * 1024, "dklen": 32}


class PasswordStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def is_set(self) -> bool:
        return self.path.is_file()

    def fingerprint(self) -> Optional[str]:
        """Identifies the current password (its salted hash); None when unset."""
        try:
            record = json.loads(self.path.read_text(encoding="utf-8"))
            return str(record["hash"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)

    def set(self, password: str) -> str:
        return self.save_record(self.prepare_record(password))

    @staticmethod
    def prepare_record(password: str) -> dict:
        if len(password) < 10:
            raise ValueError("The panel password must have at least 10 characters")
        if len(password) > 1024 or "\x00" in password:
            raise ValueError("Invalid panel password")
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
        return {"v": 1, "salt": salt.hex(), "hash": digest.hex()}

    def save_record(self, record: dict) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.{secrets.token_hex(4)}")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
        return record["hash"]

    def verified_fingerprint(self, password: str) -> Optional[str]:
        """Return the fingerprint from the same record used to check the password."""
        try:
            record = json.loads(self.path.read_text(encoding="utf-8"))
            salt = bytes.fromhex(record["salt"])
            expected = bytes.fromhex(record["hash"])
        except (OSError, ValueError, KeyError, TypeError):
            # Spend the same work so a missing file cannot be told apart.
            hashlib.scrypt(b"x", salt=b"0" * 16, **_SCRYPT)
            return None
        if len(password) > 1024:
            return None
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
        return record["hash"] if hmac.compare_digest(digest, expected) else None


# ── first-password setup code ────────────────────────────────────────────────
# No 0/O, 1/I/L: the code is read off a terminal and typed into a browser.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_LENGTH = 8


def _normalize_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


class SetupCodeStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def create(self) -> str:
        """Replace any previous code with a new one and return it for display."""
        raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))
        digest = hashlib.sha256(raw.encode("ascii")).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.{secrets.token_hex(4)}")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"v": 1, "hash": digest}, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)
        return f"{raw[:4]}-{raw[4:]}"

    def verify(self, code: str) -> bool:
        try:
            expected = str(json.loads(self.path.read_text(encoding="utf-8"))["hash"])
        except (OSError, ValueError, KeyError, TypeError):
            return False
        given = _normalize_code(code[:64])
        if len(given) != _CODE_LENGTH:
            return False
        actual = hashlib.sha256(given.encode("ascii", "replace")).hexdigest()
        return hmac.compare_digest(actual, expected)

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)


# ── sessions ─────────────────────────────────────────────────────────────────
@dataclass
class Session:
    csrf: str
    created: float
    last_seen: float
    password: str  # fingerprint of the password the session was opened with


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("ascii", "replace")).hexdigest()

    def create(self, password_fingerprint: str) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        now = time.time()
        session = Session(csrf=secrets.token_urlsafe(24), created=now, last_seen=now,
                          password=password_fingerprint)
        with self._lock:
            self._expire(now)
            self._sessions[self._key(token)] = session
        return token, session

    def get(self, token: Optional[str], password_fingerprint: Optional[str]) -> Optional[Session]:
        if not token or len(token) > 128:
            return None
        now = time.time()
        with self._lock:
            self._expire(now)
            key = self._key(token)
            session = self._sessions.get(key)
            if session is None:
                return None
            if password_fingerprint is None or not hmac.compare_digest(
                    session.password, password_fingerprint):
                # The password was reset or changed: this session is over.
                del self._sessions[key]
                return None
            session.last_seen = now
            return session

    def delete(self, token: Optional[str]) -> None:
        if token:
            with self._lock:
                self._sessions.pop(self._key(token), None)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def _expire(self, now: float) -> None:
        for key, session in list(self._sessions.items()):
            if (now - session.last_seen > SESSION_IDLE_SECONDS
                    or now - session.created > SESSION_MAX_SECONDS):
                del self._sessions[key]


# ── login rate limit ─────────────────────────────────────────────────────────
class LoginLimiter:
    """Reserve an attempt before starting authentication work."""

    def __init__(self, attempts: int = 5, window: float = 300.0) -> None:
        self.attempts = attempts
        self.window = window
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._next_cleanup = 0.0

    def reserve(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if now >= self._next_cleanup:
                self._attempts = {address: attempts for address, attempts in self._attempts.items()
                                  if now - attempts[-1] < self.window}
                self._next_cleanup = now + self.window
            recent = [t for t in self._attempts.get(client, []) if now - t < self.window]
            if len(recent) >= self.attempts:
                return False
            recent.append(now)
            self._attempts[client] = recent
            return True

    def succeeded(self, client: str) -> None:
        with self._lock:
            self._attempts.pop(client, None)
