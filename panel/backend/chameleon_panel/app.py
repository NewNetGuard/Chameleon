# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Chameleon Panel web application.

The tunnel API under ``/api/stealth``, behind the panel's own login. The
panel answers the local network only.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import time
from typing import Any, Dict, Literal, Optional
from urllib.parse import urlsplit

from fastapi import Body, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from chameleon_panel import paths
from chameleon_panel.security import (
    CSRF_HEADER,
    SESSION_COOKIE,
    LocalNetworkOnly,
    LoginLimiter,
    PasswordStore,
    Session,
    SessionStore,
    SetupCodeStore,
    is_same_machine,
)
from chameleon_panel.stealth.context import require_public_ipv4
from chameleon_panel.stealth.service import get_stealth_service

logger = logging.getLogger("chameleon_panel")

RECONCILE_INTERVAL_SECONDS = 30

sessions = SessionStore()
login_limiter = LoginLimiter()
passwords = PasswordStore(paths.data_dir() / "panel_password.json")
setup_codes = SetupCodeStore(paths.data_dir() / "setup_code.json")
# Two browsers submitting the first password at once: only one may win.
_setup_lock = asyncio.Lock()
_password_slots = asyncio.BoundedSemaphore(2)


async def _password_work(operation, password: str):
    """Bound scrypt work even if the request exits while the worker is running."""
    if _password_slots.locked():
        raise HTTPException(status_code=429, detail="Too many password checks. Try again shortly.")
    await _password_slots.acquire()
    try:
        worker = asyncio.get_running_loop().run_in_executor(None, operation, password)
    except BaseException:
        _password_slots.release()
        raise
    worker.add_done_callback(lambda _: _password_slots.release())
    return await asyncio.shield(worker)

# ── request models ───────────────────────────────────────────────────────────
class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=1024)

class SetupBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Needed only from another device; the computer itself needs no code.
    code: str = Field(default="", max_length=64)
    password: str = Field(min_length=1, max_length=1024)

class StealthClientCfg(BaseModel):
    server_address: Optional[str] = Field(default=None, max_length=320)
    shield_preset: Optional[str] = Field(default=None, max_length=320)
    doh_domain: Optional[str] = Field(default=None, max_length=253)
    buffer_size: Optional[int] = Field(default=None, ge=64, le=65535)
    reconnect_interval: Optional[int] = Field(default=None, ge=1, le=300)
    block_quic: Optional[bool] = None
    fingerprint_mode: Optional[Literal["auto", "mobile", "desktop"]] = None
    psk_key: Optional[str] = Field(default=None, max_length=64)
    reality_public: Optional[str] = Field(default=None, max_length=64)

class StealthServerCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=15)
    user: str = Field(default="root", min_length=1, max_length=32)
    port: int = Field(default=22, ge=1, le=65535)
    password: str = Field(default="", max_length=1024)
    remote_path: str = Field(default="/opt/chameleon-server", max_length=64)
    acme_terms_accepted: bool = False
    domain: str = Field(default="", max_length=253)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        return require_public_ipv4(value, label="Chameleon VPS")

    @field_validator("user")
    @classmethod
    def validate_user(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", value):
            raise ValueError("Invalid SSH username")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("SSH password cannot contain NUL")
        return value

    @field_validator("remote_path")
    @classmethod
    def validate_remote_path(cls, value: str) -> str:
        if value.rstrip("/") != "/opt/chameleon-server":
            raise ValueError("Unsupported remote path")
        return "/opt/chameleon-server"

class StealthHostKeyTrust(BaseModel):
    fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$", max_length=50)

# ── auth dependencies ────────────────────────────────────────────────────────
def _client_host(request: Request) -> str:
    return request.client.host if request.client else ""

def _json_request(request: Request) -> bool:
    # A cross-site form cannot send this content type without a CORS preflight,
    # which the panel never answers.
    return (request.headers.get("content-type") or "").split(";", 1)[0].strip() == "application/json"

def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        # Browsers send Origin on every cross-site POST; a request without it
        # is same-origin or not from a browser, and still needs the CSRF header.
        return True
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    return parsed.netloc.lower() == (request.headers.get("host") or "").lower()

def _current_session(request: Request) -> Optional[Session]:
    return sessions.get(request.cookies.get(SESSION_COOKIE), passwords.fingerprint())

def require_session(request: Request) -> Session:
    session = _current_session(request)
    if session is None:
        raise HTTPException(status_code=401, detail="Sign in to the Chameleon Panel")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        token = request.headers.get(CSRF_HEADER, "")
        if not _same_origin(request) or not token or not _tokens_equal(token, session.csrf):
            raise HTTPException(status_code=403, detail="Request blocked by CSRF protection")
    return session

def _tokens_equal(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a.encode(), b.encode())

def _stealth_operation_result(result: Dict[str, Any]) -> Dict[str, Any]:
    if result.get("busy"):
        raise HTTPException(status_code=409, detail=result.get("log") or "Deployment is busy")
    return result

# ── application ──────────────────────────────────────────────────────────────
async def _reconcile_loop() -> None:
    """Keep the enabled tunnel and its rules current."""
    while True:
        await asyncio.sleep(RECONCILE_INTERVAL_SECONDS)
        try:
            await get_stealth_service().reconcile_if_needed()
        except Exception:  # noqa: BLE001 - keep the loop alive
            logger.exception("reconcile failed")

@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_reconcile_loop())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

def create_app() -> FastAPI:
    app = FastAPI(title="Chameleon Panel", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ── auth ─────────────────────────────────────────────────────────────────
    @app.post("/api/auth/login")
    async def login(body: LoginBody, request: Request, response: Response):
        client = _client_host(request)
        if not _same_origin(request) or not _json_request(request):
            raise HTTPException(status_code=403, detail="Request blocked by CSRF protection")
        if not passwords.is_set():
            raise HTTPException(status_code=409, detail="Create the panel password first")
        if not login_limiter.reserve(client):
            raise HTTPException(status_code=429, detail="Too many attempts. Try again in a few minutes.")
        fingerprint = await _password_work(passwords.verified_fingerprint, body.password)
        if fingerprint is None or fingerprint != passwords.fingerprint():
            await asyncio.sleep(1)
            raise HTTPException(status_code=401, detail="Wrong password")
        login_limiter.succeeded(client)
        token, session = sessions.create(fingerprint)
        response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=True,
                            samesite="strict", path="/")
        return {"authenticated": True, "csrf": session.csrf}

    @app.post("/api/auth/setup")
    async def setup(body: SetupBody, request: Request, response: Response):
        """Create the first panel password (or a new one after a reset).

        Needs the one-time code shown where Chameleon was started, so another
        device on the network cannot claim the panel first.
        """
        client = _client_host(request)
        if not _same_origin(request) or not _json_request(request):
            raise HTTPException(status_code=403, detail="Request blocked by CSRF protection")
        async with _setup_lock:
            if passwords.is_set():
                raise HTTPException(status_code=409, detail="The panel password already exists. Sign in.")
            if not login_limiter.reserve(client):
                raise HTTPException(status_code=429, detail="Too many attempts. Try again in a few minutes.")
            if not is_same_machine(client) and not setup_codes.verify(body.code):
                await asyncio.sleep(1)
                raise HTTPException(
                    status_code=401,
                    detail="Wrong setup code. Create the password on the computer Chameleon runs on, "
                           "or use the code shown on the server.")
            try:
                record = await _password_work(passwords.prepare_record, body.password)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            fingerprint = passwords.save_record(record)
            setup_codes.clear()
        login_limiter.succeeded(client)
        if fingerprint != passwords.fingerprint():
            raise HTTPException(status_code=500, detail="The password could not be stored")
        token, session = sessions.create(fingerprint)
        response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=True,
                            samesite="strict", path="/")
        return {"authenticated": True, "csrf": session.csrf}

    @app.post("/api/auth/reset")
    async def reset(request: Request):
        """Forgotten password: only on the computer Chameleon runs on.

        Forgets the password and signs every browser out; the panel then asks
        for a new one. Other devices reset with chameleon-panel reset-password.
        """
        if not is_same_machine(_client_host(request)):
            raise HTTPException(
                status_code=403,
                detail="Reset the password on the computer Chameleon runs on.")
        if not _same_origin(request) or not _json_request(request):
            raise HTTPException(status_code=403, detail="Request blocked by CSRF protection")
        async with _setup_lock:
            passwords.delete()
            setup_codes.clear()
        return {"authenticated": False, "password_set": False}

    @app.post("/api/auth/logout")
    async def logout(request: Request, response: Response,
                     _session: Session = Depends(require_session)):
        sessions.delete(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"authenticated": False}

    @app.get("/api/auth/session")
    async def session_state(request: Request):
        session = _current_session(request)
        if session is None:
            return {"authenticated": False, "password_set": passwords.is_set(),
                    "same_machine": is_same_machine(_client_host(request))}
        return {"authenticated": True, "csrf": session.csrf}

    # ── stealth ──────────────────────────────────────────────────────────────
    stealth = get_stealth_service

    @app.get("/api/stealth/status")
    async def stealth_status(_s: Session = Depends(require_session)):
        return await stealth().status()

    @app.post("/api/stealth/client")
    async def stealth_save_client(body: StealthClientCfg, _s: Session = Depends(require_session)):
        try:
            return await stealth().save_client_and_apply(**body.model_dump(exclude_none=True))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/stealth/generate/psk")
    async def stealth_gen_psk(_s: Session = Depends(require_session)):
        return stealth().generate_psk()

    @app.post("/api/stealth/generate/reality")
    async def stealth_gen_reality(_s: Session = Depends(require_session)):
        return stealth().generate_reality()

    @app.post("/api/stealth/enable")
    async def stealth_enable(_body: Optional[Dict[str, Any]] = Body(default=None),
                             _s: Session = Depends(require_session)):
        operation_log = logging.getLogger("uvicorn.error")
        started = time.monotonic()
        operation_log.info("Chameleon enable requested")
        try:
            result = await stealth().enable()
        except Exception as exc:
            operation_log.error("Chameleon enable aborted (%s)", type(exc).__name__)
            raise
        operation_log.info(
            "Chameleon enable finished in %.1fs (enabled=%s, running=%s, connected=%s, rejected=%s)",
            time.monotonic() - started,
            bool(result.get("enabled")), bool(result.get("running")),
            bool(result.get("connected")), not result.get("success", True),
        )
        if not result.get("success", True) and result.get("error"):
            raise HTTPException(status_code=400, detail=result.get("error"))
        return result

    @app.post("/api/stealth/disable")
    async def stealth_disable(_s: Session = Depends(require_session)):
        result = await stealth().disable()
        if not result.get("success", True):
            raise HTTPException(status_code=400,
                                detail=result.get("error") or "Failed to disable the tunnel safely")
        return result

    @app.delete("/api/stealth/config")
    async def stealth_delete(_s: Session = Depends(require_session)):
        return _stealth_operation_result(await stealth().delete_config())

    @app.post("/api/stealth/server")
    async def stealth_save_server(body: StealthServerCfg, _s: Session = Depends(require_session)):
        try:
            return stealth().save_server(body.host, body.user, body.port, body.password,
                                         body.remote_path, body.acme_terms_accepted, body.domain)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @app.post("/api/stealth/server/domain-tls")
    async def stealth_configure_domain_tls(_s: Session = Depends(require_session)):
        return _stealth_operation_result(await stealth().configure_domain_tls())

    @app.delete("/api/stealth/server/domain-tls")
    async def stealth_remove_domain_tls(_s: Session = Depends(require_session)):
        return _stealth_operation_result(await stealth().remove_domain_tls())

    @app.post("/api/stealth/server/check")
    async def stealth_check_ssh(_s: Session = Depends(require_session)):
        return _stealth_operation_result(await stealth().check_ssh())

    @app.post("/api/stealth/server/trust-host-key")
    async def stealth_trust_host_key(body: StealthHostKeyTrust,
                                     _s: Session = Depends(require_session)):
        return _stealth_operation_result(await stealth().trust_ssh_host_key(body.fingerprint))

    @app.post("/api/stealth/server/deploy")
    async def stealth_deploy(_s: Session = Depends(require_session)):
        return _stealth_operation_result(await stealth().deploy_server())

    @app.post("/api/stealth/server/stop")
    async def stealth_stop_server(_s: Session = Depends(require_session)):
        return _stealth_operation_result(await stealth().stop_server())

    @app.post("/api/stealth/server/uninstall")
    async def stealth_uninstall_server(_s: Session = Depends(require_session)):
        return _stealth_operation_result(await stealth().uninstall_server())

    @app.post("/api/stealth/server/logs")
    async def stealth_server_logs(_s: Session = Depends(require_session)):
        return await stealth().server_logs()

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def api_not_found(rest: str):
        return JSONResponse({"detail": "Not found"}, status_code=404)

    # ── web UI ───────────────────────────────────────────────────────────────
    web_root = paths.web_root().resolve()

    @app.get("/{path:path}")
    async def web(path: str):
        candidate = (web_root / path).resolve()
        if path and candidate.is_file() and web_root in candidate.parents:
            return FileResponse(candidate)
        index = web_root / "index.html"
        if index.is_file():
            return FileResponse(index, headers={"Cache-Control": "no-store"})
        return JSONResponse({"detail": "The panel web UI is not installed"}, status_code=503)

    return LocalNetworkOnly(app)
