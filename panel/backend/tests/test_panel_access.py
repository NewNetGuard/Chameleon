# Copyright (c) 2026 NewNetGuard
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Access control of the panel: local network only, login, CSRF."""

from __future__ import annotations

import asyncio
import importlib
import os
import sys
import threading
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

PANEL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PANEL))


@pytest.fixture()
def panel(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAMELEON_PANEL_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("CHAMELEON_PANEL_ROOT", str(tmp_path / "root"))
    (tmp_path / "root" / "web").mkdir(parents=True)
    (tmp_path / "root" / "web" / "index.html").write_text("<html>panel</html>")
    for name in [m for m in sys.modules if m.startswith("chameleon_panel")]:
        del sys.modules[name]
    app_module = importlib.import_module("chameleon_panel.app")
    app_module.passwords.set("correct horse battery")
    return app_module


def client(app_module, host="192.168.1.20"):
    return TestClient(app_module.create_app(), base_url="https://panel.lan:8443",
                      client=(host, 50000))


@pytest.mark.parametrize("host", ["8.8.8.8", "100.64.1.1", "2001:4860::1", "testclient"])
def test_internet_clients_are_refused_everywhere(panel, host):
    c = client(panel, host)
    for method, path in [("GET", "/"), ("GET", "/api/auth/session"),
                         ("POST", "/api/auth/login"), ("GET", "/api/stealth/status")]:
        response = c.request(method, path, json={"password": "correct horse battery"})
        assert response.status_code == 403, (host, path)
        assert "local network only" in response.text


@pytest.mark.parametrize("host", ["127.0.0.1", "10.1.2.3", "172.20.0.5", "192.168.50.7",
                                  "169.254.3.3", "fd00::5", "::ffff:192.168.0.9"])
def test_local_clients_reach_the_login(panel, host):
    c = client(panel, host)
    assert c.get("/").status_code == 200
    assert c.get("/api/auth/session").json()["authenticated"] is False


def test_api_needs_a_session(panel):
    c = client(panel)
    assert c.get("/api/stealth/status").status_code == 401
    assert c.post("/api/stealth/enable").status_code == 401


def test_login_rejects_wrong_password_and_rate_limits(panel):
    c = client(panel)
    for _ in range(5):
        assert c.post("/api/auth/login", json={"password": "wrong password!"}).status_code == 401
    assert c.post("/api/auth/login", json={"password": "correct horse battery"}).status_code == 429


def test_password_work_is_bounded_across_addresses(panel, monkeypatch):
    entered = threading.Barrier(3)
    release = threading.Event()

    def verify(_password):
        entered.wait(timeout=5)
        assert release.wait(timeout=5)
        return panel.passwords.fingerprint()

    monkeypatch.setattr(panel.passwords, "verified_fingerprint", verify)

    async def run():
        app = panel.create_app()

        async def login(address):
            transport = httpx.ASGITransport(app=app, client=(address, 50000))
            async with httpx.AsyncClient(transport=transport, base_url="https://panel.lan") as c:
                return await c.post("/api/auth/login", json={"password": "example"})

        pending = [asyncio.create_task(login(f"192.168.1.{i}")) for i in (2, 3)]
        try:
            await asyncio.to_thread(entered.wait, 5)
            assert (await login("192.168.1.4")).status_code == 429
        finally:
            release.set()
            results = await asyncio.gather(*pending)
        assert all(response.status_code == 200 for response in results)

    asyncio.run(run())


def test_old_password_cannot_create_session_after_password_changes(panel, monkeypatch):
    verify = panel.passwords.verified_fingerprint
    replacement = panel.passwords.prepare_record("a different password")

    def change_after_verify(password):
        fingerprint = verify(password)
        panel.passwords.save_record(replacement)
        return fingerprint

    monkeypatch.setattr(panel.passwords, "verified_fingerprint", change_after_verify)
    c = client(panel)
    assert c.post("/api/auth/login", json={"password": "correct horse battery"}).status_code == 401
    assert c.get("/api/auth/session").json()["authenticated"] is False


def test_login_session_and_csrf(panel, monkeypatch):
    c = client(panel)
    login = c.post("/api/auth/login", json={"password": "correct horse battery"})
    assert login.status_code == 200
    csrf = login.json()["csrf"]
    cookie = login.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie

    calls = []

    async def fake_disable():
        calls.append("disable")
        return {"success": True}

    monkeypatch.setattr(panel.get_stealth_service(), "disable", fake_disable)
    # Mutations without the CSRF token or from another origin are refused.
    assert c.post("/api/stealth/disable").status_code == 403
    assert c.post("/api/stealth/disable", headers={"X-Chameleon-CSRF": "x" * 32}).status_code == 403
    assert c.post("/api/stealth/disable", headers={"X-Chameleon-CSRF": csrf,
                                                   "Origin": "https://evil.example"}).status_code == 403
    assert calls == []
    ok = c.post("/api/stealth/disable", headers={"X-Chameleon-CSRF": csrf,
                                                 "Origin": "https://panel.lan:8443"})
    assert ok.status_code == 200 and calls == ["disable"]
    # The session survives a page reload and hands out the same CSRF token.
    assert c.get("/api/auth/session").json() == {"authenticated": True, "csrf": csrf}
    # Logout ends it.
    assert c.post("/api/auth/logout", headers={"X-Chameleon-CSRF": csrf}).status_code == 200
    assert c.get("/api/stealth/status").status_code == 401


def test_security_headers(panel):
    response = client(panel).get("/")
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_web_root_does_not_escape(panel, tmp_path):
    (tmp_path / "secret.txt").write_text("secret")
    response = client(panel).get("/../secret.txt")
    assert "secret" not in response.text


def test_password_file_is_private(panel, tmp_path):
    path = tmp_path / "data" / "panel_password.json"
    assert path.is_file()
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0
    assert "correct horse" not in path.read_text()
    with pytest.raises(ValueError):
        panel.passwords.set("short")


@pytest.fixture()
def fresh_panel(panel):
    """A panel without a password yet, with a setup code shown at the server."""
    panel.passwords.delete()
    code = panel.setup_codes.create()
    return panel, code


def test_first_password_needs_the_setup_code(fresh_panel):
    panel, code = fresh_panel
    c = client(panel)
    assert c.get("/api/auth/session").json() == {"authenticated": False, "password_set": False, "same_machine": False}
    assert c.post("/api/auth/login", json={"password": "anything at all"}).status_code == 409
    wrong = c.post("/api/auth/setup", json={"code": "AAAA-AAAA", "password": "my new password"})
    assert wrong.status_code == 401 and not panel.passwords.is_set()
    short = c.post("/api/auth/setup", json={"code": code, "password": "short"})
    assert short.status_code == 400 and not panel.passwords.is_set()
    # The code is accepted without the dash and in lower case.
    ok = c.post("/api/auth/setup", json={"code": code.replace("-", "").lower(),
                                         "password": "my new password"})
    assert ok.status_code == 200 and ok.json()["authenticated"] is True
    assert c.get("/api/stealth/devices").status_code in (200, 404)
    assert c.get("/api/auth/session").json()["authenticated"] is True
    # The code is gone and the password cannot be created twice.
    again = client(panel).post("/api/auth/setup", json={"code": code, "password": "attacker password"})
    assert again.status_code == 409
    assert client(panel).post("/api/auth/login", json={"password": "my new password"}).status_code == 200


def test_setup_code_guessing_is_rate_limited(fresh_panel):
    panel, code = fresh_panel
    c = client(panel)
    for _ in range(5):
        assert c.post("/api/auth/setup", json={"code": "BBBB-BBBB", "password": "my new password"}).status_code == 401
    blocked = c.post("/api/auth/setup", json={"code": code, "password": "my new password"})
    assert blocked.status_code == 429 and not panel.passwords.is_set()


def test_setup_is_local_network_only(fresh_panel):
    panel, code = fresh_panel
    response = client(panel, "8.8.8.8").post("/api/auth/setup", json={"code": code, "password": "my new password"})
    assert response.status_code == 403 and not panel.passwords.is_set()


def test_reset_signs_everybody_out(panel):
    c = client(panel)
    assert c.post("/api/auth/login", json={"password": "correct horse battery"}).status_code == 200
    assert c.get("/api/auth/session").json()["authenticated"] is True
    # Reset at the server: chameleon-panel reset-password.
    panel.passwords.delete()
    code = panel.setup_codes.create()
    assert c.get("/api/stealth/status").status_code == 401
    assert c.get("/api/auth/session").json() == {"authenticated": False, "password_set": False, "same_machine": False}
    assert c.post("/api/auth/setup", json={"code": code, "password": "brand new password"}).status_code == 200
    # A session from the old password does not come back with the new one.
    old = client(panel)
    assert old.post("/api/auth/login", json={"password": "correct horse battery"}).status_code == 401


def test_setup_code_file_holds_no_code(fresh_panel, tmp_path):
    panel, code = fresh_panel
    text = (tmp_path / "data" / "setup_code.json").read_text()
    assert code.replace("-", "") not in text


def test_same_computer_creates_the_password_without_a_code(fresh_panel):
    panel, _code = fresh_panel
    here = client(panel, "127.0.0.1")
    assert here.get("/api/auth/session").json() == {
        "authenticated": False, "password_set": False, "same_machine": True}
    ok = here.post("/api/auth/setup", json={"password": "my new password"})
    assert ok.status_code == 200 and panel.passwords.is_set()
    # The pending code for other devices is gone with it.
    assert client(panel).post("/api/auth/setup", json={"code": _code, "password": "x" * 12}).status_code == 409


def test_another_device_still_needs_the_code(fresh_panel):
    panel, _code = fresh_panel
    lan = client(panel, "192.168.1.20")
    assert lan.get("/api/auth/session").json()["same_machine"] is False
    assert lan.post("/api/auth/setup", json={"password": "my new password"}).status_code == 401
    assert not panel.passwords.is_set()


def test_reset_only_from_the_same_computer(panel):
    lan = client(panel, "192.168.1.20")
    assert lan.post("/api/auth/reset", json={}).status_code == 403
    assert panel.passwords.is_set()
    here = client(panel, "127.0.0.1")
    # A page on another site cannot trigger it from the owner's browser.
    assert here.post("/api/auth/reset", json={}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert here.post("/api/auth/reset", data="x", headers={"Content-Type": "text/plain"}).status_code == 403
    assert panel.passwords.is_set()
    signed_in = client(panel, "192.168.1.30")
    assert signed_in.post("/api/auth/login", json={"password": "correct horse battery"}).status_code == 200
    assert here.post("/api/auth/reset", json={}).status_code == 200
    assert not panel.passwords.is_set()
    assert signed_in.get("/api/stealth/status").status_code == 401
    assert here.post("/api/auth/setup", json={"password": "another new password"}).status_code == 200


def test_cross_site_forms_cannot_sign_in(panel):
    c = client(panel)
    form = c.post("/api/auth/login", data={"password": "correct horse battery"})
    assert form.status_code in (403, 422)
    assert "set-cookie" not in form.headers
