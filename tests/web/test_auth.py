"""Spec 8.1 for the web process: login, lockout, rate limit, sessions, CSRF, headers, bind rules."""

from __future__ import annotations

import sqlite3

import pytest

from sshbite.errors import ConfigError
from sshbite.web.cli import is_loopback, resolve_bind

from .conftest import LAB_DB, PASSWORD, Client


def test_login_logout_and_session(lab_server):
    c = Client(lab_server.base)
    assert c.get("/api/session").status == 401
    assert c.get("/api/session").json()["error"]["code"] == "unauthenticated"
    r = c.login()
    assert r.status == 204
    ck = c.cookie("sshbite_session")
    assert ck is not None and ck.has_nonstandard_attr("HttpOnly")
    raw = r.headers.get_all("set-cookie")[0].lower()
    assert "httponly" in raw and "samesite=strict" in raw and "secure" not in raw and "max-age=28800" in raw
    s = c.get("/api/session").json()
    assert s["username"] == "admin" and len(s["csrf_token"]) >= 32
    # only the SHA-256 of the token is stored
    conn = sqlite3.connect(lab_server.db_path)
    stored = [r[0] for r in conn.execute("SELECT token_sha256 FROM session")]
    assert ck.value not in stored and len(stored[0]) == 64
    assert c.req("POST", "/api/logout").status == 204
    assert c.get("/api/scans").status == 401


def test_logout_needs_csrf(lab):
    assert lab.req("POST", "/api/logout", csrf=False).status == 403
    assert lab.get("/api/scans").status == 200


def test_wrong_password_and_unknown_user_look_the_same(lab_server):
    c = Client(lab_server.base)
    a = c.req("POST", "/api/login", {"username": "admin", "password": "nope"})
    b = c.req("POST", "/api/login", {"username": "nobody", "password": "nope"})
    assert a.status == b.status == 401
    assert a.json() == b.json()
    assert a.json()["error"]["code"] == "bad_credentials"


def test_user_lockout_after_five_failures(lab_server):
    c = Client(lab_server.base)
    for i in range(5):
        r = c.req("POST", "/api/login", {"username": "admin", "password": f"wrong{i}"})
        assert r.json()["error"]["code"] == "bad_credentials", i
    r = c.req("POST", "/api/login", {"username": "admin", "password": "wrong-6"})   # the 6th attempt
    assert r.status == 401
    e = r.json()["error"]
    assert e["code"] == "account_locked" and e["locked_until"].endswith("Z")
    # locked even with the right password
    r = c.req("POST", "/api/login", {"username": "admin", "password": PASSWORD})
    assert r.json()["error"]["code"] == "account_locked"
    row = sqlite3.connect(lab_server.db_path).execute("SELECT locked_until FROM app_user WHERE username='admin'").fetchone()
    assert row[0] == e["locked_until"]


def test_unknown_user_also_locks(lab_server):
    c = Client(lab_server.base)
    for i in range(5):
        c.req("POST", "/api/login", {"username": "ghost", "password": f"x{i}"})
    assert c.req("POST", "/api/login", {"username": "ghost", "password": "x"}).json()["error"]["code"] == "account_locked"


def test_lock_expires(make_server):
    from sshbite.web.auth import Guard

    now = [1_800_000_000.0]
    guard = Guard(clock=lambda: now[0])
    with make_server(LAB_DB, guard=guard) as s:
        c = Client(s.base)
        for i in range(5):
            c.req("POST", "/api/login", {"username": "admin", "password": f"w{i}"})
        # lock is stored with real wall-clock time; move it into the past
        conn = sqlite3.connect(s.db_path)
        conn.execute("UPDATE app_user SET locked_until='2000-01-01T00:00:00Z'")
        conn.commit()
        assert c.login().status == 204


def test_ip_rate_limit_429(lab_server):
    c = Client(lab_server.base)
    for i in range(20):
        c.req("POST", "/api/login", {"username": f"u{i}", "password": "x"})
    r = c.req("POST", "/api/login", {"username": "admin", "password": PASSWORD})
    assert r.status == 429 and r.json()["error"]["code"] == "rate_limited"


def test_csrf_on_put(lab):
    fp = "SHA256:yIQEm8CgzGzq9JAgp3eHPpdLrgGTK2EqO84qzNP9gOM"
    url = "/api/keys/" + fp.replace("+", "-").replace("/", "_") + "/label"
    r = lab.req("PUT", url, {"label": "x"}, csrf=False)
    assert r.status == 403 and r.json()["error"]["code"] == "csrf"
    r = lab.req("PUT", url, {"label": "x"}, headers={"X-CSRF-Token": "wrong"}, csrf=False)
    assert r.status == 403
    assert lab.req("PUT", url, {"label": "x"}).status == 200


def test_security_headers_everywhere(lab):
    for path in ("/", "/api/scans", "/api/nope", "/login"):
        r = lab.get(path)
        h = r.headers
        assert h["Content-Security-Policy"] == ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                                "script-src 'self'; frame-ancestors 'none'"), path
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["Referrer-Policy"] == "no-referrer"
    assert lab.get("/api/scans").headers["Cache-Control"] == "no-store"


def test_error_shape_and_404(lab):
    r = lab.get("/api/scans/999")
    assert r.status == 404 and set(r.json()["error"]) >= {"code", "message"}
    r = lab.get("/api/scans/1/hosts?page_size=5000")
    assert r.status == 400 and r.json()["error"]["code"] == "bad_request"
    assert lab.get("/api/nothing/here").json()["error"]["code"] == "not_found"


def test_spa_fallback_and_static(lab_server):
    from sshbite.web.app import static_dir

    c = Client(lab_server.base)
    if not (static_dir() / "index.html").is_file():
        pytest.skip("frontend not built")
    r = c.get("/s/1/heatmap")
    assert r.status == 200 and "<div id=\"app\">" in r.text
    # no inline script, no external URL in the shell
    assert "<script>" not in r.text and "http://" not in r.text and "https://" not in r.text
    assert c.get("/assets/does-not-exist.js").status == 404
    assert c.get("/../../etc/passwd").status in (200, 404)  # resolved inside static/ or not found, never outside


def test_bind_rules(tmp_path):
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("10.1.2.3")
    assert resolve_bind(None, "127.0.0.1", None, None, False) == ("127.0.0.1", False)
    with pytest.raises(ConfigError, match="without TLS"):
        resolve_bind("0.0.0.0", "127.0.0.1", None, None, False)
    with pytest.raises(ConfigError, match="without TLS"):
        resolve_bind(None, "192.168.1.5", None, None, False)
    with pytest.raises(ConfigError, match="together"):
        resolve_bind("0.0.0.0", "127.0.0.1", "c.pem", None, False)
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    cert.write_text("x")
    key.write_text("x")
    assert resolve_bind("0.0.0.0", "127.0.0.1", str(cert), str(key), False) == ("0.0.0.0", True)
    # the container exception
    assert resolve_bind(None, "127.0.0.1", None, None, True) == ("0.0.0.0", False)


def test_secure_cookie_under_tls(make_server):
    with make_server(LAB_DB, tls=True) as s:   # TLS itself is terminated by uvicorn; the flag drives the cookie
        c = Client(s.base)
        r = c.req("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        assert "secure" in r.headers.get_all("set-cookie")[0].lower()
        assert "Strict-Transport-Security" in r.headers


def test_serve_refuses_public_bind_without_tls(tmp_path):
    import subprocess
    import sys

    from tests.e2e.lab import KEYS  # noqa: F401  (only to locate the repo)
    cfg = tmp_path / "c.yaml"
    pin = (KEYS / "jump_host_ed25519.pub").read_text().split()[:2]
    cfg.write_text(f"database: {tmp_path}/d.db\nentry: {{host: x, host_keys: [\"{pin[0]} {pin[1]}\"]}}\n")
    cfg.chmod(0o600)
    r = subprocess.run([sys.executable, "-m", "sshbite.cli", "-c", str(cfg), "serve", "--bind", "0.0.0.0"],
                       capture_output=True, text=True, timeout=60, env={"PATH": "/usr/bin:/bin"})
    assert r.returncode == 2 and "without TLS" in r.stderr
