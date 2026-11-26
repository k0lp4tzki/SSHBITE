"""Fixes of the security check (check-7): Secure cookie behind a proxy, trusted proxies for the per-IP limit,
bind refusal, and the 64 KiB limit on /api request bodies."""

from __future__ import annotations

import logging
import socket

import pytest
from click.testing import CliRunner

from sshbite.config import parse_config_text
from sshbite.errors import ConfigError
from sshbite.web.cli import resolve_bind

from .conftest import LAB_DB, PASSWORD, Client


def _cookie_header(r) -> str:
    return r.headers.get_all("set-cookie")[0].lower()


# ---------------------------------------------------------------- S2: web.secure_cookie

def test_secure_cookie_set_by_config(make_server):
    with make_server(LAB_DB, secure_cookie=True) as s:
        c = Client(s.base)
        r = c.req("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        assert r.status == 204
        raw = _cookie_header(r)
        assert "; secure" in raw and "httponly" in raw and "samesite=strict" in raw
        # HSTS belongs to a server that speaks TLS itself; behind a proxy the proxy sends it
        assert r.headers.get("strict-transport-security") is None


def test_cookie_not_secure_by_default(make_server):
    with make_server(LAB_DB) as s:
        r = Client(s.base).req("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        assert r.status == 204 and "secure" not in _cookie_header(r)


def test_secure_cookie_always_with_tls(make_server):
    with make_server(LAB_DB, tls=True, secure_cookie=False) as s:
        r = Client(s.base).req("POST", "/api/login", {"username": "admin", "password": PASSWORD})
        assert "; secure" in _cookie_header(r)


def test_web_config_keys():
    base = "entry: {host: jump}\n"
    cfg = parse_config_text(base)
    assert cfg.web.secure_cookie is False and cfg.web.trusted_proxies == []
    cfg = parse_config_text(base + "web: {secure_cookie: true, trusted_proxies: [10.0.0.5, '192.168.0.0/24']}\n")
    assert cfg.web.secure_cookie is True and cfg.web.trusted_proxies == ["10.0.0.5", "192.168.0.0/24"]
    with pytest.raises(ConfigError, match="trusted_proxies"):
        parse_config_text(base + "web: {trusted_proxies: [proxy.example]}\n")


# ---------------------------------------------------------------- S2: web.trusted_proxies

def _fail(c: Client, xff: str | None) -> int:
    h = {"X-Forwarded-For": xff} if xff else {}
    return c.req("POST", "/api/login", {"username": "nobody", "password": "wrong password!"}, headers=h).status


def test_forwarded_for_ignored_without_trusted_proxy(make_server):
    with make_server(LAB_DB) as s:
        c = Client(s.base)
        codes = [_fail(c, f"9.9.9.{i}") for i in range(21)]
        # a spoofed header does not escape the per-IP limit: all 21 count against the peer 127.0.0.1
        assert codes[:20] == [401] * 20 and codes[20] == 429


def test_forwarded_for_last_hop_from_trusted_proxy(make_server):
    with make_server(LAB_DB, trusted_proxies=["127.0.0.1/32"]) as s:
        c = Client(s.base)
        # the proxy appends the address it saw; anything before it is client-supplied and ignored
        codes = [_fail(c, f"6.6.6.{i}, 203.0.113.7") for i in range(20)]
        assert codes == [401] * 20
        assert _fail(c, "203.0.113.7") == 429          # the real client is limited ...
        assert _fail(c, "203.0.113.8") == 401          # ... another client behind the same proxy is not
        assert Client(s.base).login().status == 204    # nor is a login without the header (peer address)


def test_forwarded_for_from_untrusted_peer_is_ignored(make_server):
    with make_server(LAB_DB, trusted_proxies=["10.0.0.0/8"]) as s:   # the test client is 127.0.0.1
        c = Client(s.base)
        codes = [_fail(c, f"203.0.113.{i}") for i in range(21)]
        assert codes[20] == 429


# ---------------------------------------------------------------- S2: bind rules

def test_bind_refused_in_container_for_explicit_address():
    # the container exception covers only the default bind ...
    assert resolve_bind(None, "127.0.0.1", None, None, True) == ("0.0.0.0", False)
    # ... an explicit non-loopback --bind without TLS is refused there too
    with pytest.raises(ConfigError, match="without TLS"):
        resolve_bind("0.0.0.0", "127.0.0.1", None, None, True)
    with pytest.raises(ConfigError, match="secure_cookie"):
        resolve_bind("10.1.2.3", "127.0.0.1", None, None, True)
    # loopback is always fine
    assert resolve_bind("127.0.0.1", "127.0.0.1", None, None, True) == ("127.0.0.1", False)


def test_bind_allowed_with_secure_cookie_or_insecure_flag():
    assert resolve_bind("0.0.0.0", "127.0.0.1", None, None, True, secure_cookie=True) == ("0.0.0.0", False)
    assert resolve_bind("0.0.0.0", "127.0.0.1", None, None, True, insecure_bind=True) == ("0.0.0.0", False)
    assert resolve_bind("10.1.2.3", "127.0.0.1", None, None, False, secure_cookie=True) == ("10.1.2.3", False)


def test_serve_refuses_explicit_bind_in_container(tmp_path, monkeypatch):
    from sshbite.cli import main

    cfgp = tmp_path / "c.yaml"
    cfgp.write_text(f"database: {tmp_path / 's.db'}\nentry: {{host: jump}}\n")
    monkeypatch.setenv("SSHBITE_IN_CONTAINER", "1")
    r = CliRunner().invoke(main, ["-c", str(cfgp), "serve", "--bind", "0.0.0.0"])
    assert r.exit_code == 2 and "refusing to bind 0.0.0.0 without TLS" in r.output


def test_insecure_bind_logs_a_warning(tmp_path, monkeypatch, caplog):
    import uvicorn

    from sshbite.cli import main

    cfgp = tmp_path / "c.yaml"
    cfgp.write_text(f"database: {tmp_path / 's.db'}\nentry: {{host: jump}}\n")
    monkeypatch.setenv("SSHBITE_IN_CONTAINER", "1")
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw, app=app))
    caplog.set_level(logging.WARNING)
    r = CliRunner().invoke(main, ["-c", str(cfgp), "serve", "--bind", "0.0.0.0", "--insecure-bind"])
    assert r.exit_code == 0, r.output
    assert seen["host"] == "0.0.0.0"
    assert "--insecure-bind: serving 0.0.0.0 over plain HTTP" in caplog.text
    assert seen["app"].state.secure_cookie is False


def test_serve_passes_secure_cookie_and_proxies(tmp_path, monkeypatch):
    import uvicorn

    from sshbite.cli import main

    cfgp = tmp_path / "c.yaml"
    cfgp.write_text(f"database: {tmp_path / 's.db'}\nentry: {{host: jump}}\n"
                    "web: {secure_cookie: true, trusted_proxies: [172.20.0.2]}\n")
    monkeypatch.setenv("SSHBITE_IN_CONTAINER", "1")
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw, app=app))
    r = CliRunner().invoke(main, ["-c", str(cfgp), "serve", "--bind", "0.0.0.0"])
    assert r.exit_code == 0, r.output
    st = seen["app"].state
    assert st.secure_cookie is True and [str(n) for n in st.trusted_proxies] == ["172.20.0.2/32"]
    assert seen["proxy_headers"] is False   # uvicorn's own header handling stays off; client_ip() decides


# ---------------------------------------------------------------- S8: request size

def _raw(port: int, req: bytes) -> bytes:
    c = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        c.sendall(req)
    except OSError:
        pass
    data = c.recv(4096)
    c.close()
    return data


def test_api_body_over_64k_gets_413(lab_server):
    c = Client(lab_server.base)
    big = {"username": "admin", "password": "x" * (64 * 1024)}
    r = c.req("POST", "/api/login", big)
    assert r.status == 413 and r.json()["error"]["code"] == "too_large"
    assert r.headers.get("content-security-policy")
    # just under the limit is processed normally
    ok = {"username": "admin", "password": "x" * (60 * 1024)}
    assert c.req("POST", "/api/login", ok).status == 401


def test_api_chunked_body_over_64k_gets_413(lab_server):
    body = b"x" * 70000
    req = (b"POST /api/login HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n"
           b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
    for i in range(0, len(body), 8192):
        ch = body[i:i + 8192]
        req += f"{len(ch):x}\r\n".encode() + ch + b"\r\n"
    req += b"0\r\n\r\n"
    assert _raw(lab_server.port, req).startswith(b"HTTP/1.1 413")


def test_small_chunked_body_still_works(lab_server):
    body = b'{"username":"admin","password":"' + PASSWORD.encode() + b'"}'
    req = (b"POST /api/login HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n"
           b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
           + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
    assert _raw(lab_server.port, req).startswith(b"HTTP/1.1 204")
