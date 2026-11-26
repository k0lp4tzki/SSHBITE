"""Fixtures for the web API tests: a real uvicorn server on a free port, over a copy of a database."""

from __future__ import annotations

import http.cookiejar
import json
import shutil
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import uvicorn

from sshbite import db as dbm
from sshbite.users import add_user
from sshbite.web.app import create_app
from sshbite.web.auth import Guard

FIX = Path(__file__).resolve().parents[1] / "fixtures"
LAB_DB = FIX / "lab_scans.db"   # scans 1-3 of a real P1 lab run against real sshd (spec 9.3)
PASSWORD = "correct horse battery"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Server:
    def __init__(self, db_path: str, tls: bool = False, guard: Guard | None = None, **app_kw):
        self.db_path = db_path
        self.app = create_app(db_path, session_hours=8, tls=tls, guard=guard, **app_kw)
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        cfg = uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error", access_log=False,
                             proxy_headers=False)   # as `sshbite serve`: client_ip() alone reads X-Forwarded-For
        self.server = uvicorn.Server(cfg)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                break
            time.sleep(0.02)
        return self

    def __exit__(self, *a):
        self.server.should_exit = True
        self.thread.join(5)


class Resp:
    def __init__(self, status: int, headers, body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body)

    @property
    def text(self) -> str:
        return self.body.decode()


class Client:
    def __init__(self, base: str):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""

    def req(self, method: str, path: str, body=None, csrf: bool = True, headers: dict | None = None) -> Resp:
        data = json.dumps(body).encode() if body is not None else None
        h = {"Accept": "application/json", **(headers or {})}
        if data is not None:
            h["Content-Type"] = "application/json"
        if csrf and self.csrf and method != "GET":
            h["X-CSRF-Token"] = self.csrf
        r = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with self.opener.open(r, timeout=30) as resp:
                return Resp(resp.status, resp.headers, resp.read())
        except urllib.error.HTTPError as e:
            return Resp(e.code, e.headers, e.read())

    def get(self, path: str) -> Resp:
        return self.req("GET", path)

    def login(self, user: str = "admin", password: str = PASSWORD) -> Resp:
        r = self.req("POST", "/api/login", {"username": user, "password": password})
        if r.status == 204:
            self.csrf = self.get("/api/session").json()["csrf_token"]
        return r

    def cookie(self, name: str):
        return next((c for c in self.jar if c.name == name), None)


def _prepare(tmp_path: Path, src: Path | None) -> str:
    dst = tmp_path / "sshbite.db"
    if src is not None:
        shutil.copy(src, dst)
        dst.chmod(0o600)
    conn = dbm.connect(str(dst))
    add_user(conn, "admin", PASSWORD)
    conn.close()
    return str(dst)


@pytest.fixture
def lab_server(tmp_path):
    with Server(_prepare(tmp_path, LAB_DB)) as s:
        yield s


@pytest.fixture
def lab(lab_server) -> Client:
    c = Client(lab_server.base)
    assert c.login().status == 204
    return c


@pytest.fixture
def make_server(tmp_path):
    def make(src: Path | None = None, **kw) -> Server:
        return Server(_prepare(tmp_path, src), **kw)
    return make
