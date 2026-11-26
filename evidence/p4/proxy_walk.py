"""J1 behind a proxy (check-7 S2), walked with the real `sshbite serve` and a TLS reverse proxy.

    .venv/bin/python evidence/p4/proxy_walk.py DB_TO_COPY SCREENSHOT_DIR

The proxy stands in for the nginx example of docs/operations.md (no nginx in this workspace): it terminates TLS
with a self-signed certificate and forwards to SSHBITE on 127.0.0.1 with `X-Forwarded-For: <remote address>`
(replacing anything the client sent) and `X-Forwarded-Proto: https`. Clients use different loopback source
addresses (127.0.0.2, 127.0.0.3) so the proxy sees two clients.
"""

from __future__ import annotations

import http.client
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sshbite import db as dbm  # noqa: E402
from sshbite.users import add_user  # noqa: E402

PW = "correct horse battery"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def make_proxy(upstream_port: int, cert: str, key: str) -> tuple[http.server.ThreadingHTTPServer, int]:
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _fwd(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else None
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "x-forwarded-for", "x-forwarded-proto", "connection")}
            headers["Host"] = self.headers.get("Host", "")
            headers["X-Forwarded-For"] = self.client_address[0]          # proxy_set_header ... $remote_addr
            headers["X-Forwarded-Proto"] = "https"
            c = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=30)
            c.request(self.command, self.path, body=body, headers=headers)
            r = c.getresponse()
            data = r.read()
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.end_headers()
            self.wfile.write(data)
            c.close()

        do_GET = do_POST = do_PUT = do_DELETE = _fwd

    port = free_port()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def client(port: int, source: str):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return http.client.HTTPSConnection("127.0.0.1", port, context=ctx, source_address=(source, 0), timeout=30)


def login(port: int, source: str, user: str, pw: str, spoof: str | None = None):
    c = client(port, source)
    h = {"Content-Type": "application/json"}
    if spoof:
        h["X-Forwarded-For"] = spoof
    c.request("POST", "/api/login", body=json.dumps({"username": user, "password": pw}), headers=h)
    r = c.getresponse()
    r.read()
    return r.status, r.getheader("Set-Cookie")


def start_serve(tmp: Path, db: str, web: dict, name: str):
    port = free_port()
    cfg = tmp / f"{name}.yaml"
    cfg.write_text(json.dumps({"database": db, "entry": {"host": "jump"}, "web": {"port": port, **web}}))
    cfg.chmod(0o600)
    log = open(tmp / f"{name}.log", "w")
    p = subprocess.Popen([str(ROOT / ".venv/bin/sshbite"), "-c", str(cfg), "serve"], stderr=log, stdout=log)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    return p, port, cfg


def main():
    src, shots = sys.argv[1], Path(sys.argv[2])
    tmp = Path(tempfile.mkdtemp())
    db = str(tmp / "sshbite.db")
    shutil.copy(src, db)
    os.chmod(db, 0o600)
    c = dbm.connect(db)
    c.execute("DELETE FROM app_user")
    add_user(c, "admin", PW)
    c.close()
    cert, key = str(tmp / "cert.pem"), str(tmp / "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-days", "1", "-subj", "/CN=sshbite.test", "-keyout", key, "-out", cert],
                   check=True, capture_output=True)

    print("== 1. SSHBITE behind the TLS proxy, configured as in docs/operations.md")
    web = {"bind": "127.0.0.1", "secure_cookie": True, "trusted_proxies": ["127.0.0.1"]}
    serve, sport, cfg = start_serve(tmp, db, web, "with-proxy-settings")
    print("config web:", json.loads(cfg.read_text())["web"])
    print("serve log:", (tmp / "with-proxy-settings.log").read_text().strip())
    proxy, pport = make_proxy(sport, cert, key)
    print(f"proxy: https://127.0.0.1:{pport}/ -> http://127.0.0.1:{sport}/")

    status, cookie = login(pport, "127.0.0.2", "admin", PW)
    print(f"\nlogin through the proxy: HTTP {status}\nSet-Cookie: {cookie}")
    assert status == 204 and "; secure" in cookie.lower()

    print("\n== 2. per-IP limit counts the real client (X-Forwarded-For set by the proxy)")
    codes = [login(pport, "127.0.0.2", "nobody", "wrong password!", spoof=f"9.9.9.{i}")[0] for i in range(20)]
    print("client 127.0.0.2, 20 wrong logins (each with a spoofed X-Forwarded-For 9.9.9.N):", codes)
    s21 = login(pport, "127.0.0.2", "admin", PW)[0]
    print("client 127.0.0.2, 21st attempt with the right password:", s21)
    other = login(pport, "127.0.0.3", "admin", PW)[0]
    print("client 127.0.0.3 (another user behind the same proxy), right password:", other)
    assert codes == [401] * 20 and s21 == 429 and other == 204

    print("\n== 3. browser through the proxy (Chromium)")
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        b = pw.chromium.launch(args=["--no-sandbox"])
        ctx = b.new_context(viewport={"width": 1440, "height": 900}, ignore_https_errors=True)
        pg = ctx.new_page()
        base = f"https://127.0.0.1:{pport}"
        pg.goto(base + "/login")
        pg.fill("input[name=username]", "admin")
        pg.fill("input[name=password]", PW)
        pg.click("button[type=submit]")
        pg.wait_for_url(lambda u: "/login" not in u)
        pg.wait_for_selector("[data-stat]")
        ck = [x for x in ctx.cookies() if x["name"] == "sshbite_session"][0]
        print("browser cookie sshbite_session:", {k: ck[k] for k in ("secure", "httpOnly", "sameSite", "path")})
        assert ck["secure"] and ck["httpOnly"]
        pg.screenshot(path=str(shots / "c7-j1-proxy-dashboard-over-https.png"))
        print("screenshot c7-j1-proxy-dashboard-over-https.png")
        b.close()
    proxy.shutdown()
    serve.terminate()

    print("\n== 4. for contrast: the same proxy without trusted_proxies")
    serve, sport, _ = start_serve(tmp, db, {"bind": "127.0.0.1", "secure_cookie": True}, "without-trusted")
    proxy, pport = make_proxy(sport, cert, key)
    codes = [login(pport, "127.0.0.2", "nobody", "wrong password!")[0] for i in range(20)]
    other = login(pport, "127.0.0.3", "admin", PW)[0]
    print("client 127.0.0.2: 20 wrong logins; then client 127.0.0.3 with the right password:", other,
          "(every client shares the proxy's address)")
    assert other == 429
    proxy.shutdown()
    serve.terminate()

    print("\n== 5. bind rules of `sshbite serve` (in the container: SSHBITE_IN_CONTAINER=1)")
    plain = tmp / "plain.yaml"
    plain.write_text(json.dumps({"database": db, "entry": {"host": "jump"}, "web": {"port": free_port()}}))
    plain.chmod(0o600)
    behind = tmp / "behind-proxy.yaml"
    behind.write_text(json.dumps({"database": db, "entry": {"host": "jump"},
                                  "web": {"port": free_port(), "secure_cookie": True}}))
    behind.chmod(0o600)
    env = {**os.environ, "SSHBITE_IN_CONTAINER": "1"}
    for cfgf, args, what in ((plain, [], "default bind, no TLS"),
                             (plain, ["--bind", "0.0.0.0"], "explicit --bind, no TLS, no secure_cookie"),
                             (behind, ["--bind", "0.0.0.0"], "explicit --bind with web.secure_cookie: true"),
                             (plain, ["--bind", "0.0.0.0", "--insecure-bind"], "explicit --bind with --insecure-bind")):
        p = subprocess.Popen([str(ROOT / ".venv/bin/sshbite"), "-c", str(cfgf), "serve", *args],
                             stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True, env=env)
        try:
            rc = p.wait(4)
            state = f"exit {rc}"
        except subprocess.TimeoutExpired:
            p.terminate()
            p.wait(5)
            state = "serving (stopped after 4 s)"
        err = " | ".join(line for line in p.stderr.read().strip().splitlines() if line)
        print(f"$ sshbite serve {' '.join(args)}   ({what})\n  -> {state}: {err}")
    print("\nall checks passed")


if __name__ == "__main__":
    main()
