"""`sshbite serve` (spec 3.2, 8.1): the web UI and API.

Bind rules:
- default web.bind / web.port from the config (127.0.0.1:8722);
- a non-loopback address needs --tls-cert and --tls-key;
- exception: with SSHBITE_IN_CONTAINER=1 (set in the image) and no --bind, the server binds 0.0.0.0 without
  TLS, and the compose file publishes the port on 127.0.0.1 only. An explicit --bind gets no such exception;
- without TLS of its own, a non-loopback address is allowed only with web.secure_cookie (TLS ends at a reverse
  proxy) or with --insecure-bind (logs a warning).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket

import click

from ..errors import ConfigError


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_loopback for i in infos)


INSECURE_BIND_WARNING = ("--insecure-bind: serving {addr} over plain HTTP without a Secure cookie - "
                         "passwords and session cookies cross the network in clear text")


def resolve_bind(bind: str | None, cfg_bind: str, tls_cert: str | None, tls_key: str | None,
                 in_container: bool, secure_cookie: bool = False, insecure_bind: bool = False) -> tuple[str, bool]:
    """Return (address, tls). Raises ConfigError when a rule of spec 8.1 is broken."""
    if bool(tls_cert) != bool(tls_key):
        raise ConfigError("--tls-cert and --tls-key must be given together")
    tls = bool(tls_cert)
    for f in (tls_cert, tls_key):
        if f and not os.path.isfile(f):
            raise ConfigError(f"TLS file {f} does not exist")
    if in_container and bind is None:
        return "0.0.0.0", tls
    addr = bind or cfg_bind
    if not is_loopback(addr) and not tls and not secure_cookie and not insecure_bind:
        raise ConfigError(f"refusing to bind {addr} without TLS: a non-loopback address needs --tls-cert and "
                          "--tls-key, or TLS at a reverse proxy with web.secure_cookie: true (docs/operations.md), "
                          "or --insecure-bind (the audit data is sensitive)")
    return addr, tls


@click.command("serve")
@click.option("--bind", help="Address to listen on (default web.bind, 127.0.0.1)")
@click.option("--port", type=click.IntRange(1, 65535), help="Port (default web.port, 8722)")
@click.option("--tls-cert", type=click.Path(dir_okay=False), help="PEM certificate; required for a non-loopback bind")
@click.option("--tls-key", type=click.Path(dir_okay=False), help="PEM private key")
@click.option("--insecure-bind", is_flag=True,
              help="Allow a non-loopback --bind without TLS and without web.secure_cookie (logs a warning)")
@click.pass_context
def serve(ctx: click.Context, bind: str | None, port: int | None, tls_cert: str | None, tls_key: str | None,
          insecure_bind: bool) -> None:
    """Serve the web UI and API (login required; read-only views plus key labels)."""
    import uvicorn

    from ..config import load_config
    from .app import create_app

    cfg = load_config(ctx.obj["config_path"])
    in_container = os.environ.get("SSHBITE_IN_CONTAINER") == "1"
    addr, tls = resolve_bind(bind, cfg.web.bind, tls_cert, tls_key, in_container,
                             secure_cookie=cfg.web.secure_cookie, insecure_bind=insecure_bind)
    if insecure_bind and not is_loopback(addr) and not tls and not cfg.web.secure_cookie:
        logging.getLogger("sshbite.web").warning(INSECURE_BIND_WARNING.format(addr=addr))
    port = port or cfg.web.port
    app = create_app(cfg.database, session_hours=cfg.web.session_hours, tls=tls,
                     secure_cookie=cfg.web.secure_cookie, trusted_proxies=cfg.web.trusted_proxies)
    scheme = "https" if tls else "http"
    shown = f"[{addr}]" if ":" in addr else addr
    click.echo(f"SSHBITE UI on {scheme}://{shown}:{port}/  (database {cfg.database})", err=True)
    if not __import__("sqlite3").connect(cfg.database).execute("SELECT count(*) FROM app_user").fetchone()[0]:
        click.echo("no UI user yet - create one with `sshbite user add NAME`", err=True)
    uvicorn.run(app, host=addr, port=port, ssl_certfile=tls_cert, ssl_keyfile=tls_key, log_level="warning",
                access_log=False, proxy_headers=False, server_header=False)
