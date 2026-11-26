"""`sshbite serve` (spec 3.2, 8.1): the web UI and API.

Bind rules:
- default web.bind / web.port from the config (127.0.0.1:8722);
- a non-loopback address needs --tls-cert and --tls-key;
- exception: with SSHBITE_IN_CONTAINER=1 (set in the image) the server binds 0.0.0.0 without TLS, and the
  compose file publishes the port on 127.0.0.1 only.
"""

from __future__ import annotations

import ipaddress
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


def resolve_bind(bind: str | None, cfg_bind: str, tls_cert: str | None, tls_key: str | None,
                 in_container: bool) -> tuple[str, bool]:
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
    if not is_loopback(addr) and not tls and not in_container:
        raise ConfigError(f"refusing to bind {addr} without TLS: a non-loopback address needs --tls-cert and "
                          "--tls-key (the audit data is sensitive)")
    return addr, tls


@click.command("serve")
@click.option("--bind", help="Address to listen on (default web.bind, 127.0.0.1)")
@click.option("--port", type=click.IntRange(1, 65535), help="Port (default web.port, 8722)")
@click.option("--tls-cert", type=click.Path(dir_okay=False), help="PEM certificate; required for a non-loopback bind")
@click.option("--tls-key", type=click.Path(dir_okay=False), help="PEM private key")
@click.pass_context
def serve(ctx: click.Context, bind: str | None, port: int | None, tls_cert: str | None, tls_key: str | None) -> None:
    """Serve the web UI and API (login required; read-only views plus key labels)."""
    import uvicorn

    from ..config import load_config
    from .app import create_app

    cfg = load_config(ctx.obj["config_path"])
    in_container = os.environ.get("SSHBITE_IN_CONTAINER") == "1"
    addr, tls = resolve_bind(bind, cfg.web.bind, tls_cert, tls_key, in_container)
    port = port or cfg.web.port
    app = create_app(cfg.database, session_hours=cfg.web.session_hours, tls=tls)
    scheme = "https" if tls else "http"
    shown = f"[{addr}]" if ":" in addr else addr
    click.echo(f"SSHBITE UI on {scheme}://{shown}:{port}/  (database {cfg.database})", err=True)
    if not __import__("sqlite3").connect(cfg.database).execute("SELECT count(*) FROM app_user").fetchone()[0]:
        click.echo("no UI user yet - create one with `sshbite user add NAME`", err=True)
    uvicorn.run(app, host=addr, port=port, ssl_certfile=tls_cert, ssl_keyfile=tls_key, log_level="warning",
                access_log=False, proxy_headers=False, server_header=False)
