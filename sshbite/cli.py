"""Command line interface (spec 3.2). Exit codes: 0 ok, 2 config, 3 entry failure, 4 internal, 5 locked."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time

import click

from . import __version__
from .config import EXAMPLE_CONFIG, Config, check_files, load_config, resolve_config_path
from .errors import ConfigError, EntryError, ScanLocked, SshbiteError
from .privilege import RedactingFilter, SudoSecret

log = logging.getLogger("sshbite")
_SECRET = SudoSecret()


def _setup_logging(verbose: int) -> None:
    level = logging.WARNING if verbose == 0 else logging.INFO if verbose == 1 else logging.DEBUG
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter(_SECRET))
    handler.set_name("sshbite")
    root = logging.getLogger()
    root.handlers[:] = [h for h in root.handlers if h.get_name() != "sshbite"] + [handler]
    root.setLevel(level)
    # asyncssh logs connection details at INFO; keep it quiet unless -vv
    logging.getLogger("asyncssh").setLevel(logging.WARNING if verbose < 2 else logging.DEBUG)


class _Group(click.Group):
    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except SshbiteError as exc:
            click.echo(_SECRET.redact(f"error: {exc}"), err=True)
            ctx.exit(exc.exit_code)
        except (click.exceptions.Exit, click.exceptions.Abort, click.ClickException, SystemExit):
            raise
        except KeyboardInterrupt:
            click.echo("interrupted", err=True)
            ctx.exit(4)
        except Exception as exc:  # internal error: exit 4, never print secrets
            log.debug("internal error", exc_info=True)
            click.echo(_SECRET.redact(f"internal error: {exc.__class__.__name__}: {exc}"), err=True)
            ctx.exit(4)


@click.group(cls=_Group)
@click.option("-c", "--config", "config_path", metavar="PATH", help="Config file (else $SSHBITE_CONFIG, else /etc/sshbite/sshbite.yaml)")
@click.option("-v", "--verbose", count=True, help="More log output on stderr (-vv: debug)")
@click.version_option(__version__, prog_name="sshbite")
@click.pass_context
def main(ctx: click.Context, config_path: str | None, verbose: int) -> None:
    """SSHBITE - read-only SSH access audit."""
    _setup_logging(verbose)
    ctx.obj = {"config_path": config_path}


def _cfg(ctx: click.Context) -> Config:
    return load_config(ctx.obj["config_path"])


def _db(cfg: Config, create: bool = True):
    from . import db

    return db.connect(cfg.database, create=create)


def _open_existing_db(cfg: Config):
    if not os.path.exists(cfg.database):
        raise ConfigError(f"database {cfg.database} does not exist yet - run `sshbite scan` first")
    return _db(cfg)


# ---------------------------------------------------------------- init-config / config

@main.command("init-config")
def init_config() -> None:
    """Print the example config."""
    click.echo(EXAMPLE_CONFIG, nl=False)


@main.group("config")
def config_group() -> None:
    """Check the configuration."""


@config_group.command("validate")
@click.option("--connect", is_flag=True, help="Also connect to the entry point: check the pin and probe sudo")
@click.pass_context
def config_validate(ctx: click.Context, connect: bool) -> None:
    """Check schema, file permissions and seeds."""
    path = resolve_config_path(ctx.obj["config_path"])
    cfg = load_config(ctx.obj["config_path"])
    res = check_files(cfg)
    for w in res.warnings:
        click.echo(f"warning: {w}", err=True)
    if res.errors:
        for e in res.errors:
            click.echo(f"error: {e}", err=True)
        ctx.exit(2)
    click.echo(f"config OK: {path}")
    if connect:
        msg = asyncio.run(_check_entry(cfg))
        click.echo(msg)


async def _check_entry(cfg: Config) -> str:
    from .config import load_audit_key
    from .privilege import PASSWORD_REQUIRED
    from .transport import Hop, HostKeyPolicy, RouteError, Transport, run

    if not cfg.entry.host_keys:
        raise EntryError("ENTRY HOST KEY NOT PINNED: set entry.host_keys (compare ssh-keyscan with the console)")
    key = load_audit_key(cfg)
    policy = HostKeyPolicy(None, "tofu", None, cfg.entry.host_keys)
    tr = Transport(user=cfg.audit.user, client_key=key, policy=policy, connect_timeout=cfg.limits.connect_timeout,
                   entry_connections=1)
    try:
        conn = await tr.open_entry(Hop(cfg.entry.host, cfg.entry.host, cfg.entry.port, (cfg.entry.host,), "entry"))
    except RouteError as exc:
        if exc.kind == "pin_mismatch":
            raise EntryError("ENTRY HOST KEY MISMATCH – scan aborted\n"
                             f"  offered: {exc.detail.get('offered') or '(no pinned algorithm offered)'}\n"
                             + "".join(f"  pinned:  {p}\n" for p in exc.detail.get("pinned", []))) from None
        what = "authentication failed" if exc.kind == "auth" else "unreachable"
        raise EntryError(f"entry {cfg.entry.host}:{cfg.entry.port} {what}: {exc.message}") from None
    try:
        mode = cfg.privilege.mode
        if mode == "none":
            sudo = "not used (privilege.mode none)"
        else:
            i = " -i" if mode == "sudo-login" else ""
            r = await run(conn, f"sudo -n{i} /bin/true", None, max_bytes=65536)
            if r.rc == 0:
                sudo = "root"
            elif PASSWORD_REQUIRED.search(r.stderr):
                sudo = "password required (use --ask-sudo-password or SSHBITE_SUDO_PASSWORD when scanning)"
            else:
                first = (r.stderr.strip().splitlines() or [f"exit {r.rc}"])[0][:200]
                sudo = f"denied ({first})"
    finally:
        await tr.close()
    return f"entry OK, pinned key matches, sudo: {sudo}"


# ---------------------------------------------------------------- scan

@main.command("scan")
@click.option("--max-depth", type=click.IntRange(0, 100), help="Override crawl.max_depth")
@click.option("--max-hosts", type=click.IntRange(1, 100000), help="Override crawl.max_hosts")
@click.option("--concurrency", type=click.IntRange(1, 500), help="Override limits.concurrency")
@click.option("--timeout", type=click.FloatRange(1, 3600), help="Override limits.host_timeout (seconds)")
@click.option("--no-crawl", is_flag=True, help="Scan the entry and seeds only")
@click.option("--ask-sudo-password", is_flag=True, help="Prompt once for the sudo password (kept in memory only)")
@click.option("--label", help="A label for this scan")
@click.option("--dry-run", is_flag=True, help="Print entry, seeds and scope; do not connect")
@click.pass_context
def scan_cmd(ctx, max_depth, max_hosts, concurrency, timeout, no_crawl, ask_sudo_password, label, dry_run) -> None:
    """Crawl from the entry point and store a new scan."""
    from .crawl import ScanOptions, Scanner

    cfg = _cfg(ctx)
    opts = ScanOptions(max_depth=max_depth, max_hosts=max_hosts, concurrency=concurrency, timeout=timeout,
                       no_crawl=no_crawl, label=label)
    if dry_run:
        _dry_run(cfg, opts)
        return
    if ask_sudo_password:
        pw = click.prompt("sudo password", hide_input=True, default="", show_default=False, err=True)
        _SECRET._value = pw or None
    elif os.environ.get("SSHBITE_SUDO_PASSWORD"):
        _SECRET._value = os.environ["SSHBITE_SUDO_PASSWORD"]
    os.environ.pop("SSHBITE_SUDO_PASSWORD", None)
    conn = _db(cfg)
    started = time.monotonic()
    scanner = Scanner(cfg, conn, _SECRET, opts, echo=lambda s: click.echo(s))
    click.echo(f"scan: entry {cfg.entry.host}:{cfg.entry.port}, max depth {scanner.max_depth}, "
               f"max hosts {scanner.max_hosts}, concurrency {scanner.concurrency}")
    try:
        sid = asyncio.run(scanner.run())
    finally:
        _SECRET.clear()
    _print_summary(conn, sid, time.monotonic() - started, cfg, scanner)


def _dry_run(cfg: Config, opts) -> None:
    from .seeds import load_seeds

    click.echo(f"entry:     {cfg.entry.host}:{cfg.entry.port} ({len(cfg.entry.host_keys)} pinned key(s))")
    click.echo(f"audit:     user {cfg.audit.user}, key {cfg.audit.key_file}")
    click.echo(f"privilege: {cfg.privilege.mode}; host keys: {cfg.hostkeys.mode}")
    md = 0 if opts.no_crawl else (opts.max_depth if opts.max_depth is not None else cfg.crawl.max_depth)
    click.echo(f"crawl:     max depth {md}, max hosts {opts.max_hosts or cfg.crawl.max_hosts}, "
               f"chain fallback {'on' if cfg.crawl.chain_fallback else 'off'}")
    click.echo(f"include:   {', '.join(cfg.crawl.include) or '(no restriction)'}")
    click.echo(f"exclude:   {', '.join(cfg.crawl.exclude) or '(none)'}")
    seeds = load_seeds(cfg)
    click.echo(f"seeds:     {len(seeds)}")
    for s in seeds[:50]:
        click.echo(f"  {s.value}:{s.port}  ({s.source}{', probe' if s.probe else ''})")
    if len(seeds) > 50:
        click.echo(f"  ... {len(seeds) - 50} more")
    click.echo("dry run: no connection made")


def _print_summary(conn, sid: int, secs: float, cfg: Config, scanner) -> None:
    row = conn.execute("SELECT status, counts FROM scan WHERE id=?", (sid,)).fetchone()
    counts = json.loads(row["counts"] or "{}")
    hosts = counts.get("hosts", {})
    order = ["ok", "partial", "output_limit", "collector_error", "unreachable", "timeout", "auth_failed",
             "hostkey_mismatch", "hostkey_unknown", "alias", "excluded", "out_of_scope", "unresolvable",
             "max_depth", "max_hosts", "no_ssh"]
    parts = [f"{hosts[k]} {k}" for k in order if hosts.get(k)]
    parts += [f"{v} {k}" for k, v in hosts.items() if k not in order]
    f = counts.get("findings", {})
    sev = [f"{f.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "info")]
    click.echo("")
    click.echo(f"scan {sid} {row['status']} in {secs:.0f} s")
    click.echo(f"hosts:    {counts.get('hosts_connected', 0)} connected; " + ", ".join(parts))
    click.echo(f"findings: {counts.get('findings_total', 0)} - " + ", ".join(sev))
    click.echo(f"edges:    {counts.get('access_edges', 0)} access ({counts.get('effective_edges', 0)} effective, "
               f"{counts.get('unknown_origin_edges', 0)} unknown origin); keys: {counts.get('keys', 0)}")
    need = counts.get("need_sudo_password", 0)
    if need:
        click.echo(f"{need} host{'s' if need != 1 else ''} need{'' if need != 1 else 's'} a sudo password: "
                   "rerun with --ask-sudo-password")
    if counts.get("hosts_connected", 0) == 1:
        click.echo("Only the entry point was found; it has no known_hosts/ssh config references. "
                   "Add seeds to scan more.")
    click.echo(f"scan id:  {sid}")
    click.echo(f"UI:       http://{cfg.web.bind}:{cfg.web.port}/  (start it with `sshbite serve`)")


# ---------------------------------------------------------------- scans

@main.group("scans")
def scans_group() -> None:
    """List, show and delete stored scans."""


def _resolve_scan_id(conn, ident: str) -> int:
    if ident == "latest":
        row = conn.execute("SELECT id FROM scan WHERE status='completed' ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            raise ConfigError("no completed scan yet")
        return row[0]
    try:
        sid = int(ident)
    except ValueError:
        raise click.BadParameter(f"not a scan id: {ident}") from None
    if conn.execute("SELECT 1 FROM scan WHERE id=?", (sid,)).fetchone() is None:
        raise click.BadParameter(f"scan {sid} does not exist")
    return sid


@scans_group.command("list")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def scans_list(ctx, as_json: bool) -> None:
    from .report import scans_list_data

    conn = _open_existing_db(_cfg(ctx))
    data = scans_list_data(conn)
    if as_json:
        click.echo(json.dumps(data, indent=2))
        return
    if not data:
        click.echo("No scans yet. Run `sshbite scan`.")
        return
    click.echo(f"{'id':>4}  {'started':20}  {'status':9}  {'hosts':>5}  {'findings':>8}  label")
    for s in data:
        c = s["counts"] or {}
        syn = " [SYNTHETIC]" if s["synthetic"] else ""
        click.echo(f"{s['id']:>4}  {s['started_at']:20}  {s['status']:9}  {c.get('hosts_connected', 0):>5}  "
                   f"{c.get('findings_total', 0):>8}  {s['label'] or ''}{syn}")


@scans_group.command("show")
@click.argument("scan_id")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def scans_show(ctx, scan_id: str, as_json: bool) -> None:
    from .report import render_scan_text, scan_show_data

    conn = _open_existing_db(_cfg(ctx))
    sid = _resolve_scan_id(conn, scan_id)
    data = scan_show_data(conn, sid)
    if as_json:
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo(render_scan_text(data))


@scans_group.command("delete")
@click.argument("scan_id")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def scans_delete(ctx, scan_id: str, as_json: bool) -> None:
    from .report import delete_scan

    conn = _open_existing_db(_cfg(ctx))
    sid = _resolve_scan_id(conn, scan_id)
    res = delete_scan(conn, sid)
    if as_json:
        click.echo(json.dumps(res))
    else:
        click.echo(f"scan {sid} deleted; pruned {res['hosts_pruned']} hosts and {res['keys_pruned']} keys "
                   "no scan references any more")


# ---------------------------------------------------------------- export / diff

@main.command("export")
@click.option("--scan", "scan_ident", default="latest", show_default=True, help="Scan id or 'latest'")
@click.option("--what", type=click.Choice(["findings", "keys", "edges", "hosts", "authorized"]), required=True)
@click.option("--format", "fmt", type=click.Choice(["csv", "json"]), default="csv", show_default=True)
@click.option("-o", "output", type=click.Path(dir_okay=False, writable=True), help="Output file (default stdout)")
@click.option("--min-severity", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--rule", multiple=True, help="Finding rule (repeatable)")
@click.option("--host", "host_glob", help="Host name glob")
@click.option("--kind", type=click.Choice(["access", "evidence"]), help="Edge kind")
@click.pass_context
def export_cmd(ctx, scan_ident, what, fmt, output, min_severity, rule, host_glob, kind) -> None:
    """Export a cleanup worklist as CSV or JSON."""
    from .export import ExportFilter, export

    conn = _open_existing_db(_cfg(ctx))
    sid = _resolve_scan_id(conn, scan_ident)
    flt = ExportFilter(min_severity=min_severity, rules=list(rule), host_glob=host_glob, kind=kind)
    text = export(conn, sid, what, fmt, flt)
    if output:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        click.echo(f"wrote {output}", err=True)
    else:
        click.echo(text, nl=False)


@main.command("diff")
@click.argument("a")
@click.argument("b")
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", show_default=True)
@click.pass_context
def diff_cmd(ctx, a: str, b: str, fmt: str) -> None:
    """Compare scan A with scan B: added, removed and changed per category."""
    from .diff import diff_scans, render_text

    conn = _open_existing_db(_cfg(ctx))
    ia, ib = _resolve_scan_id(conn, a), _resolve_scan_id(conn, b)
    d = diff_scans(conn, ia, ib)
    click.echo(json.dumps(d, indent=2) if fmt == "json" else render_text(d))


# ---------------------------------------------------------------- hostkey

@main.group("hostkey")
def hostkey_group() -> None:
    """Manage the TOFU host key store."""


def _split_addr(value: str) -> tuple[str, int | None]:
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        return host, int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    if value.count(":") == 1:
        h, p = value.split(":")
        if p.isdigit():
            return h, int(p)
    return value, None


@hostkey_group.command("list")
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def hostkey_list(ctx, as_json: bool) -> None:
    conn = _db(_cfg(ctx))
    rows = [dict(r) for r in conn.execute("SELECT * FROM trusted_hostkey ORDER BY addr, port, alg")]
    if as_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No trusted host keys yet.")
    for r in rows:
        click.echo(f"{r['addr']}:{r['port']}  {r['alg']:22}  {r['fp']}  first scan {r['first_seen_scan']}"
                   f"  accepted {r['accepted_at'] or '-'}")


@hostkey_group.command("accept")
@click.argument("addr")
@click.pass_context
def hostkey_accept(ctx, addr: str) -> None:
    """Trust the changed host key of ADDR[:PORT] (check it out-of-band first)."""
    from .hostkeys import accept

    conn = _db(_cfg(ctx))
    host, port = _split_addr(addr)
    for line in accept(conn, host, port):
        click.echo(line)


@hostkey_group.command("forget")
@click.argument("addr")
@click.pass_context
def hostkey_forget(ctx, addr: str) -> None:
    """Remove all stored keys of ADDR (the next scan trusts what it sees)."""
    conn = _db(_cfg(ctx))
    host, port = _split_addr(addr)
    if port is None:
        n = conn.execute("DELETE FROM trusted_hostkey WHERE addr=?", (host,)).rowcount
    else:
        n = conn.execute("DELETE FROM trusted_hostkey WHERE addr=? AND port=?", (host, port)).rowcount
    click.echo(f"removed {n} key(s) of {addr}")


# ---------------------------------------------------------------- user

@main.group("user")
def user_group() -> None:
    """UI logins (argon2id)."""


def _prompt_password() -> str:
    pw = click.prompt("password", hide_input=True, confirmation_prompt="repeat password", err=True)
    if len(pw) < 12:
        raise click.UsageError("the password must have at least 12 characters")
    return pw


@user_group.command("add")
@click.argument("name")
@click.pass_context
def user_add(ctx, name: str) -> None:
    from .users import add_user, validate_username

    validate_username(name)
    conn = _db(_cfg(ctx))
    if conn.execute("SELECT 1 FROM app_user WHERE username=?", (name,)).fetchone():
        raise click.UsageError(f"user {name} exists already (use `sshbite user passwd {name}`)")
    add_user(conn, name, _prompt_password())
    click.echo(f"user {name} added")


@user_group.command("passwd")
@click.argument("name")
@click.pass_context
def user_passwd(ctx, name: str) -> None:
    from .users import set_password

    conn = _db(_cfg(ctx))
    if not conn.execute("SELECT 1 FROM app_user WHERE username=?", (name,)).fetchone():
        raise click.UsageError(f"no user {name}")
    set_password(conn, name, _prompt_password())
    click.echo(f"password of {name} changed; its sessions were ended and the lockout cleared")


@user_group.command("remove")
@click.argument("name")
@click.pass_context
def user_remove(ctx, name: str) -> None:
    conn = _db(_cfg(ctx))
    n = conn.execute("DELETE FROM app_user WHERE username=?", (name,)).rowcount
    if not n:
        raise click.UsageError(f"no user {name}")
    click.echo(f"user {name} removed")


# ---------------------------------------------------------------- db / collector / synth

@main.group("db")
def db_group() -> None:
    """Database maintenance."""


@db_group.command("backup")
@click.argument("path", type=click.Path(dir_okay=False))
@click.pass_context
def db_backup(ctx, path: str) -> None:
    """SQLite online backup; safe while the DB is in use."""
    from . import db

    conn = _open_existing_db(_cfg(ctx))
    try:
        db.backup(conn, path)
    except FileExistsError:
        raise click.UsageError(f"{path} exists already") from None
    click.echo(f"backup written to {path}")


@main.group("collector")
def collector_group() -> None:
    """The fixed scripts that run on targets."""


@collector_group.command("show")
def collector_show() -> None:
    """Print both target scripts with their SHA-256 for review."""
    from . import collector
    from .collector.lint import lint

    for name, text in (("collect.sh", collector.collect_script()), ("resolve.sh", collector.resolve_script())):
        v = lint(text, name)
        click.echo(f"===== {name}  sha256 {collector.sha256(text)}  lint: {'OK' if not v else f'{len(v)} violation(s)'}")
        click.echo(text, nl=not text.endswith("\n"))
        for x in v:
            click.echo(f"  LINT: {x}")
    from .privilege import commands

    click.echo("===== literal commands sent on exec channels (privilege.mode: sudo / sudo-login)")
    seen = []
    for mode in ("sudo", "sudo-login"):
        for c in commands(mode).values():
            if c not in seen:
                seen.append(c)
                click.echo(c)


@main.command("synth")
@click.option("--hosts", "n_hosts", type=click.IntRange(10, 100000), default=2000, show_default=True)
@click.option("--seed", "seed", type=int, default=42, show_default=True)
@click.pass_context
def synth_cmd(ctx, n_hosts: int, seed: int) -> None:
    """Create a synthetic scan (synthetic=1) for testing the UI at scale."""
    from .synth import synth

    cfg = _cfg(ctx)
    conn = _db(cfg)
    t0 = time.monotonic()
    res = synth(conn, n_hosts, seed, cfg)
    click.echo(f"synthetic scan {res['scan_id']}: {res['hosts']} hosts, {res['authorized_entries']} authorized entries, "
               f"{res['access_edges']} access edges, {res['findings']} findings")
    click.echo(f"generate {res['generate_s']:.1f} s, derive {res['derive_s']:.1f} s, total {time.monotonic() - t0:.1f} s")


if __name__ == "__main__":  # pragma: no cover
    main()
