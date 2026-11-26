"""Breadth-first crawl from the verified entry point (spec 3.3) and scan orchestration."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Callable

from . import __version__, collector
from .config import Config, check_audit_key_file, load_audit_key, scope_match
from .db import j, utcnow
from .errors import ConfigError, EntryError, ScanLocked
from .parse import known_hosts as kh
from .parse import records
from .parse.authorized_keys import literal_from_targets
from .parse.host import HostData, KnownHostsRec, build
from .parse.keys import parse_public_key_line
from .parse.ssh_config import has_wildcard, proxyjump_hops
from .privilege import SudoSecret, collect as priv_collect
from .seeds import Seed, load_seeds
from .transport import Hop, HostKeyPolicy, RouteError, Transport, run

log = logging.getLogger("sshbite.crawl")

CONNECTED_STATUSES = ("ok", "partial", "unreachable", "timeout", "auth_failed", "hostkey_mismatch",
                      "hostkey_unknown", "collector_error", "output_limit")
DATA_STATUSES = ("ok", "partial", "collector_error", "output_limit")
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ip_sort_key(ip: str):
    a = ipaddress.ip_address(ip)
    return (a.version, a)


# ---------------------------------------------------------------- model

@dataclass(eq=False)
class Target:
    addr: str
    port: int
    depth: int
    role: str = "host"
    names: list[str] = field(default_factory=list)
    via: "Ref | None" = None
    parent: "Target | None" = None
    seed_source: str | None = None
    status: str = "queued"
    privilege: str | None = None
    route: list["Target"] | None = None
    attempts: list[tuple[list["Target"], str | None]] = field(default_factory=list)
    data: HostData | None = None
    partial_reasons: list[str] = field(default_factory=list)
    error: str | None = None
    duration_ms: int | None = None
    alias_of: "Target | None" = None
    needs_password: bool = False
    unresolved_hashed: int = 0
    hostkey_verdict: str | None = None
    hostkey_detail: dict | None = None
    connect_ip: str | None = None
    groups: list[tuple[str, str]] = field(default_factory=list)
    host_id: int | None = None
    order: int = 0

    @property
    def display(self) -> str:
        if self.data is not None and self.data.hostname:
            return self.data.hostname
        if self.role == "entry":
            return self.addr
        return self.names[0] if self.names else self.addr

    def hop(self) -> Hop:
        return Hop(name=self.display, addr=self.addr, port=self.port, names=tuple(self.names), role=self.role)

    @property
    def has_data(self) -> bool:
        return self.data is not None and self.status in DATA_STATUSES


@dataclass(eq=False)
class Ref:
    from_t: Target
    username: str
    source: str
    file: str
    line_no: int
    value: str
    port: int
    resolved_ips: list[str] = field(default_factory=list)
    target: Target | None = None
    outcome: str = ""
    kh_rec: KnownHostsRec | None = None
    order: int = 0
    db_id: int | None = None

    def sort_key(self):
        return (self.from_t.display, self.file, self.line_no, self.order)


@dataclass
class PendingHash:
    host: Target
    rec: KnownHostsRec
    source: str


@dataclass
class ScanOptions:
    max_depth: int | None = None
    max_hosts: int | None = None
    concurrency: int | None = None
    timeout: float | None = None
    no_crawl: bool = False
    label: str | None = None


# ---------------------------------------------------------------- scanner

class Scanner:
    def __init__(self, cfg: Config, db: sqlite3.Connection, secret: SudoSecret | None = None,
                 opts: ScanOptions | None = None, echo: Callable[[str], None] = print):
        self.cfg = cfg
        self.db = db
        self.secret = secret or SudoSecret()
        self.opts = opts or ScanOptions()
        self.echo = echo
        self.max_depth = 0 if self.opts.no_crawl else (
            self.opts.max_depth if self.opts.max_depth is not None else cfg.crawl.max_depth)
        self.max_hosts = self.opts.max_hosts or cfg.crawl.max_hosts
        self.concurrency = self.opts.concurrency or cfg.limits.concurrency
        self.host_timeout = self.opts.timeout or cfg.limits.host_timeout
        self.script_text = collector.collect_script()
        self.script = self.script_text.encode("utf-8")
        self.resolve_script = collector.resolve_script().encode("utf-8")
        self.expected_sha_short = collector.declared_sha_short(self.script_text)
        self.targets: list[Target] = []           # connected or queued, in order
        self.seen: dict[tuple[str, int], Target] = {}  # never-connected hosts (excluded, out_of_scope...)
        self.by_addr: dict[tuple[str, int], Target] = {}
        self.ip_owner: dict[str, Target] = {}     # interface IP -> collected host
        self.refs: list[Ref] = []
        self.pending_hashed: list[PendingHash] = []
        self.resolved: dict[str, list[str]] = {}
        self.unresolvable: set[str] = set()
        self.scan_id: int | None = None
        self.transport: Transport | None = None
        self.entry: Target | None = None
        self.audit_fp: str | None = None
        self.depth = 0
        self.running = 0
        self._order = 0
        self._ref_order = 0
        self._progress_task: asyncio.Task | None = None
        self._last_echo = ""

    # ---- lock -----------------------------------------------------------------
    def _acquire_lock(self) -> None:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT pid, scan_id FROM scan_lock WHERE id = 1").fetchone()
            if row is not None:
                if _pid_alive(row["pid"]):
                    raise ScanLocked(f"another scan is running (pid {row['pid']}, scan {row['scan_id']})")
                if row["scan_id"]:
                    self.db.execute("UPDATE scan SET status='failed', finished_at=? WHERE id=? AND status='running'",
                                    (utcnow(), row["scan_id"]))
                self.db.execute("DELETE FROM scan_lock WHERE id = 1")
            self.db.execute("INSERT INTO scan_lock(id, pid, scan_id, started_at) VALUES (1, ?, NULL, ?)",
                            (os.getpid(), utcnow()))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def _release_lock(self) -> None:
        self.db.execute("DELETE FROM scan_lock WHERE id = 1 AND pid = ?", (os.getpid(),))

    # ---- scan row -------------------------------------------------------------
    def _create_scan(self) -> int:
        params = {
            "max_depth": self.max_depth, "max_hosts": self.max_hosts, "concurrency": self.concurrency,
            "host_timeout": self.host_timeout, "no_crawl": self.opts.no_crawl,
            "privilege_mode": self.cfg.privilege.mode, "hostkeys_mode": self.cfg.hostkeys.mode,
            "include": self.cfg.crawl.include, "exclude": self.cfg.crawl.exclude,
            "chain_fallback": self.cfg.crawl.chain_fallback,
            "sudo_password_given": bool(self.secret),
        }
        cur = self.db.execute(
            "INSERT INTO scan(label, started_at, status, synthetic, tool_version, collector_sha256, config_sha256,"
            " entry_host, params, progress, pid) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (self.opts.label, utcnow(), "running", 0, __version__, collector.sha256(self.script_text),
             self.cfg.raw_sha256, f"{self.cfg.entry.host}:{self.cfg.entry.port}", j(params),
             j({"phase": "connect", "depth": 0, "queued": 0, "running": 0, "done": 0, "by_status": {}}),
             os.getpid()))
        sid = cur.lastrowid
        self.db.execute("UPDATE scan_lock SET scan_id=? WHERE id=1", (sid,))
        return sid

    def _finish_scan(self, status: str, counts: dict | None = None, phase: str = "done") -> None:
        self.db.execute("UPDATE scan SET status=?, finished_at=?, counts=?, progress=? WHERE id=?",
                        (status, utcnow(), j(counts or {}), j(self._progress(phase)), self.scan_id))

    # ---- progress -------------------------------------------------------------
    def _progress(self, phase: str = "crawl") -> dict:
        by: dict[str, int] = {}
        queued = done = 0
        for t in self.targets:
            if t.status == "queued":
                queued += 1
            elif t.status != "running":
                done += 1
                by[t.status] = by.get(t.status, 0) + 1
        return {"phase": phase, "depth": self.depth, "queued": queued, "running": self.running, "done": done,
                "by_status": by}

    def _progress_line(self) -> str:
        p = self._progress()
        extra = []
        for st in ("partial", "unreachable", "timeout", "auth_failed", "hostkey_mismatch", "hostkey_unknown",
                   "collector_error", "output_limit"):
            if p["by_status"].get(st):
                extra.append(f"{p['by_status'][st]} {st.replace('_', ' ')}")
        tail = f" ({', '.join(extra)})" if extra else ""
        return f"depth {p['depth']}: {p['queued']} queued, {p['running']} running, {p['done']} done{tail}"

    def _emit_progress(self, force: bool = False) -> None:
        line = self._progress_line()
        if force or line != self._last_echo:
            self.echo(line)
            self._last_echo = line

    async def _progress_loop(self) -> None:
        while True:
            await asyncio.sleep(2)
            try:
                self.db.execute("UPDATE scan SET progress=? WHERE id=?", (j(self._progress()), self.scan_id))
            except sqlite3.Error as exc:  # never let progress kill the scan
                log.debug("progress update failed: %s", exc)
            self._emit_progress()

    # ---- main -----------------------------------------------------------------
    def check_preconditions(self) -> None:
        err = check_audit_key_file(self.cfg)
        if err:
            raise ConfigError(err)

    async def run(self) -> int:
        """Run the scan; return the scan id. Raises EntryError (exit 3), ConfigError (2), ScanLocked (5)."""
        self.check_preconditions()
        client_key = load_audit_key(self.cfg)
        self.audit_fp = _fp_of_asyncssh_key(client_key) if self.cfg.rules.ignore_audit_key else None
        seeds = load_seeds(self.cfg)
        self._acquire_lock()
        try:
            self.scan_id = self._create_scan()
            if not self.cfg.entry.host_keys:
                self._finish_scan("aborted", {"error": "entry.host_keys missing"}, "aborted")
                raise EntryError("ENTRY HOST KEY NOT PINNED - scan aborted: set entry.host_keys in the config")
            known_text = None
            if self.cfg.hostkeys.mode == "strict":
                try:
                    with open(self.cfg.hostkeys.known_hosts_file or "", encoding="utf-8", errors="replace") as fh:
                        known_text = fh.read()
                except OSError as exc:
                    self._finish_scan("failed", {"error": str(exc)}, "failed")
                    raise ConfigError(f"hostkeys.known_hosts_file: {exc}") from None
            policy = HostKeyPolicy(self.db, self.cfg.hostkeys.mode, known_text, self.cfg.entry.host_keys, self.scan_id)
            self.transport = Transport(user=self.cfg.audit.user, client_key=client_key, policy=policy,
                                       connect_timeout=self.cfg.limits.connect_timeout,
                                       entry_connections=self.cfg.limits.entry_connections)
            self.entry = Target(addr=self.cfg.entry.host, port=self.cfg.entry.port, depth=0, role="entry",
                                names=[self.cfg.entry.host], seed_source="entry")
            self._add_target(self.entry)
            try:
                conn = await self.transport.open_entry(self.entry.hop())
            except RouteError as exc:
                if exc.kind == "pin_mismatch":
                    self._finish_scan("aborted", {"error": "entry host key mismatch", **exc.detail}, "aborted")
                    raise EntryError(
                        "ENTRY HOST KEY MISMATCH – scan aborted\n"
                        f"  offered by {self.cfg.entry.host}:{self.cfg.entry.port}: {exc.detail.get('offered') or '(no pinned algorithm offered)'}\n"
                        + "".join(f"  pinned: {p}\n" for p in exc.detail.get("pinned", []))) from None
                self._finish_scan("failed", {"error": f"entry: {exc.message}"}, "failed")
                kind = "authentication failed" if exc.kind == "auth" else "unreachable"
                raise EntryError(f"entry {self.cfg.entry.host}:{self.cfg.entry.port} {kind}: {exc.message}") from None
            peer = conn.get_extra_info("peername")
            self.entry.connect_ip = peer[0] if peer else None
            self.entry.route = [self.entry]
            self.entry.attempts.append(([self.entry], None))

            for s in seeds:
                await self._add_seed(s)

            self._progress_task = asyncio.create_task(self._progress_loop())
            try:
                await self._crawl()
            finally:
                self._progress_task.cancel()
                await self.transport.close()
            self.db.execute("UPDATE scan SET progress=? WHERE id=?", (j(self._progress("store")), self.scan_id))
            from .db.store import persist_scan
            persist_scan(self)
            self.db.execute("UPDATE scan SET progress=? WHERE id=?", (j(self._progress("derive")), self.scan_id))
            from .derive import derive_scan
            derive_scan(self.db, self.scan_id, self.cfg)
            counts = scan_counts(self.db, self.scan_id)
            counts["need_sudo_password"] = sum(1 for t in self.targets if t.needs_password)
            self._finish_scan("completed", counts)
            return self.scan_id
        except (EntryError, ConfigError):
            raise
        except BaseException as exc:
            if self.scan_id is not None:
                try:
                    self._finish_scan("failed", {"error": self.secret.redact(f"{exc.__class__.__name__}: {exc}")},
                                      "failed")
                except sqlite3.Error:
                    pass
            raise
        finally:
            self._release_lock()

    # ---- targets ----------------------------------------------------------------
    def _add_target(self, t: Target) -> Target:
        self._order += 1
        t.order = self._order
        self.targets.append(t)
        self.by_addr[(t.addr, t.port)] = t
        return t

    async def _add_seed(self, s: Seed) -> None:
        assert self.transport is not None and self.entry is not None
        source = f"seed:{s.source}"
        ips = [s.value] if is_ip(s.value) else await self._resolve_on_entry([s.value])
        if not ips:
            key = (s.value, s.port)
            if key not in self.seen:
                t = Target(addr=s.value, port=s.port, depth=0, names=[s.value], seed_source=source,
                           status="unresolvable")
                self.seen[key] = t
            return
        ip = sorted(ips, key=_ip_sort_key)[0]
        if (ip, s.port) in self.by_addr:
            ex = self.by_addr[(ip, s.port)]
            for g in s.groups:
                ex.groups.append(("ansible", g))
            return
        if s.probe:
            ok = await self._tcp_probe(ip, s.port)
            if not ok:
                self.seen[(ip, s.port)] = Target(addr=ip, port=s.port, depth=0, names=[ip], seed_source=source,
                                                 status="no_ssh")
                return
        names = [s.value] if s.value == ip else [s.value, ip]
        t = Target(addr=ip, port=s.port, depth=0, names=names, seed_source=source)
        t.groups.extend(("ansible", g) for g in s.groups)
        self._add_target(t)

    async def _tcp_probe(self, ip: str, port: int) -> bool:
        assert self.transport is not None
        try:
            reader, writer = await asyncio.wait_for(self.transport.entry.open_connection(ip, port), timeout=2)
            writer.close()
            return True
        except BaseException as exc:
            if isinstance(exc, asyncio.CancelledError):
                raise
            return False

    async def _resolve_on(self, conn, names: list[str]) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for i in range(0, len(names), 500):
            chunk = names[i:i + 500]
            data = self.resolve_script + ("\n".join(chunk) + "\n").encode()
            try:
                res = await asyncio.wait_for(run(conn, "/bin/sh -s", data, max_bytes=1 << 20),
                                             timeout=max(10.0, self.cfg.limits.connect_timeout * 2))
            except BaseException as exc:
                if isinstance(exc, asyncio.CancelledError):
                    raise
                log.warning("name resolution failed: %s", exc)
                continue
            for line in res.stdout.decode("utf-8", "replace").splitlines():
                n, _, ip = line.partition("\t")
                ip = ip.strip()
                if n in chunk and is_ip(ip):
                    lst = out.setdefault(n, [])
                    if ip not in lst:
                        lst.append(ip)
        return out

    async def _resolve_on_entry(self, names: list[str]) -> list[str]:
        assert self.transport is not None
        r = await self._resolve_on(self.transport.entry, names)
        return r.get(names[0], []) if names else []

    # ---- crawl loop -------------------------------------------------------------
    async def _crawl(self) -> None:
        level = [t for t in self.targets if t.depth == 0]
        self.depth = 0
        while level:
            self._emit_progress(force=True)
            sem = asyncio.Semaphore(self.concurrency)

            async def one(t: Target):
                async with sem:
                    await self._collect_target(t)

            await asyncio.gather(*(one(t) for t in level))
            self._alias_by_hostkey(level)
            for t in level:
                if t.has_data:
                    for ip in t.data.ips + ([t.connect_ip] if t.connect_ip else []):
                        self.ip_owner.setdefault(ip, t)
            self._emit_progress(force=True)
            new_refs = self._derive_refs([t for t in level if t.has_data])
            await self._resolve_refs(new_refs)
            new_refs.extend(self._probe_hashed())
            level = self._classify(new_refs, self.depth)
            if level:
                self.depth += 1
        # entries still unmatched
        for p in self.pending_hashed:
            p.host.unresolved_hashed += 1

    def _alias_by_hostkey(self, level: list[Target]) -> None:
        seen: dict[str, Target] = {}
        for t in self.targets:
            if t in level or not t.has_data:
                continue
            k = t.data.preferred_host_key()
            if k:
                seen.setdefault(k.fp, t)
        for t in sorted(level, key=lambda x: x.order):
            if not t.has_data:
                continue
            k = t.data.preferred_host_key()
            if not k:
                continue
            if k.fp in seen and seen[k.fp] is not t:
                t.alias_of = seen[k.fp]
                t.status = "alias"
                t.data = None
            else:
                seen[k.fp] = t

    # ---- collection -----------------------------------------------------------
    async def _collect_target(self, t: Target) -> None:
        t.status = "running"
        self.running += 1
        start = time.monotonic()
        current: list[list[Target]] = []
        try:
            async with asyncio.timeout(self.host_timeout):
                await self._connect_and_collect(t, current)
        except TimeoutError:
            t.status = "timeout"
            t.error = f"no result within host_timeout ({self.host_timeout:g} s)"
            if current and (not t.attempts or t.attempts[-1][0] is not current[-1]):
                t.attempts.append((current[-1], "timeout (host_timeout)"))
        except Exception as exc:  # a host never aborts the scan
            log.exception("collection of %s failed", t.addr)
            t.status = "collector_error"
            t.error = self.secret.redact(f"{exc.__class__.__name__}: {exc}")[:500]
        finally:
            self.running -= 1
            t.duration_ms = int((time.monotonic() - start) * 1000)

    async def _connect_and_collect(self, t: Target, current: list) -> None:
        assert self.transport is not None and self.entry is not None
        if t.role == "entry":
            conn = self.transport.entry
            route = [t]
        else:
            routes = [[self.entry, t]]
            conn = None
            route = None
            i = 0
            while i < len(routes):
                r = routes[i]
                i += 1
                current.append(r)
                try:
                    conn = await self.transport.connect([h.hop() for h in r])
                    route = r
                    t.attempts.append((r, None))
                    break
                except RouteError as exc:
                    t.attempts.append((r, self.secret.redact(str(exc))))
                    at_target = exc.hop_key == (t.addr, t.port)
                    if exc.kind == "network" or not at_target:
                        if (i == 1 and self.cfg.crawl.chain_fallback and t.parent is not None
                                and t.parent.route and t.parent.role != "entry"):
                            routes.append(list(t.parent.route) + [t])
                        continue
                    if exc.kind == "auth":
                        t.status = "auth_failed"
                    elif exc.kind == "hostkey_mismatch":
                        t.status = "hostkey_mismatch"
                        t.hostkey_detail = exc.detail
                    elif exc.kind == "hostkey_unknown":
                        t.status = "hostkey_unknown"
                        t.hostkey_detail = exc.detail
                    else:
                        t.status = "unreachable"
                    t.error = exc.message
                    return
            if conn is None:
                t.status = "unreachable"
                t.error = t.attempts[-1][1] if t.attempts else "unreachable"
                return
            t.connect_ip = t.addr
        t.route = route
        try:
            outcome = await priv_collect(conn, self.script, self.cfg.privilege.mode, self.secret,
                                         self.cfg.limits.max_output_mb * 1024 * 1024)
        finally:
            if t.role != "entry":
                self.transport.release([h.hop() for h in route])
        t.privilege = outcome.privilege
        t.needs_password = outcome.needs_password
        t.partial_reasons.extend(outcome.partial_reasons)
        res = outcome.result
        text = res.stdout.decode("utf-8", "replace")
        c = records.parse(text, truncated=res.truncated)
        t.data = build(c, self.audit_fp)
        if res.truncated:
            t.status = "output_limit"
            t.partial_reasons.append(f"output limit of {self.cfg.limits.max_output_mb} MB reached")
        elif c.sha_short != self.expected_sha_short:
            t.status = "collector_error"
            t.error = "no collector output" if not c.sha_short else "collector header does not match the script"
            if res.stderr:
                t.error += ": " + self.secret.redact(res.stderr.strip().splitlines()[0])[:200]
        elif not c.complete:
            t.status = "collector_error"
            t.error = "collector output ended without #END"
            if res.stderr:
                t.error += ": " + self.secret.redact(res.stderr.strip().splitlines()[0])[:200]
        elif outcome.privilege == "unprivileged":
            t.status = "partial"
        else:
            t.status = "ok"
        if outcome.privilege == "unprivileged" or t.status in ("partial", "output_limit"):
            for path, reason in t.data.unreadable:
                if reason == "unreadable":
                    t.partial_reasons.append(f"unreadable: {path}")
            t.partial_reasons = t.partial_reasons[:50]

    # ---- references -----------------------------------------------------------
    def _new_ref(self, **kw) -> Ref:
        self._ref_order += 1
        return Ref(order=self._ref_order, **kw)

    def _derive_refs(self, hosts: list[Target]) -> list[Ref]:
        out: list[Ref] = []
        dport = self.cfg.crawl.ssh_port
        for t in hosts:
            d = t.data
            assert d is not None
            for rec in d.known_hosts:
                e = rec.entry
                if e.error or e.marker:
                    continue
                source = "system_known_hosts" if rec.username == "" else "known_hosts"
                if e.hashed:
                    self.pending_hashed.append(PendingHash(t, rec, source))
                    continue
                for pat in e.patterns:
                    if not kh.is_plain_pattern(pat):
                        continue
                    h, p = kh.split_host_port(pat, dport)
                    out.append(self._new_ref(from_t=t, username=rec.username, source=source, file=rec.file,
                                             line_no=e.line_no, value=h, port=p, kh_rec=rec))
            for rec in d.ssh_configs:
                e = rec.entry
                if e.is_match:
                    continue
                source = "system_ssh_config" if rec.username == "" else "ssh_config"
                port = e.port or dport
                if e.hostname and "%" not in e.hostname:
                    out.append(self._new_ref(from_t=t, username=rec.username, source=source, file=rec.file,
                                             line_no=e.hostname_line or e.line_no, value=e.hostname, port=port))
                elif not e.hostname and e.line_no > 0:
                    for pat in e.host_pattern.split():
                        if has_wildcard(pat):
                            continue
                        out.append(self._new_ref(from_t=t, username=rec.username, source=source, file=rec.file,
                                                 line_no=e.line_no, value=pat, port=port))
                if e.proxyjump:
                    for host, p in proxyjump_hops(e.proxyjump):
                        if has_wildcard(host) or "%" in host:
                            continue
                        out.append(self._new_ref(from_t=t, username=rec.username, source="ssh_config_proxyjump",
                                                 file=rec.file, line_no=e.proxyjump_line or e.line_no, value=host,
                                                 port=p or dport))
            for a in d.authorized:
                if a.entry.key is None:
                    continue
                for v in literal_from_targets(a.entry.from_patterns):
                    out.append(self._new_ref(from_t=t, username=a.username, source="from_option", file=a.file,
                                             line_no=a.entry.line_no, value=v, port=dport))
        return out

    async def _resolve_refs(self, refs: list[Ref]) -> None:
        names: list[str] = []
        for r in refs:
            if is_ip(r.value):
                r.resolved_ips = [str(ipaddress.ip_address(r.value))]
                continue
            if not _NAME_RE.match(r.value):
                continue
            if r.value not in self.resolved and r.value not in self.unresolvable and r.value not in names:
                names.append(r.value)
        if names:
            assert self.transport is not None
            got = await self._resolve_on(self.transport.entry, names)
            self.resolved.update(got)
            missing = [n for n in names if n not in got]
            # still unresolved: try once more on the host that referenced them
            for n in missing:
                src = next((r.from_t for r in refs if r.value == n), None)
                if src is not None and src.role != "entry" and src.route:
                    try:
                        conn = await self.transport.connect([h.hop() for h in src.route])
                        try:
                            got2 = await self._resolve_on(conn, [n])
                        finally:
                            self.transport.release([h.hop() for h in src.route])
                    except RouteError:
                        got2 = {}
                    if got2.get(n):
                        self.resolved[n] = got2[n]
                        continue
                self.unresolvable.add(n)
        for r in refs:
            if not r.resolved_ips and r.value in self.resolved:
                r.resolved_ips = sorted(self.resolved[r.value], key=_ip_sort_key)

    def _hash_candidates(self) -> list[tuple[str, int]]:
        names: set[str] = set()
        for t in self.targets:
            names.add(t.addr)
            names.update(t.names)
            if t.data is not None:
                if t.data.hostname:
                    names.add(t.data.hostname)
                names.update(t.data.ips)
        for r in self.refs:
            names.add(r.value)
            names.update(r.resolved_ips)
        for t in self.seen.values():
            names.add(t.addr)
            names.update(t.names)
        for n, ips in self.resolved.items():
            names.add(n)
            names.update(ips)
        if self.cfg.crawl.hash_probe_include_cidrs:
            budget = self.cfg.crawl.hash_probe_max_addresses
            for pat in self.cfg.crawl.include:
                if "/" not in pat or budget <= 0:
                    continue
                net = ipaddress.ip_network(pat, strict=False)
                for a in net.hosts() if net.num_addresses > 2 else net:
                    if budget <= 0:
                        break
                    names.add(str(a))
                    budget -= 1
        ports = {22, self.cfg.crawl.ssh_port}
        return [(n, p) for n in sorted(names) if n for p in sorted(ports)]

    def _probe_hashed(self) -> list[Ref]:
        if not self.pending_hashed:
            return []
        cands = [(kh.hash_candidate(n, p), n, p) for n, p in self._hash_candidates()]
        out: list[Ref] = []
        still: list[PendingHash] = []
        for ph in self.pending_hashed:
            hit = None
            for cand, n, p in cands:
                if kh.hash_matches(ph.rec.entry, cand):
                    hit = (n, p)
                    break
            if hit is None:
                still.append(ph)
                continue
            n, p = hit
            r = self._new_ref(from_t=ph.host, username=ph.rec.username, source="known_hosts_hashed",
                              file=ph.rec.file, line_no=ph.rec.entry.line_no, value=n, port=p, kh_rec=ph.rec)
            if is_ip(n):
                r.resolved_ips = [n]
            else:
                r.resolved_ips = sorted(self.resolved.get(n, []), key=_ip_sort_key)
            out.append(r)
        self.pending_hashed = still
        return out

    # ---- classification ---------------------------------------------------------
    def _connected_count(self) -> int:
        return len(self.targets)

    def _seen_target(self, r: Ref, status: str, depth: int) -> Target:
        ip = r.resolved_ips[0] if r.resolved_ips else None
        key = (ip or r.value.lower(), r.port)
        t = self.seen.get(key)
        if t is None:
            names = [r.value] if (ip is None or r.value == ip) else [r.value, ip]
            t = Target(addr=ip or r.value, port=r.port, depth=depth, names=names, via=r, parent=r.from_t,
                       status=status)
            self.seen[key] = t
        elif r.value not in t.names:
            t.names.append(r.value)
        return t

    def _classify(self, refs: list[Ref], depth: int) -> list[Target]:
        new_level: list[Target] = []
        inc, exc = self.cfg.crawl.include, self.cfg.crawl.exclude
        for r in sorted(refs, key=lambda x: x.sort_key()):
            self.refs.append(r)
            if not r.resolved_ips:
                r.outcome = "unresolvable"
                r.target = self._seen_target(r, "unresolvable", depth + 1)
                continue
            owner = next((self.ip_owner[ip] for ip in r.resolved_ips if ip in self.ip_owner), None)
            if owner is not None:
                r.outcome, r.target = "alias", owner
                if r.value not in owner.names and not is_ip(r.value):
                    owner.names.append(r.value)
                continue
            known = next((self.by_addr[(ip, r.port)] for ip in r.resolved_ips if (ip, r.port) in self.by_addr), None)
            if known is not None:
                r.outcome, r.target = "already", known
                if r.value not in known.names:
                    known.names.append(r.value)
                continue
            names = [r.value]
            if exc and scope_match(exc, names, r.resolved_ips):
                r.outcome = "excluded"
                r.target = self._seen_target(r, "excluded", depth + 1)
                continue
            if inc and not scope_match(inc, names, r.resolved_ips):
                r.outcome = "out_of_scope"
                r.target = self._seen_target(r, "out_of_scope", depth + 1)
                continue
            if depth + 1 > self.max_depth:
                r.outcome = "max_depth"
                r.target = self._seen_target(r, "max_depth", depth + 1)
                continue
            if self._connected_count() >= self.max_hosts:
                r.outcome = "max_hosts"
                r.target = self._seen_target(r, "max_hosts", depth + 1)
                continue
            ip = r.resolved_ips[0]
            tnames = [r.value] if r.value == ip else [r.value, ip]
            t = Target(addr=ip, port=r.port, depth=depth + 1, names=tnames, via=r, parent=r.from_t)
            self._add_target(t)
            r.outcome, r.target = "queued", t
            new_level.append(t)
        return new_level


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _fp_of_asyncssh_key(key) -> str | None:
    try:
        line = key.export_public_key("openssh").decode()
    except Exception:
        return None
    k = parse_public_key_line(line)
    return k.fp if k else None


def scan_counts(db: sqlite3.Connection, scan_id: int) -> dict:
    hosts = {r[0]: r[1] for r in db.execute(
        "SELECT status, count(*) FROM host_scan WHERE scan_id=? GROUP BY status", (scan_id,))}
    findings = {r[0]: r[1] for r in db.execute(
        "SELECT severity, count(*) FROM finding WHERE scan_id=? GROUP BY severity", (scan_id,))}
    edges = db.execute("SELECT count(*), sum(effective), sum(src_host_id IS NULL) FROM edge WHERE scan_id=? AND kind='access'",
                       (scan_id,)).fetchone()
    keys = db.execute("SELECT count(DISTINCT fp) FROM (SELECT fp FROM authorized_entry WHERE scan_id=? AND fp IS NOT NULL"
                      " UNION SELECT fp FROM private_key WHERE scan_id=? AND fp IS NOT NULL)", (scan_id, scan_id)).fetchone()[0]
    return {
        "hosts": hosts,
        "hosts_total": sum(hosts.values()),
        "hosts_connected": sum(v for k, v in hosts.items() if k in CONNECTED_STATUSES),
        "findings": findings,
        "findings_total": sum(findings.values()),
        "access_edges": edges[0] or 0,
        "effective_edges": edges[1] or 0,
        "unknown_origin_edges": edges[2] or 0,
        "keys": keys,
    }
