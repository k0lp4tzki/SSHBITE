"""SSH transport (spec 3.4): pinned entry, TOFU/strict host keys, routes through hops, hop cache.

Every connection uses only the audit account and key. The operator's ssh config,
known_hosts and agent are never used; tunnels are asyncssh direct-tcpip channels,
so no ssh client runs on any hop. Host keys are checked in
SSHClient.validate_host_public_key, which asyncssh calls during key exchange,
i.e. before any authentication request is sent.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections import OrderedDict
from dataclasses import dataclass, field

import asyncssh

from .db import utcnow
from .parse import known_hosts as kh
from .parse.keys import fingerprint, parse_public_key_line

log = logging.getLogger("sshbite.transport")

PLAIN_HOST_KEY_ALGS = {
    "ssh-ed25519": ["ssh-ed25519"],
    "ecdsa-sha2-nistp256": ["ecdsa-sha2-nistp256"],
    "ecdsa-sha2-nistp384": ["ecdsa-sha2-nistp384"],
    "ecdsa-sha2-nistp521": ["ecdsa-sha2-nistp521"],
    "ssh-rsa": ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
    "ssh-dss": ["ssh-dss"],
    "sk-ssh-ed25519@openssh.com": ["sk-ssh-ed25519@openssh.com"],
    "sk-ecdsa-sha2-nistp256@openssh.com": ["sk-ecdsa-sha2-nistp256@openssh.com"],
}
DEFAULT_HOST_KEY_ALGS = [a for algs in PLAIN_HOST_KEY_ALGS.values() for a in algs]


def host_key_algs_for(algs: list[str]) -> list[str]:
    out: list[str] = []
    for a in algs:
        for x in PLAIN_HOST_KEY_ALGS.get(a, [a]):
            if x not in out:
                out.append(x)
    return out


def key_alg_fp(key: asyncssh.SSHKey) -> tuple[str, str]:
    return key.get_algorithm(), fingerprint(key.public_data)


# ---------------------------------------------------------------- errors

class RouteError(Exception):
    """A hop of a route failed. kind: network | auth | hostkey_mismatch | hostkey_unknown | pin_mismatch."""

    def __init__(self, kind: str, message: str, hop: str = "", detail: dict | None = None,
                 hop_key: tuple[str, int] | None = None):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.hop = hop
        self.detail = detail or {}
        self.hop_key = hop_key

    def __str__(self) -> str:
        return f"{self.hop}: {self.message}" if self.hop else self.message


# ---------------------------------------------------------------- host keys

@dataclass
class Verdict:
    ok: bool
    kind: str = "ok"          # ok | new | mismatch | unknown | pin_mismatch
    alg: str = ""
    fp: str = ""
    old: list[tuple[str, str]] = field(default_factory=list)


class HostKeyPolicy:
    """Decides on offered host keys: entry pins, TOFU store in the DB, or strict known_hosts."""

    def __init__(self, db: sqlite3.Connection | None, mode: str = "tofu", known_hosts_text: str | None = None,
                 pins: list[str] | None = None, scan_id: int | None = None):
        self.db = db
        self.mode = mode
        self.scan_id = scan_id
        self.pins: list[tuple[str, str]] = []
        for p in pins or []:
            k = parse_public_key_line(p)
            if k is not None:
                self.pins.append((k.info.blob_alg, k.fp))
        self.strict_entries = kh.parse(known_hosts_text) if known_hosts_text else []

    # algorithms we ask the server for, so that it presents a key we can judge
    def algs_for(self, role: str, addr: str, port: int) -> list[str]:
        if role == "entry":
            return host_key_algs_for([a for a, _ in self.pins]) or DEFAULT_HOST_KEY_ALGS
        if self.mode == "tofu" and self.db is not None:
            rows = self.db.execute("SELECT alg FROM trusted_hostkey WHERE addr=? AND port=?", (addr, port)).fetchall()
            if rows:
                return host_key_algs_for(sorted({r[0] for r in rows}, key=_alg_pref))
        return DEFAULT_HOST_KEY_ALGS

    def verify(self, role: str, addr: str, port: int, names: list[str], key: asyncssh.SSHKey) -> Verdict:
        alg, fp = key_alg_fp(key)
        if role == "entry":
            if (alg, fp) in self.pins:
                return Verdict(True, "ok", alg, fp)
            return Verdict(False, "pin_mismatch", alg, fp, old=list(self.pins))
        if self.mode == "strict":
            cands = list(dict.fromkeys([addr] + list(names)))
            for e in self.strict_entries:
                if e.key is None or e.marker:
                    continue
                if e.key.info.blob_alg == alg and e.key.fp == fp and kh.entry_matches_host(e, cands, port):
                    return Verdict(True, "ok", alg, fp)
            return Verdict(False, "unknown", alg, fp)
        # TOFU
        assert self.db is not None
        rows = self.db.execute("SELECT alg, fp FROM trusted_hostkey WHERE addr=? AND port=?", (addr, port)).fetchall()
        if not rows:
            self.db.execute(
                "INSERT INTO trusted_hostkey(addr, port, alg, fp, first_seen_scan, accepted_at) VALUES (?,?,?,?,?,?)",
                (addr, port, alg, fp, self.scan_id, utcnow()))
            return Verdict(True, "new", alg, fp)
        for r in rows:
            if r[0] == alg and r[1] == fp:
                return Verdict(True, "ok", alg, fp)
        return Verdict(False, "mismatch", alg, fp, old=[(r[0], r[1]) for r in rows])

    def known_fps(self, addr: str, port: int) -> list[tuple[str, str]]:
        if self.db is None:
            return []
        return [(r[0], r[1]) for r in
                self.db.execute("SELECT alg, fp FROM trusted_hostkey WHERE addr=? AND port=?", (addr, port))]


def _alg_pref(alg: str) -> int:
    if "ed25519" in alg:
        return 0
    if alg.startswith("ecdsa") or "ecdsa" in alg:
        return 1
    if alg == "ssh-rsa":
        return 2
    return 3


class _Client(asyncssh.SSHClient):
    def __init__(self, check):
        self._check = check
        self.verdict: Verdict | None = None

    def validate_host_public_key(self, host, addr, port, key):  # called during key exchange
        self.verdict = self._check(key)
        return self.verdict.ok


# ---------------------------------------------------------------- routes

@dataclass(frozen=True)
class Hop:
    name: str          # display name, used in recorded routes
    addr: str          # address to connect to (from the previous hop)
    port: int
    names: tuple[str, ...] = ()  # names/addresses for strict mode lookup
    role: str = "host"           # entry | host

    @property
    def key(self) -> tuple[str, int]:
        return (self.addr, self.port)


@dataclass
class _Cached:
    conn: asyncssh.SSHClientConnection
    users: int = 0
    parent: tuple | None = None


def classify_exception(exc: BaseException) -> tuple[str, str]:
    """Map a connect exception to (kind, message). kind: network | auth | hostkey | other."""
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return "network", "timeout"
    if isinstance(exc, asyncssh.PermissionDenied):
        return "auth", f"authentication failed: {exc.reason}"
    if isinstance(exc, asyncssh.HostKeyNotVerifiable):
        return "hostkey", "host key not verifiable"
    if isinstance(exc, asyncssh.ChannelOpenError):
        return "network", f"channel open failed: {exc.reason}"
    if isinstance(exc, asyncssh.KeyExchangeFailed):
        return "hostkey_alg", f"key exchange failed: {exc.reason}"
    if isinstance(exc, asyncssh.DisconnectError):
        return "network", f"disconnected: {exc.reason}"
    if isinstance(exc, asyncssh.ConnectionLost):
        return "network", "connection lost"
    if isinstance(exc, ConnectionRefusedError):
        return "network", "connection refused"
    if isinstance(exc, OSError):
        return "network", (exc.strerror or str(exc) or exc.__class__.__name__)
    return "other", f"{exc.__class__.__name__}: {exc}"


class Transport:
    def __init__(self, *, user: str, client_key, policy: HostKeyPolicy, connect_timeout: float = 10,
                 entry_connections: int = 4, cache_size: int = 50):
        self.user = user
        self.client_key = client_key
        self.policy = policy
        self.connect_timeout = connect_timeout
        self.entry_connections = max(1, entry_connections)
        self.cache_size = cache_size
        self._entry_pool: list[asyncssh.SSHClientConnection] = []
        self._entry_hop: Hop | None = None
        self._rr = 0
        self._cache: OrderedDict[tuple, _Cached] = OrderedDict()
        self._locks: dict[tuple, asyncio.Lock] = {}

    def _options(self, hop: Hop) -> dict:
        return dict(
            username=self.user,
            client_keys=[self.client_key],
            agent_path=None,
            agent_forwarding=False,
            x11_forwarding=False,
            config=None,              # never read the operator's ssh config (() would load ~/.ssh/config)
            known_hosts=([], [], []),  # empty trust lists: every key goes to validate_host_public_key
            server_host_key_algs=self.policy.algs_for(hop.role, hop.addr, hop.port),
            preferred_auth=["publickey"],
            password=None,
            kbdint_auth=False,
            gss_host=None,
            host_based_auth=False,
            client_host_keys=None,
            ignore_encrypted=True,
            keepalive_interval=15,
            connect_timeout=self.connect_timeout,
            request_pty=False,
        )

    async def _connect_hop(self, hop: Hop, tunnel) -> asyncssh.SSHClientConnection:
        try:
            return await self._connect_hop_inner(hop, tunnel)
        except RouteError as exc:
            exc.hop_key = hop.key
            raise

    async def _connect_hop_inner(self, hop: Hop, tunnel) -> asyncssh.SSHClientConnection:
        client = _Client(lambda key: self.policy.verify(hop.role, hop.addr, hop.port, list(hop.names), key))
        try:
            conn, _ = await asyncio.wait_for(
                asyncssh.create_connection(lambda: client, hop.addr, hop.port, tunnel=tunnel or (),
                                           **self._options(hop)),
                timeout=self.connect_timeout)
            return conn
        except BaseException as exc:
            if isinstance(exc, asyncio.CancelledError):
                raise
            kind, msg = classify_exception(exc)
            v = client.verdict
            if v is not None and not v.ok:
                if v.kind == "pin_mismatch":
                    raise RouteError("pin_mismatch", "ENTRY HOST KEY MISMATCH", hop.name,
                                     {"offered": f"{v.alg} {v.fp}", "pinned": [f"{a} {f}" for a, f in v.old]}) from None
                if v.kind == "mismatch":
                    trusted = ", ".join(f"{a} {f}" for a, f in v.old)
                    raise RouteError("hostkey_mismatch", f"host key changed: offered {v.alg} {v.fp}; trusted {trusted}",
                                     hop.name,
                                     {"new": {"alg": v.alg, "fp": v.fp},
                                      "old": [{"alg": a, "fp": f} for a, f in v.old]}) from None
                raise RouteError("hostkey_unknown", f"host key {v.alg} {v.fp} not in known_hosts_file", hop.name,
                                 {"new": {"alg": v.alg, "fp": v.fp}}) from None
            if kind == "hostkey_alg":
                if hop.role == "entry":
                    raise RouteError("pin_mismatch", "ENTRY HOST KEY MISMATCH (no pinned algorithm offered)", hop.name,
                                     {"offered": "", "pinned": [f"{a} {f}" for a, f in self.policy.pins]}) from None
                old = self.policy.known_fps(hop.addr, hop.port)
                if old and self.policy.mode == "tofu":
                    raise RouteError("hostkey_mismatch", "host no longer offers a trusted host key algorithm",
                                     hop.name, {"new": None, "old": [{"alg": a, "fp": f} for a, f in old]}) from None
                kind = "network"
            if kind == "hostkey":
                kind = "network"
            raise RouteError(kind, msg, hop.name) from None

    # ---- entry ----------------------------------------------------------------
    async def open_entry(self, hop: Hop) -> asyncssh.SSHClientConnection:
        """Open the entry connection pool. Raises RouteError (pin_mismatch, auth, network)."""
        self._entry_hop = hop
        first = await self._connect_hop(hop, None)
        self._entry_pool = [first]
        return first

    async def _entry_conn(self) -> asyncssh.SSHClientConnection:
        assert self._entry_hop is not None
        # grow the pool lazily up to entry_connections; tunnels are multiplexed over these
        if len(self._entry_pool) < self.entry_connections:
            try:
                self._entry_pool.append(await self._connect_hop(self._entry_hop, None))
            except RouteError as exc:
                log.debug("extra entry connection failed: %s", exc)
        self._rr = (self._rr + 1) % len(self._entry_pool)
        return self._entry_pool[self._rr]

    @property
    def entry(self) -> asyncssh.SSHClientConnection:
        return self._entry_pool[0]

    # ---- routes ---------------------------------------------------------------
    async def connect(self, route: list[Hop]) -> asyncssh.SSHClientConnection:
        """Connect along route = [entry, hop1, ..., target]. Intermediate hops come from the LRU cache.
        The returned connection is held (release() it when done)."""
        assert route and route[0].role == "entry"
        if len(route) == 1:
            return self.entry
        key = tuple(h.key for h in route)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            cached = self._cache.get(key)
            if cached is not None and not _closed(cached.conn):
                self._cache.move_to_end(key)
                cached.users += 1
                return cached.conn
            if len(route) == 2:
                tunnel = await self._entry_conn()
                parent_key = None
            else:
                tunnel = await self.connect(route[:-1])
                parent_key = tuple(h.key for h in route[:-1])
            try:
                conn = await self._connect_hop(route[-1], tunnel)
            except BaseException:
                if parent_key is not None:
                    self.release(route[:-1])
                raise
            self._cache[key] = _Cached(conn=conn, users=1, parent=parent_key)
            self._evict()
            return conn

    def release(self, route: list[Hop]) -> None:
        if len(route) <= 1:
            return
        key = tuple(h.key for h in route)
        c = self._cache.get(key)
        if c is not None and c.users > 0:
            c.users -= 1

    def _evict(self) -> None:
        if len(self._cache) <= self.cache_size:
            return
        parents = {c.parent for c in self._cache.values() if c.parent}
        for key in list(self._cache.keys()):
            if len(self._cache) <= self.cache_size:
                break
            c = self._cache[key]
            if c.users > 0 or key in parents:
                continue
            del self._cache[key]
            c.conn.close()
            if c.parent and c.parent in self._cache:
                self._cache[c.parent].users = max(0, self._cache[c.parent].users - 1)

    async def close(self) -> None:
        for c in reversed(list(self._cache.values())):
            c.conn.close()
        self._cache.clear()
        for conn in self._entry_pool:
            conn.close()
        self._entry_pool = []


def _closed(conn) -> bool:
    return getattr(conn, "_transport", None) is None


# ---------------------------------------------------------------- remote execution

@dataclass
class ExecResult:
    rc: int | None
    stdout: bytes
    stderr: str
    truncated: bool = False


async def run(conn: asyncssh.SSHClientConnection, command: str, stdin: bytes | None = None,
              max_bytes: int = 32 * 1024 * 1024, max_stderr: int = 65536) -> ExecResult:
    """Run a fixed command on an exec channel, feed stdin then EOF, read stdout up to max_bytes."""
    proc = await conn.create_process(command, encoding=None, request_pty=False)
    try:
        if stdin:
            proc.stdin.write(stdin)
        proc.stdin.write_eof()

        out = bytearray()
        err = bytearray()
        truncated = False

        async def read_err():
            while True:
                chunk = await proc.stderr.read(8192)
                if not chunk:
                    return
                if len(err) < max_stderr:
                    err.extend(chunk[: max_stderr - len(err)])

        err_task = asyncio.create_task(read_err())
        while True:
            chunk = await proc.stdout.read(65536)
            if not chunk:
                break
            room = max_bytes - len(out)
            if len(chunk) > room:
                out.extend(chunk[:max(room, 0)])
                truncated = True
                break
            out.extend(chunk)
        if truncated:
            proc.close()
            err_task.cancel()
            return ExecResult(None, bytes(out), err.decode("utf-8", "replace"), True)
        await err_task
        await proc.wait_closed()
        return ExecResult(proc.exit_status, bytes(out), err.decode("utf-8", "replace"), False)
    finally:
        proc.close()
