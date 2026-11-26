"""Transport against in-process asyncssh servers: pins, TOFU, strict, checked before auth, routes, cache."""

from __future__ import annotations

import asyncio

import asyncssh
import pytest

from sshbite import db as dbm
from sshbite.parse.keys import fingerprint
from sshbite.transport import Hop, HostKeyPolicy, RouteError, Transport, run

CLIENT_KEY = asyncssh.generate_private_key("ssh-ed25519")


class _Server(asyncssh.SSHServer):
    def __init__(self, log: list):
        self.log = log

    def connection_made(self, conn):
        self.log.append("connect")

    def begin_auth(self, username):
        self.log.append(f"begin_auth:{username}")
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        self.log.append("validate_public_key")
        return key.public_data == CLIENT_KEY.public_data and username == "sshbite"

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        self.log.append(f"direct-tcpip:{dest_host}:{dest_port}")
        return True


async def _handle(process):
    cmd = process.command or ""
    if cmd == "echo-stdin":
        data = await process.stdin.read()
        process.stdout.write(data)
    else:
        process.stdout.write(f"ran {cmd}\n")
    process.exit(0)


async def _start(host_key, log):
    server = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[host_key], process_factory=_handle,
                                   server_factory=lambda: _Server(log), allow_scp=False)
    port = server.sockets[0].getsockname()[1]
    return server, port


def _line(key) -> str:
    return key.export_public_key("openssh").decode().strip()


@pytest.fixture
def conn(tmp_path):
    return dbm.connect(str(tmp_path / "t.db"))


def _transport(policy, **kw) -> Transport:
    return Transport(user="sshbite", client_key=CLIENT_KEY, policy=policy, connect_timeout=5, **kw)


def test_entry_pin_matches_and_mismatch_never_authenticates(conn):
    async def go():
        hk = asyncssh.generate_private_key("ssh-ed25519")
        other = asyncssh.generate_private_key("ssh-ed25519")
        log: list = []
        server, port = await _start(hk, log)
        try:
            ok = _transport(HostKeyPolicy(conn, pins=[_line(hk)]))
            c = await ok.open_entry(Hop("entry", "127.0.0.1", port, role="entry"))
            r = await run(c, "hello")
            assert r.stdout == b"ran hello\n"
            await ok.close()
            assert "validate_public_key" in log

            log.clear()
            bad = _transport(HostKeyPolicy(conn, pins=[_line(other)]))
            with pytest.raises(RouteError) as ei:
                await bad.open_entry(Hop("entry", "127.0.0.1", port, role="entry"))
            assert ei.value.kind == "pin_mismatch"
            assert fingerprint(hk.public_data) in ei.value.detail["offered"]
            # the host key is checked during key exchange: no authentication request ever reached the server
            assert not [x for x in log if x.startswith(("begin_auth", "validate_public_key"))], log
        finally:
            server.close()
    asyncio.run(go())


def test_tofu_store_then_mismatch_blocks_auth(conn):
    async def go():
        k1 = asyncssh.generate_private_key("ssh-ed25519")
        log: list = []
        server, port = await _start(k1, log)
        try:
            pol = HostKeyPolicy(conn, mode="tofu", scan_id=None)
            tr = _transport(pol)
            # a target as entry-less direct hop: use role host via a direct connection (tunnel=None)
            c = await tr._connect_hop(Hop("t", "127.0.0.1", port), None)
            c.close()
            rows = conn.execute("SELECT alg, fp FROM trusted_hostkey").fetchall()
            assert [tuple(r) for r in rows] == [("ssh-ed25519", fingerprint(k1.public_data))]
        finally:
            server.close()
        # same address, new key
        k2 = asyncssh.generate_private_key("ssh-ed25519")
        log.clear()
        server2 = await asyncssh.listen("127.0.0.1", port, server_host_keys=[k2], process_factory=_handle,
                                        server_factory=lambda: _Server(log))
        try:
            tr = _transport(HostKeyPolicy(conn, mode="tofu"))
            with pytest.raises(RouteError) as ei:
                await tr._connect_hop(Hop("t", "127.0.0.1", port), None)
            assert ei.value.kind == "hostkey_mismatch"
            assert ei.value.detail["new"]["fp"] == fingerprint(k2.public_data)
            assert ei.value.detail["old"][0]["fp"] == fingerprint(k1.public_data)
            assert not [x for x in log if x.startswith(("begin_auth", "validate_public_key"))], log
        finally:
            server2.close()
    asyncio.run(go())


def test_strict_mode_unknown_key(conn, tmp_path):
    async def go():
        hk = asyncssh.generate_private_key("ssh-ed25519")
        log: list = []
        server, port = await _start(hk, log)
        try:
            known = f"[127.0.0.1]:{port} {_line(hk)}\n"
            tr = _transport(HostKeyPolicy(conn, mode="strict", known_hosts_text=known))
            c = await tr._connect_hop(Hop("t", "127.0.0.1", port), None)
            c.close()
            other = asyncssh.generate_private_key("ssh-ed25519")
            tr2 = _transport(HostKeyPolicy(conn, mode="strict", known_hosts_text=f"[127.0.0.1]:{port} {_line(other)}\n"))
            with pytest.raises(RouteError) as ei:
                await tr2._connect_hop(Hop("t", "127.0.0.1", port), None)
            assert ei.value.kind == "hostkey_unknown"
        finally:
            server.close()
    asyncio.run(go())


def test_routes_tunnel_through_hops_and_cache(conn):
    async def go():
        keys = [asyncssh.generate_private_key("ssh-ed25519") for _ in range(3)]
        logs = [[], [], []]
        started = [await _start(k, lg) for k, lg in zip(keys, logs)]
        (s0, p0), (s1, p1), (s2, p2) = started
        try:
            tr = _transport(HostKeyPolicy(conn, pins=[_line(keys[0])]), cache_size=1)
            entry = Hop("e", "127.0.0.1", p0, role="entry")
            await tr.open_entry(entry)
            h1, h2 = Hop("h1", "127.0.0.1", p1), Hop("h2", "127.0.0.1", p2)
            c1 = await tr.connect([entry, h1])
            assert (await run(c1, "x")).stdout == b"ran x\n"
            c2 = await tr.connect([entry, h1, h2])
            r = await run(c2, "echo-stdin", b"data\n")
            assert r.stdout == b"data\n"
            # the entry opened a direct-tcpip channel to h1, h1 one to h2: no ssh client ran on a hop
            assert f"direct-tcpip:127.0.0.1:{p1}" in logs[0]
            assert f"direct-tcpip:127.0.0.1:{p2}" in logs[1]
            # the hop connection is reused from the cache
            again = await tr.connect([entry, h1])
            assert again is c1
            tr.release([entry, h1]); tr.release([entry, h1]); tr.release([entry, h1, h2])
            await tr.close()
        finally:
            for s, _ in started:
                s.close()
    asyncio.run(go())


def test_network_errors_are_classified(conn):
    async def go():
        hk = asyncssh.generate_private_key("ssh-ed25519")
        log: list = []
        server, port = await _start(hk, log)
        try:
            tr = _transport(HostKeyPolicy(conn, pins=[_line(hk)]))
            entry = Hop("e", "127.0.0.1", port, role="entry")
            await tr.open_entry(entry)
            with pytest.raises(RouteError) as ei:   # nothing listens on port 1
                await tr.connect([entry, Hop("dead", "127.0.0.1", 1)])
            assert ei.value.kind == "network"
            assert ei.value.hop_key == ("127.0.0.1", 1)
            await tr.close()
        finally:
            server.close()
        with pytest.raises(RouteError) as ei:
            await _transport(HostKeyPolicy(conn, pins=[_line(hk)])).open_entry(entry)
        assert ei.value.kind == "network"
    asyncio.run(go())


def test_auth_failure_is_not_a_network_error(conn):
    async def go():
        hk = asyncssh.generate_private_key("ssh-ed25519")
        log: list = []
        server, port = await _start(hk, log)
        try:
            tr = Transport(user="nobody", client_key=CLIENT_KEY, policy=HostKeyPolicy(conn, pins=[_line(hk)]),
                           connect_timeout=5)
            with pytest.raises(RouteError) as ei:
                await tr.open_entry(Hop("e", "127.0.0.1", port, role="entry"))
            assert ei.value.kind == "auth"
        finally:
            server.close()
    asyncio.run(go())


def test_operator_ssh_config_is_never_read(conn, tmp_path, monkeypatch):
    """A ProxyJump in ~/.ssh/config would break the connection if it were read (config=() would read it)."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "config").write_text("Host *\n    ProxyJump nonexistent.invalid\n    User evil\n    Port 1\n")
    monkeypatch.setenv("HOME", str(home))

    async def go():
        hk = asyncssh.generate_private_key("ssh-ed25519")
        log: list = []
        server, port = await _start(hk, log)
        try:
            tr = _transport(HostKeyPolicy(conn, pins=[_line(hk)]))
            c = await tr.open_entry(Hop("e", "127.0.0.1", port, role="entry"))
            assert (await run(c, "ok")).rc == 0
            assert "begin_auth:sshbite" in log
            await tr.close()
        finally:
            server.close()
    asyncio.run(go())


def test_output_limit_truncates(conn):
    async def go():
        hk = asyncssh.generate_private_key("ssh-ed25519")
        log: list = []
        server, port = await _start(hk, log)
        try:
            tr = _transport(HostKeyPolicy(conn, pins=[_line(hk)]))
            c = await tr.open_entry(Hop("e", "127.0.0.1", port, role="entry"))
            r = await run(c, "echo-stdin", b"x" * 5000, max_bytes=1000)
            assert r.truncated and len(r.stdout) == 1000
            await tr.close()
        finally:
            server.close()
    asyncio.run(go())
