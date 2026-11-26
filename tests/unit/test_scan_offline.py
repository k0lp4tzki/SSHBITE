"""A full scan (crawl, store, derive) against an in-process SSH server that plays a sudo-protected host.

The fake sudo deliberately echoes the password into stderr to prove that redaction holds: the sudo
password must never appear in captured logs (even at -vv) or in the bytes of the DB files (spec 9.1).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import threading

import asyncssh
import pytest
import yaml
from click.testing import CliRunner

from sshbite import collector
from sshbite.cli import main

from .conftest import FIX

PASSWORD = "s3cr3t-Sudo-PW-4711"


def _fixture_output(name: str) -> bytes:
    text = (FIX / name).read_text()
    first, rest = text.split("\n", 1)
    return (f"#SSHBITE 1 {collector.declared_sha_short(collector.collect_script())}\n" + rest).encode()


ROOT_OUT = _fixture_output("collect_a1_root.txt")
UNPRIV_OUT = _fixture_output("collect_b5_unprivileged.txt")


def make_handler(mode: str, seen: list):
    async def handle(process):
        cmd = process.command or ""
        seen.append(cmd)
        data = await process.stdin.read() if cmd.endswith("-s") or "-S" in cmd else ""
        if cmd == "sudo -n /bin/true":
            if mode == "nopasswd":
                process.exit(0)
            else:
                process.stderr.write("sudo: a password is required\n")
                process.exit(1)
            return
        if cmd == "sudo -n /bin/sh -s":
            if mode not in ("nopasswd", "sh_nopasswd"):
                process.stderr.write("sudo: a password is required\n")
                process.exit(1)
                return
            process.stdout.write(ROOT_OUT.decode())
            process.exit(0)
            return
        if cmd == "sudo -S -k -p '' /bin/true":
            first = data.split("\n", 1)[0]
            if first == PASSWORD:
                process.stderr.write(f"debug: misbehaving sudo echoes {first}\n")
                process.exit(0)
            else:
                process.stderr.write(f"Sorry, try again. (got {first})\nsudo: 1 incorrect password attempt\n")
                process.exit(1)
            return
        if cmd == "sudo -S -k -p '' /bin/sh -s":
            first, script = data.split("\n", 1)
            assert first == PASSWORD and script.startswith("LC_ALL=C;")
            process.stderr.write(f"warning: the password was {first}\n")
            process.stdout.write(ROOT_OUT.decode())
            process.exit(0)
            return
        if cmd == "/bin/sh -s":
            process.stdout.write(UNPRIV_OUT.decode())
            process.exit(0)
            return
        process.exit(0)   # resolve command: nothing resolves
    return handle


class _Srv(asyncssh.SSHServer):
    def __init__(self, pub):
        self.pub = pub

    def begin_auth(self, username):
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return username == "sshbite" and key.public_data == self.pub


class ServerThread:
    """Runs the fake host in its own event loop thread so the CLI can use asyncio.run()."""

    def __init__(self, mode: str, client_pub: bytes):
        self.mode = mode
        self.client_pub = client_pub
        self.seen: list = []
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        asyncio.set_event_loop(self.loop)

        async def start():
            self.server = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[self.host_key],
                                                process_factory=make_handler(self.mode, self.seen),
                                                server_factory=lambda: _Srv(self.client_pub))
            self.port = self.server.sockets[0].getsockname()[1]
            self.ready.set()
        self.loop.run_until_complete(start())
        self.loop.run_forever()

    def __enter__(self):
        self.thread.start()
        self.ready.wait(10)
        return self

    def __exit__(self, *a):
        self.loop.call_soon_threadsafe(self.server.close)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


@pytest.fixture
def audit(tmp_path):
    k = asyncssh.generate_private_key("ssh-ed25519")
    p = tmp_path / "audit_ed25519"
    p.write_bytes(k.export_private_key())
    os.chmod(p, 0o600)
    return k, p


def _config(tmp_path, srv: ServerThread, key_path) -> str:
    cfg = {
        "database": str(tmp_path / "data" / "sshbite.db"),
        "entry": {"host": "127.0.0.1", "port": srv.port,
                  "host_keys": [srv.host_key.export_public_key("openssh").decode().strip()]},
        "audit": {"key_file": str(key_path)},
        "limits": {"connect_timeout": 5},
    }
    p = tmp_path / "sshbite.yaml"
    p.write_text(yaml.safe_dump(cfg))
    os.chmod(p, 0o600)
    return str(p)


def _db_bytes(tmp_path) -> bytes:
    out = b""
    for f in (tmp_path / "data").iterdir():
        out += f.read_bytes()
    return out


def test_password_never_in_logs_or_db(tmp_path, audit, caplog):
    key, kp = audit
    with ServerThread("password", key.public_data) as srv:
        cfg = _config(tmp_path, srv, kp)
        caplog.set_level(logging.DEBUG)
        runner = CliRunner()
        r = runner.invoke(main, ["-vv", "-c", cfg, "scan", "--no-crawl"], env={"SSHBITE_SUDO_PASSWORD": PASSWORD},
                          catch_exceptions=False)
        assert r.exit_code == 0, r.output
        assert "sudo -S -k -p '' /bin/sh -s" in srv.seen
    out = r.output + (r.stderr if hasattr(r, "stderr") and r.stderr_bytes is not None else "")
    assert PASSWORD not in out
    assert "sudo -S -k -p" in caplog.text or "asyncssh" in caplog.text or len(caplog.records) > 10, "no logs captured"
    assert PASSWORD not in caplog.text
    assert PASSWORD.encode() not in _db_bytes(tmp_path)
    c = sqlite3.connect(tmp_path / "data" / "sshbite.db")
    row = c.execute("SELECT status, privilege FROM host_scan").fetchone()
    assert tuple(row) == ("ok", "sudo_password")
    assert c.execute("SELECT count(*) FROM authorized_entry").fetchone()[0] > 0
    assert oct(os.stat(tmp_path / "data" / "sshbite.db").st_mode & 0o777) == "0o600"
    assert oct(os.stat(tmp_path / "data").st_mode & 0o777) == "0o700"


def test_wrong_password_is_redacted_in_reasons(tmp_path, audit):
    key, kp = audit
    with ServerThread("password", key.public_data) as srv:
        cfg = _config(tmp_path, srv, kp)
        r = CliRunner().invoke(main, ["-c", cfg, "scan", "--no-crawl"], env={"SSHBITE_SUDO_PASSWORD": "wrong-" + PASSWORD})
        assert r.exit_code == 0, r.output
    c = sqlite3.connect(tmp_path / "data" / "sshbite.db")
    st, priv, reasons = c.execute("SELECT status, privilege, partial_reasons FROM host_scan").fetchone()
    assert (st, priv) == ("partial", "unprivileged")
    assert "sudo password not accepted" in reasons and "[REDACTED]" in reasons
    assert PASSWORD.encode() not in _db_bytes(tmp_path)


def test_needs_password_summary_and_partial(tmp_path, audit):
    key, kp = audit
    with ServerThread("password", key.public_data) as srv:
        cfg = _config(tmp_path, srv, kp)
        r = CliRunner().invoke(main, ["-c", cfg, "scan", "--no-crawl"], env={"SSHBITE_SUDO_PASSWORD": ""})
        assert r.exit_code == 0, r.output
        assert "1 host needs a sudo password: rerun with --ask-sudo-password" in r.output
        assert "sudo -S -k -p '' /bin/true" not in srv.seen
    c = sqlite3.connect(tmp_path / "data" / "sshbite.db")
    assert c.execute("SELECT status, privilege FROM host_scan").fetchone() == ("partial", "unprivileged")
    assert c.execute("SELECT count(*) FROM finding WHERE rule='partial_scan'").fetchone()[0] == 1


def test_nopasswd_root_and_summary(tmp_path, audit):
    key, kp = audit
    with ServerThread("nopasswd", key.public_data) as srv:
        cfg = _config(tmp_path, srv, kp)
        r = CliRunner().invoke(main, ["-c", cfg, "scan", "--no-crawl", "--label", "t1"])
        assert r.exit_code == 0, r.output
        assert "scan 1 completed" in r.output and "scan id:  1" in r.output
        assert "depth 0:" in r.output
        assert srv.seen[:2] == ["sudo -n /bin/true", "sudo -n /bin/sh -s"]
        # entry failure: wrong pin -> exit 3, aborted scan, no host rows
        bad = yaml.safe_load(open(cfg))
        bad["entry"]["host_keys"] = [asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode()]
        bad["database"] = str(tmp_path / "data" / "bad.db")
        open(cfg, "w").write(yaml.safe_dump(bad))
        r = CliRunner().invoke(main, ["-c", cfg, "scan"])
        assert r.exit_code == 3 and "ENTRY HOST KEY MISMATCH" in r.output
    c = sqlite3.connect(tmp_path / "data" / "bad.db")
    assert c.execute("SELECT status FROM scan").fetchall() == [("aborted",)]
    assert c.execute("SELECT count(*) FROM host_scan").fetchone()[0] == 0


def test_unreachable_entry_exit_3_and_lock(tmp_path, audit):
    key, kp = audit
    cfg = {"database": str(tmp_path / "data" / "s.db"),
           "entry": {"host": "127.0.0.1", "port": 1,
                     "host_keys": [asyncssh.generate_private_key("ssh-ed25519").export_public_key("openssh").decode()]},
           "audit": {"key_file": str(kp)}}
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    r = CliRunner().invoke(main, ["-c", str(p), "scan"])
    assert r.exit_code == 3, r.output
    c = sqlite3.connect(tmp_path / "data" / "s.db")
    assert c.execute("SELECT status FROM scan").fetchall() == [("failed",)]
    # a live lock blocks (exit 5); a stale one is cleared and its scan marked failed
    c.execute("INSERT INTO scan_lock(id, pid, scan_id, started_at) VALUES (1, ?, NULL, 'x')", (os.getpid(),))
    c.commit()
    r = CliRunner().invoke(main, ["-c", str(p), "scan"])
    assert r.exit_code == 5, r.output
    c.execute("INSERT INTO scan(started_at, status) VALUES ('x', 'running')")
    c.execute("UPDATE scan_lock SET pid=999999, scan_id=2")
    c.commit()
    r = CliRunner().invoke(main, ["-c", str(p), "scan"])
    assert r.exit_code == 3
    assert c.execute("SELECT status FROM scan WHERE id=2").fetchone()[0] == "failed"
    assert c.execute("SELECT count(*) FROM scan_lock").fetchone()[0] == 0


def test_audit_key_must_be_0600(tmp_path, audit):
    key, kp = audit
    os.chmod(kp, 0o644)
    cfg = {"database": str(tmp_path / "s.db"), "entry": {"host": "127.0.0.1", "host_keys": []},
           "audit": {"key_file": str(kp)}}
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    r = CliRunner().invoke(main, ["-c", str(p), "scan"])
    assert r.exit_code == 2 and str(kp) in r.output and "0600" in r.output
    r = CliRunner().invoke(main, ["-c", str(p), "config", "validate"])
    assert r.exit_code == 2 and str(kp) in r.output


def test_seeds_hosts_file_and_cidr_probe(tmp_path, audit):
    key, kp = audit
    with ServerThread("nopasswd", key.public_data) as srv:
        cfgp = _config(tmp_path, srv, kp)
        cfg = yaml.safe_load(open(cfgp))
        hf = tmp_path / "hosts"
        hf.write_text("# extra seeds\n192.0.2.10\n")
        cfg["seeds"] = {"hosts_file": str(hf), "cidrs": ["198.51.100.7/32"]}
        open(cfgp, "w").write(yaml.safe_dump(cfg))
        r = CliRunner().invoke(main, ["-c", cfgp, "scan", "--no-crawl"])
        assert r.exit_code == 0, r.output
        d = CliRunner().invoke(main, ["-c", cfgp, "scan", "--dry-run"])
        assert "192.0.2.10:22  (hosts_file)" in d.output and "198.51.100.7:22  (cidr, probe)" in d.output
    c = sqlite3.connect(tmp_path / "data" / "sshbite.db")
    rows = {r[0]: r[1:] for r in c.execute(
        "SELECT hs.connect_addr, hs.status, hs.seed_source, hs.depth FROM host_scan hs")}
    # the seed is depth 0; the fake entry refuses direct-tcpip, so it is unreachable via [entry, seed]
    assert rows["192.0.2.10"] == ("unreachable", "seed:hosts_file", 0)
    # the CIDR address did not answer the TCP probe through the entry: no_ssh, never connected to
    assert rows["198.51.100.7"] == ("no_ssh", "seed:cidr", 0)


def test_nopasswd_only_for_sh_never_sends_the_password(tmp_path, audit):
    """sudoers wants a password for /bin/true but has NOPASSWD for /bin/sh: the password line must not be sent,
    or the root shell would run it as a command."""
    key, kp = audit
    with ServerThread("sh_nopasswd", key.public_data) as srv:
        cfg = _config(tmp_path, srv, kp)
        r = CliRunner().invoke(main, ["-c", cfg, "scan", "--no-crawl"], env={"SSHBITE_SUDO_PASSWORD": PASSWORD})
        assert r.exit_code == 0, r.output
        assert not [c for c in srv.seen if "-S" in c]
    c = sqlite3.connect(tmp_path / "data" / "sshbite.db")
    assert c.execute("SELECT status, privilege FROM host_scan").fetchone() == ("ok", "root")
