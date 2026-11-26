"""CLI commands besides scan: init-config, user, collector show, scans, export, diff, hostkey, db backup, synth."""

from __future__ import annotations

import json
import os
import sqlite3

import pytest
import yaml
from click.testing import CliRunner

from sshbite import db as dbm
from sshbite.cli import main
from sshbite.config import EXAMPLE_CONFIG
from sshbite.derive import derive_scan

from . import fixture_db as F


@pytest.fixture
def cfgfile(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"database": str(tmp_path / "data" / "s.db"), "entry": {"host": "jump"}}))
    return str(p)


def run(*args, input=None):
    return CliRunner().invoke(main, list(args), input=input, catch_exceptions=False)


def test_init_config_prints_example():
    r = run("init-config")
    assert r.exit_code == 0 and r.output == EXAMPLE_CONFIG


def test_user_add_passwd_remove(cfgfile, tmp_path, monkeypatch):
    from sshbite import cli as cli_mod

    monkeypatch.setattr(cli_mod, "_stdin_is_tty", lambda: True)   # the interactive prompt (S7: refused without a TTY)
    r = run("-c", cfgfile, "user", "add", "admin", input="short\nshort\n")
    assert r.exit_code != 0 and "at least 12" in r.output
    r = run("-c", cfgfile, "user", "add", "admin", input="correct horse battery\ncorrect horse battery\n")
    assert r.exit_code == 0, r.output
    c = sqlite3.connect(tmp_path / "data" / "s.db")
    h = c.execute("SELECT pw_hash FROM app_user WHERE username='admin'").fetchone()[0]
    assert h.startswith("$argon2id$")
    from sshbite.users import verify_password
    assert verify_password(h, "correct horse battery") and not verify_password(h, "wrong password!!")
    assert b"correct horse battery" not in (tmp_path / "data" / "s.db").read_bytes()
    r = run("-c", cfgfile, "user", "add", "admin", input="correct horse battery\ncorrect horse battery\n")
    assert r.exit_code != 0 and "exists" in r.output
    r = run("-c", cfgfile, "user", "add", "admin", input="correct horse battery\ndifferent password!\n")
    assert r.exit_code != 0
    c.execute("UPDATE app_user SET failed_logins=5, locked_until='2099-01-01T00:00:00Z'")
    c.commit()
    r = run("-c", cfgfile, "user", "passwd", "admin", input="another long password\nanother long password\n")
    assert r.exit_code == 0
    row = c.execute("SELECT pw_hash, failed_logins, locked_until FROM app_user").fetchone()
    assert row[0] != h and row[1] == 0 and row[2] is None
    assert run("-c", cfgfile, "user", "remove", "admin").exit_code == 0
    assert c.execute("SELECT count(*) FROM app_user").fetchone()[0] == 0
    assert run("-c", cfgfile, "user", "remove", "admin").exit_code != 0
    assert run("-c", cfgfile, "user", "add", "bad name", input="x" * 12 + "\n" + "x" * 12 + "\n").exit_code != 0


def test_collector_show():
    from sshbite import collector

    r = run("collector", "show")
    assert r.exit_code == 0
    assert f"collect.sh  sha256 {collector.sha256(collector.collect_script())}  lint: OK" in r.output
    assert f"resolve.sh  sha256 {collector.sha256(collector.resolve_script())}  lint: OK" in r.output
    assert collector.collect_script() in r.output and "sudo -S -k -p '' /bin/sh -s" in r.output


def test_scans_export_diff_backup(cfgfile, tmp_path):
    assert run("-c", cfgfile, "scans", "list").exit_code == 2   # no DB yet
    conn = dbm.connect(str(tmp_path / "data" / "s.db"))
    assert "No scans yet" in run("-c", cfgfile, "scans", "list").output
    s1, _ = F.build(conn, 1)
    derive_scan(conn, s1)
    s2, _ = F.build(conn, 2)
    derive_scan(conn, s2)
    r = run("-c", cfgfile, "scans", "list", "--json")
    assert [s["id"] for s in json.loads(r.output)] == [s1, s2]
    r = run("-c", cfgfile, "scans", "show", str(s1))
    assert r.exit_code == 0 and "unreachable" in r.output and "tried A -> E: timeout" in r.output
    d = json.loads(run("-c", cfgfile, "scans", "show", str(s1), "--json").output)
    assert {h["display_name"] for h in d["hosts"]} == {"A", "B", "C", "D", "E"}
    r = run("-c", cfgfile, "diff", str(s1), str(s2))
    assert "edges: 0 added, 1 removed" in r.output and "~ E (ok, root): status: unreachable -> ok" in r.output
    out = tmp_path / "f.csv"
    r = run("-c", cfgfile, "export", "--scan", "latest", "--what", "findings", "-o", str(out))
    assert r.exit_code == 0 and oct(os.stat(out).st_mode & 0o777) == "0o600"
    assert out.read_text().startswith("finding_id,scan_id,severity,rule,host")
    r = run("-c", cfgfile, "export", "--scan", "99", "--what", "keys")
    assert r.exit_code == 2
    bk = tmp_path / "backup.db"
    assert run("-c", cfgfile, "db", "backup", str(bk)).exit_code == 0
    assert sqlite3.connect(bk).execute("SELECT count(*) FROM scan").fetchone()[0] == 2
    assert oct(os.stat(bk).st_mode & 0o777) == "0o600"
    assert run("-c", cfgfile, "db", "backup", str(bk)).exit_code != 0
    r = run("-c", cfgfile, "scans", "delete", str(s1))
    assert r.exit_code == 0 and "deleted" in r.output
    assert conn.execute("SELECT count(*) FROM edge WHERE scan_id=?", (s1,)).fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM scan").fetchone()[0] == 1


def test_hostkey_commands(cfgfile, tmp_path):
    conn = dbm.connect(str(tmp_path / "data" / "s.db"))
    conn.execute("INSERT INTO trusted_hostkey(addr, port, alg, fp) VALUES ('10.0.0.9', 22, 'ssh-ed25519', 'SHA256:old')")
    sid = conn.execute("INSERT INTO scan(started_at, status) VALUES ('x','completed')").lastrowid
    hid = conn.execute("INSERT INTO host(identity, display_name) VALUES ('hk:SHA256:old', 'c2')").lastrowid
    conn.execute("INSERT INTO host_scan(scan_id, host_id, status, connect_addr, connect_port, error) VALUES (?,?,?,?,?,?)",
                 (sid, hid, "hostkey_mismatch", "10.0.0.9", 22,
                  "host key changed: offered ssh-ed25519 SHA256:new; trusted ssh-ed25519 SHA256:old"))
    assert "SHA256:old" in run("-c", cfgfile, "hostkey", "list").output
    r = run("-c", cfgfile, "hostkey", "accept", "10.0.0.9")
    assert r.exit_code == 0 and "SHA256:new  -> trusted" in r.output
    assert [tuple(r) for r in conn.execute("SELECT fp, accepted_at IS NOT NULL FROM trusted_hostkey")] == [("SHA256:new", 1)]
    r = run("-c", cfgfile, "hostkey", "forget", "10.0.0.9")
    assert "removed 1" in r.output


def test_synth_small(cfgfile, tmp_path):
    r = run("-c", cfgfile, "synth", "--hosts", "300", "--seed", "7")
    assert r.exit_code == 0, r.output
    c = sqlite3.connect(tmp_path / "data" / "s.db")
    assert c.execute("SELECT synthetic, status FROM scan").fetchone() == (1, "completed")
    assert c.execute("SELECT count(*) FROM host_scan").fetchone()[0] == 300
    assert c.execute("SELECT count(*) FROM host WHERE synthetic=1 AND display_name LIKE 'syn-%.synthetic.invalid'"
                     ).fetchone()[0] == 300
    assert c.execute("SELECT max(out_hosts) FROM host_metric").fetchone()[0] > 200


def test_dry_run_does_not_connect(cfgfile):
    r = run("-c", cfgfile, "scan", "--dry-run")
    assert r.exit_code == 0 and "entry:     jump:22" in r.output and "no connection made" in r.output


def test_synth_2000_matches_spec_and_derives_fast(tmp_path):
    """Spec 9.4: 40 /24 subnets, 15,000 authorized entries, fleet key on 1,200 hosts, 300 unknown-origin keys,
    hubs with more than 200 outbound edges; derivation < 60 s."""
    from sshbite.synth import synth

    conn = dbm.connect(str(tmp_path / "s.db"))
    res = synth(conn, 2000, 42)
    assert res["derive_s"] < 60
    q = lambda s: conn.execute(s).fetchone()[0]  # noqa: E731
    assert q("SELECT count(DISTINCT name) FROM host_group WHERE kind='subnet'") == 40
    assert q("SELECT count(*) FROM authorized_entry") == 15000
    assert q("SELECT count(DISTINCT host_id) FROM authorized_entry WHERE comment='fleet-deploy'") == 1200
    assert q("SELECT count(DISTINCT fp) FROM edge WHERE status='unknown_origin'") == 300
    assert q("SELECT count(*) FROM host_metric WHERE out_hosts > 200") >= 1
    assert q("SELECT synthetic FROM scan") == 1
    # deterministic for a seed
    again = synth(conn, 2000, 42)
    assert q(f"SELECT count(*) FROM edge WHERE scan_id={again['scan_id']}") == res["access_edges"] + \
        q(f"SELECT count(*) FROM edge WHERE scan_id={res['scan_id']} AND kind='evidence'")
