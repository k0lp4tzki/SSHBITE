"""End-to-end assertions of spec 9.3 against the lab: real OpenSSH servers behind a jump host.

Every scan is bracketed by a read-only snapshot of /etc, /root and /home of all 13 lab hosts; the
snapshots before and after must be byte-identical. The test's own lab changes happen outside the
brackets. Set SSHBITE_EVIDENCE_DIR to keep the console transcripts and exports of the run.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import subprocess
from collections import Counter
from pathlib import Path

import pytest
import yaml

from . import lab as L

pytestmark = pytest.mark.e2e

EXP = L.expected()
S1 = EXP["scan1"]


# ---------------------------------------------------------------- fixtures

@pytest.fixture(scope="module")
def entry():
    e = L.find_entry()
    if e is None:
        pytest.skip("lab unavailable: need docker, podman or root")
    return e


@pytest.fixture(scope="module")
def ctl(entry):
    return L.LabControl(EXP["hosts"])


@pytest.fixture(scope="module")
def evidence():
    d = os.environ.get("SSHBITE_EVIDENCE_DIR")
    if not d:
        return None
    p = Path(d)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _write(evidence, name: str, text: str) -> None:
    if evidence is not None:
        (evidence / name).write_text(text)


@pytest.fixture(scope="module")
def cfg(entry, tmp_path_factory):
    host, port = entry
    env = dict(os.environ, LAB_NO_START="1", LAB_ENTRY_HOST=host, LAB_ENTRY_PORT=str(port))
    subprocess.run(["sh", str(L.LAB / "up.sh")], check=True, env=env, capture_output=True)
    data = yaml.safe_load((L.LAB / "sshbite.lab.yaml").read_text())
    d = tmp_path_factory.mktemp("e2e")
    data["database"] = str(d / "sshbite.db")
    path = d / "sshbite.yaml"
    path.write_text(yaml.safe_dump(data))
    path.chmod(0o600)
    wrong = dict(data)
    wrong["entry"] = dict(data["entry"])
    wrong["entry"]["host_keys"] = [(L.KEYS / "a1_host_ed25519.pub").read_text().split(" ")[0] + " " +
                                   (L.KEYS / "a1_host_ed25519.pub").read_text().split(" ")[1]]
    wrong["database"] = str(d / "pin.db")
    wpath = d / "wrong-pin.yaml"
    wpath.write_text(yaml.safe_dump(wrong))
    wpath.chmod(0o600)
    return {"path": path, "db": Path(data["database"]), "wrong": wpath, "wrong_db": Path(wrong["database"])}


@pytest.fixture(scope="module")
def state():
    return {}


def _db(cfg) -> sqlite3.Connection:
    c = sqlite3.connect(cfg["db"])
    c.row_factory = sqlite3.Row
    return c


FP = {name: L.key_fp(f) for name, f in EXP["keys"].items()}
_SNAPSHOTS: list[tuple[str, dict, dict]] = []


def _scan_bracketed(ctl, cfg, label: str, evidence, env: dict | None = None, config_key: str = "path"):
    """Snapshot all hosts, run the scan, snapshot again; return (process, snapshot diff)."""
    before = ctl.snapshot_all()
    for h, text in before.items():  # the snapshot really covers the files a scan reads
        assert "/etc/ssh/sshd_config " in text and "/home/sshbite/.ssh/authorized_keys" in text, h
    proc = L.sshbite(cfg[config_key], "scan", "--label", label, env=env)
    after = ctl.snapshot_all()
    _SNAPSHOTS.append((label, before, after))
    diff = L.snapshot_diff(before, after)
    _write(evidence, f"snapshot-{label}.diff", diff)
    _write(evidence, f"snapshot-{label}-before.txt",
           "\n".join(f"### {h}\n{before[h]}" for h in sorted(before)))
    return proc, diff


def _host_rows(conn, sid) -> dict[str, sqlite3.Row]:
    out = {}
    for r in conn.execute("SELECT hs.*, h.display_name FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=?",
                          (sid,)):
        out[r["display_name"]] = r
    return out


def _via(conn, ref_id) -> tuple[str, str] | None:
    if ref_id is None:
        return None
    r = conn.execute("SELECT h.display_name, r.file, r.line_no, r.source FROM reference r JOIN host h ON h.id=r.from_host_id"
                     " WHERE r.id=?", (ref_id,)).fetchone()
    return f"{r[0]} {r[1]}:{r[2]}", r[3]


def _hostname(conn, hid) -> str:
    return conn.execute("SELECT display_name FROM host WHERE id=?", (hid,)).fetchone()[0]


def _edges(conn, sid, kind="access") -> list[dict]:
    out = []
    for r in conn.execute("SELECT * FROM edge WHERE scan_id=? AND kind=?", (sid, kind)):
        src = "unknown" if r["src_host_id"] is None else f"{_hostname(conn, r['src_host_id'])}:{r['src_user'] or ''}"
        dst = f"{_hostname(conn, r['dst_host_id'])}:{r['dst_user'] or ''}" if kind == "access" else \
            _hostname(conn, r["dst_host_id"])
        out.append({"src": src, "dst": dst, "fp": r["fp"], "status": r["status"], "effective": r["effective"],
                    "flags": json.loads(r["flags"] or "[]")})
    return out


# ---------------------------------------------------------------- tests

def test_00_lab_reset_and_scripts(ctl, evidence):
    """Restore the lab's original state (the test may have run before), and record the collector review output."""
    for host in ("a5", "b2", "c2"):
        ctl.run(host, "labctl.sh", "reset")
    from sshbite import collector
    from sshbite.collector.lint import lint

    assert lint(collector.collect_script()) == []
    assert lint(collector.resolve_script()) == []


def test_00b_sshd_and_ssh_keygen_write_nothing(ctl, evidence):
    """Spec assumption: `sshd -T` and `ssh-keygen -y/-l` write nothing - checked on the whole root filesystem
    (mtime/ctime/size/mode of every path except /proc, /sys, /dev, /run, /var/log), not only /etc, /root, /home."""
    out = []
    for host, key in (("jump", "/home/ops/.ssh/id_ed25519"), ("a1", "/home/deploy/.ssh/id_rsa"),
                      ("b2", "/home/www/.ssh/backup_rsa")):
        res = ctl.run(host, "writecheck.sh", key)
        out.append(f"{host} ({key}): {res.strip()}")
        assert res.startswith("NO CHANGES"), (host, res)
    _write(evidence, "writecheck.txt", "\n".join(out) + "\n")


def test_01_pin_negative(ctl, cfg, evidence):
    """A wrong entry.host_keys gives exit 3 and no host_scan rows."""
    proc, diff = _scan_bracketed(ctl, cfg, "pin-negative", evidence, config_key="wrong")
    _write(evidence, "console-pin-negative.txt", proc.stdout + proc.stderr)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "ENTRY HOST KEY MISMATCH" in proc.stderr
    assert "SHA256:" in proc.stderr
    conn = sqlite3.connect(cfg["wrong_db"])
    assert conn.execute("SELECT count(*) FROM host_scan").fetchone()[0] == 0
    assert conn.execute("SELECT status FROM scan").fetchall() == [("aborted",)]
    assert diff == "", diff


def test_02_scan1_runs_read_only(ctl, cfg, state, evidence):
    proc, diff = _scan_bracketed(ctl, cfg, "scan1", evidence, env={"SSHBITE_SUDO_PASSWORD": "labsudo"})
    _write(evidence, "console-scan1.txt", "$ SSHBITE_SUDO_PASSWORD=*** sshbite scan --label scan1\n"
           + proc.stdout + proc.stderr)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "labsudo" not in proc.stdout + proc.stderr
    assert diff == "", "lab changed during scan 1:\n" + diff
    conn = _db(cfg)
    sid = conn.execute("SELECT max(id) FROM scan WHERE status='completed'").fetchone()[0]
    state["s1"] = sid
    # progress per depth and the end summary
    assert "depth 0:" in proc.stdout and "depth 4:" in proc.stdout
    assert f"scan id:  {sid}" in proc.stdout


def test_03_scan1_hosts(cfg, state):
    conn = _db(cfg)
    sid = state["s1"]
    rows = _host_rows(conn, sid)
    for name, (status, priv, depth, via, route) in S1["hosts"].items():
        r = rows.get(name)
        assert r is not None, f"{name} missing; have {sorted(rows)}"
        assert r["status"] == status, (name, r["status"])
        assert r["privilege"] == priv, (name, r["privilege"])
        assert r["depth"] == depth, (name, r["depth"])
        if via == "entry":
            assert r["seed_source"] == "entry" and r["discovered_via_ref"] is None
        else:
            assert _via(conn, r["discovered_via_ref"])[0] == via, (name, _via(conn, r["discovered_via_ref"]))
        assert (json.loads(r["route"]) if r["route"] else None) == route, (name, r["route"])
    assert _via(conn, rows["a2"]["discovered_via_ref"])[1] == S1["a2_discovered_source"]
    c1_attempts = [a["route"] for a in json.loads(rows["c1"]["route_attempts"]) if a["error"]]
    assert S1["c1_failed_attempt"] in c1_attempts
    u_attempts = [a["route"] for a in json.loads(rows["172.30.1.99"]["route_attempts"])]
    assert u_attempts == S1["unreachable_attempts"]
    assert all(a["error"] for a in json.loads(rows["172.30.1.99"]["route_attempts"]))
    # b5: partial with the sudo reason and the unreadable directories
    reasons = json.loads(rows["b5"]["partial_reasons"])
    assert any("password" in x for x in reasons) and "unreadable: /root/.ssh" in reasons
    # exactly 12 hosts connected through the entry (11 ok/partial + 1 unreachable), none collected twice
    connected = ("ok", "partial", "unreachable", "timeout", "auth_failed", "hostkey_mismatch", "hostkey_unknown",
                 "collector_error", "output_limit")
    via_entry = [n for n, r in rows.items() if r["status"] in connected and r["seed_source"] != "entry"]
    assert len(via_entry) == S1["connected_via_entry"], via_entry
    assert len([n for n in via_entry if rows[n]["status"] in ("ok", "partial")]) == S1["connected_ok_partial_via_entry"]
    hk = conn.execute("SELECT h.identity FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=?"
                      " AND hs.status IN ('ok','partial')", (sid,)).fetchall()
    assert len(hk) == len(set(hk)) == 12
    assert conn.execute("SELECT count(*) FROM host_scan WHERE scan_id=? AND status='alias'", (sid,)).fetchone()[0] == 0
    # unresolved hashed entries
    for name, n in S1["unresolved_hashed"].items():
        assert rows[name]["unresolved_hashed"] == n


def test_04_scan1_references(cfg, state):
    conn = _db(cfg)
    sid = state["s1"]
    refs = conn.execute("SELECT r.*, h.display_name AS src FROM reference r JOIN host h ON h.id=r.from_host_id"
                        " WHERE r.scan_id=?", (sid,)).fetchall()
    for value, outcome in S1["references"].items():
        got = {r["outcome"] for r in refs if r["value"] == value}
        assert got == {outcome}, (value, got)
    for src, value, of in S1["aliases"]:
        r = [r for r in refs if r["src"] == src and r["value"] == value]
        assert r and all(x["outcome"] == "alias" and _hostname(conn, x["target_host_id"]) == of for x in r), (src, value)
    for src, value in S1["already"]:
        r = [r for r in refs if r["src"] == src and r["value"] == value]
        assert r and all(x["outcome"] == "already" for x in r), (src, value, [x["outcome"] for x in r])
    # from= is a reference source but never an evidence edge
    assert any(r["source"] == "from_option" for r in refs)


def test_05_scan1_access_edges(cfg, state):
    conn = _db(cfg)
    edges = _edges(conn, state["s1"])
    exp = S1["access_edges"]
    assert len(edges) == exp["total"]
    assert sum(e["effective"] for e in edges) == exp["effective"]
    assert sum(1 for e in edges if e["src"] == "unknown") == exp["unknown_origin"]
    remaining = list(edges)
    for src, dst, key, status, flags, eff in exp["list"]:
        m = [e for e in remaining if e["src"] == src and e["dst"] == dst and e["fp"] == FP[key]]
        assert len(m) == 1, (src, dst, key, m)
        e = m[0]
        assert e["status"] == status, (src, dst, e["status"])
        assert set(flags) <= set(e["flags"]), (src, dst, e["flags"])
        assert e["effective"] == eff, (src, dst)
        remaining.remove(e)
    assert remaining == []
    for key in exp["no_edges_for"]:
        assert not [e for e in edges if e["fp"] == FP[key]], key


def test_06_scan1_evidence_edges(cfg, state):
    conn = _db(cfg)
    sid = state["s1"]
    rows = conn.execute(
        "SELECT hs.display_name AS src, e.src_user, hd.display_name AS dst, r.source FROM edge e"
        " JOIN host hs ON hs.id=e.src_host_id JOIN host hd ON hd.id=e.dst_host_id JOIN reference r ON r.id=e.reference_id"
        " WHERE e.scan_id=? AND e.kind='evidence'", (sid,)).fetchall()
    have = {(f"{r['src']}:{r['src_user'] or ''}", r["dst"], r["source"]) for r in rows}
    for src, dst, source in S1["evidence_edges"]:
        assert (src, dst, source) in have, (src, dst, source)
    assert not [r for r in rows if r["source"] == "from_option"]


def test_07_scan1_metrics(cfg, state):
    conn = _db(cfg)
    sid = state["s1"]
    m = {r["display_name"]: r for r in conn.execute(
        "SELECT m.*, h.display_name FROM host_metric m JOIN host h ON h.id=m.host_id WHERE m.scan_id=?", (sid,))}
    for col in ("out_hosts", "in_hosts", "in_unknown_keys"):
        for host, v in S1["metrics"][col].items():
            assert m[host][col] == v, (col, host, m[host][col])
    top_out = conn.execute("SELECT h.display_name FROM host_metric m JOIN host h ON h.id=m.host_id WHERE m.scan_id=?"
                           " ORDER BY m.out_hosts DESC LIMIT 1", (sid,)).fetchone()[0]
    top_in = conn.execute("SELECT h.display_name FROM host_metric m JOIN host h ON h.id=m.host_id WHERE m.scan_id=?"
                          " ORDER BY m.in_hosts DESC LIMIT 1", (sid,)).fetchone()[0]
    assert top_out == S1["metrics"]["top_outbound"]
    assert top_in == S1["metrics"]["top_inbound"]


def _finding_matches(conn, f, host, user, what) -> bool:
    if host is not None and (f["host_id"] is None or _hostname(conn, f["host_id"]) != host):
        return False
    if host is None and f["host_id"] is not None:
        return False
    if user is not None and f["username"] != user:
        return False
    if what is None:
        return True
    if what.startswith("/"):
        return f["file"] == what
    return f["fp"] == FP[what]


def test_08_scan1_findings(cfg, state):
    conn = _db(cfg)
    sid = state["s1"]
    fs = conn.execute("SELECT * FROM finding WHERE scan_id=?", (sid,)).fetchall()
    counts = Counter(f["rule"] for f in fs)
    for rule, n in S1["findings"].items():
        assert counts.get(rule, 0) == n, (rule, counts.get(rule, 0))
    assert set(counts) <= set(S1["findings"]), set(counts) - set(S1["findings"])
    for rule, wheres in S1["finding_where"].items():
        rows = [f for f in fs if f["rule"] == rule]
        for host, user, what in wheres:
            assert any(_finding_matches(conn, f, host, user, what) for f in rows), (rule, host, user, what)
    root = [f for f in fs if f["rule"] == "root_authorized_key"]
    assert {f["severity"] for f in root} == {S1["root_authorized_key_severity"]}
    by_key = Counter(f["fp"] for f in root)
    assert {k: by_key[FP[k]] for k in S1["root_authorized_key_keys"]} == S1["root_authorized_key_keys"]
    assert all(f["recommendation"] for f in fs)


def test_09_scan1_parsing(cfg, state):
    conn = _db(cfg)
    sid = state["s1"]
    p = S1["parsing"]
    r = conn.execute("SELECT a.expiry_time FROM authorized_entry a JOIN host h ON h.id=a.host_id WHERE a.scan_id=?"
                     " AND h.display_name='a1' AND a.fp=?", (sid, FP["K_OPS"])).fetchone()
    assert r["expiry_time"] == p["k_ops_expiry_on_a1"]
    r = conn.execute("SELECT encrypted FROM private_key WHERE scan_id=? AND fp=?", (sid, FP["K_OPS"])).fetchone()
    assert r["encrypted"] == p["k_ops_private_encrypted"]
    assert conn.execute("SELECT bits FROM key WHERE fp=?", (FP["K_DSA"],)).fetchone()[0] == p["k_dsa_bits"]
    # the audit key is ignored everywhere
    assert conn.execute("SELECT count(*) FROM authorized_entry WHERE fp=?", (FP["AUDIT"],)).fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM key WHERE fp=?", (FP["AUDIT"],)).fetchone()[0] == 0
    # no secret in the DB: the sudo password never reaches it
    assert b"labsudo" not in cfg["db"].read_bytes()


def test_10_scan1_exports(cfg, state, evidence):
    sid = str(state["s1"])
    p = L.sshbite(cfg["path"], "export", "--scan", sid, "--what", "edges", "--kind", "access", "--format", "csv")
    assert p.returncode == 0, p.stderr
    rows = list(csv.DictReader(io.StringIO(p.stdout)))
    assert len(rows) == S1["exports"]["access_edges_csv_rows"]
    _write(evidence, "scan1-access-edges.csv", p.stdout)
    p = L.sshbite(cfg["path"], "export", "--scan", sid, "--what", "findings", "--format", "csv")
    assert p.returncode == 0, p.stderr
    rows = list(csv.DictReader(io.StringIO(p.stdout)))
    counts = Counter(r["rule"] for r in rows)
    assert {k: v for k, v in S1["findings"].items() if v} == dict(counts)
    assert all(r["removal_hint"] for r in rows if r["rule"] == "key_unknown_origin")
    _write(evidence, "scan1-findings.csv", p.stdout)
    p = L.sshbite(cfg["path"], "export", "--scan", sid, "--what", "findings", "--rule", "key_unknown_origin",
                  "--min-severity", "high", "--format", "csv")
    assert len(list(csv.DictReader(io.StringIO(p.stdout)))) == S1["findings"]["key_unknown_origin"]
    _write(evidence, "scan1-key_unknown_origin.csv", p.stdout)
    p = L.sshbite(cfg["path"], "export", "--scan", sid, "--what", "findings", "--format", "json")
    doc = json.loads(p.stdout)
    assert doc["scan"]["id"] == int(sid) and len(doc["items"]) == sum(S1["findings"].values())
    for what in ("keys", "hosts", "authorized"):
        p = L.sshbite(cfg["path"], "export", "--scan", sid, "--what", what, "--format", "csv")
        assert p.returncode == 0 and len(p.stdout.splitlines()) > 1, (what, p.stderr)
    p = L.sshbite(cfg["path"], "scans", "show", sid)
    assert p.returncode == 0
    _write(evidence, "scans-show-1.txt", p.stdout)


def test_20_scan2(ctl, cfg, state, evidence):
    for host, action in EXP["scan2"]["changes"]:
        ctl.run(host, "labctl.sh", action)
    proc, diff = _scan_bracketed(ctl, cfg, "scan2", evidence, env={"SSHBITE_SUDO_PASSWORD": "labsudo"})
    _write(evidence, "console-scan2.txt", proc.stdout + proc.stderr)
    # the snapshot detects changes: the lab changes made above show up between scan 1 and scan 2
    after_scan1 = [a for lbl, _b, a in _SNAPSHOTS if lbl == "scan1"][0]
    before_scan2 = [b for lbl, b, _a in _SNAPSHOTS if lbl == "scan2"][0]
    between = L.snapshot_diff(after_scan1, before_scan2)
    _write(evidence, "snapshot-lab-changes-before-scan2.diff", between)
    for path in ("a5/before", "b2/before", "c2/before", "/root/.ssh/authorized_keys", "/home/www/.ssh/authorized_keys",
                 "/etc/ssh/ssh_host_ed25519_key"):
        assert path in between, path
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert diff == "", "lab changed during scan 2:\n" + diff
    conn = _db(cfg)
    sid = conn.execute("SELECT max(id) FROM scan WHERE status='completed'").fetchone()[0]
    state["s2"] = sid
    rows = _host_rows(conn, sid)
    assert rows["c2"]["status"] == "hostkey_mismatch"
    f = conn.execute("SELECT severity, detail FROM finding WHERE scan_id=? AND rule='host_key_changed'", (sid,)).fetchall()
    assert len(f) == 1 and f[0]["severity"] == "critical"
    detail = json.loads(f[0]["detail"])
    rotated = L.key_fp("c2_rotated_host_ed25519")
    original = L.key_fp("c2_host_ed25519")
    assert detail["new"]["fp"] == rotated and original in [o["fp"] for o in detail["old"]]
    # c2 was not authenticated to or collected
    assert conn.execute("SELECT count(*) FROM account a JOIN host h ON h.id=a.host_id WHERE a.scan_id=?"
                        " AND h.display_name='c2'", (sid,)).fetchone()[0] == 0


def test_21_diff_1_2(cfg, state, evidence):
    p = L.sshbite(cfg["path"], "diff", str(state["s1"]), str(state["s2"]), "--format", "json")
    assert p.returncode == 0, p.stderr
    d = json.loads(p.stdout)
    t = L.sshbite(cfg["path"], "diff", str(state["s1"]), str(state["s2"]))
    _write(evidence, "diff-1-2.txt", t.stdout)
    _write(evidence, "diff-1-2.json", p.stdout)
    exp = EXP["scan2"]["diff_1_2"]

    def e_key(e):
        src = "unknown" if e["src"] == "unknown" else f"{e['src']}:{e['src_user'] or ''}"
        return (src, f"{e['dst']}:{e['dst_user'] or ''}", e["fp"])

    removed = {e_key(e) for e in d["edges"]["removed"] if e["kind"] == "access"}
    added = {e_key(e) for e in d["edges"]["added"] if e["kind"] == "access"}
    assert removed == {(s, t_, FP[k]) for s, t_, k in exp["edges_removed"]}, removed
    assert added == {(s, t_, FP[k]) for s, t_, k in exp["edges_added"]}, added
    assert {k["fp"] for k in d["keys"]["added"]} == {FP[k] for k in exp["keys_added"]}
    assert {k["fp"] for k in d["keys"]["removed"]} == {FP[k] for k in exp["keys_removed"]}

    def f_key(f):
        return (f["rule"], f["host"], f["user"], f["fp"])

    def x_key(x):
        rule, host, user, key = x
        return (rule, host, user, FP[key] if key else None)

    assert {f_key(f) for f in d["findings"]["added"]} == {x_key(x) for x in exp["findings_added"]}
    assert {f_key(f) for f in d["findings"]["removed"]} == {x_key(x) for x in exp["findings_removed"]}
    changed = {(h["host"], h["changes"]["status"]["a"], h["changes"]["status"]["b"])
               for h in d["hosts"]["changed"] if "status" in h["changes"]}
    assert changed == {tuple(x) for x in exp["hosts_changed"]}
    assert d["hosts"]["added"] == [] and d["hosts"]["removed"] == []


def test_30_scan3(ctl, cfg, state, evidence):
    p = L.sshbite(cfg["path"], "hostkey", "accept", "172.30.3.22")
    _write(evidence, "console-hostkey-accept.txt", "$ sshbite hostkey accept 172.30.3.22\n" + p.stdout + p.stderr)
    assert p.returncode == 0, p.stderr
    proc, diff = _scan_bracketed(ctl, cfg, "scan3", evidence)
    _write(evidence, "console-scan3.txt", proc.stdout + proc.stderr)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert diff == "", "lab changed during scan 3:\n" + diff
    assert "need a sudo password: rerun with --ask-sudo-password" in proc.stdout or \
        "needs a sudo password: rerun with --ask-sudo-password" in proc.stdout
    conn = _db(cfg)
    sid = conn.execute("SELECT max(id) FROM scan WHERE status='completed'").fetchone()[0]
    state["s3"] = sid
    rows = _host_rows(conn, sid)
    assert rows["c2"]["status"] == "ok"
    assert (rows["a4"]["status"], rows["a4"]["privilege"]) == ("partial", "unprivileged")
    assert conn.execute("SELECT count(*) FROM finding f JOIN host h ON h.id=f.host_id WHERE f.scan_id=?"
                        " AND f.rule='partial_scan' AND h.display_name='a4'", (sid,)).fetchone()[0] == 1
    edges = _edges(conn, sid)
    src, dst, key = EXP["scan3"]["edge_absent"]
    assert not [e for e in edges if e["src"] == src and e["dst"] == dst and e["fp"] == FP[key]]
    # c2 keeps its identity across the accepted key change
    ids = {conn.execute("SELECT hs.host_id FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=?"
                        " AND hs.connect_addr='172.30.3.22'", (s,)).fetchone()[0] for s in (state["s1"], sid)}
    assert len(ids) == 1


def test_31_reset_lab(ctl):
    """Leave the lab as it was."""
    for host in ("a5", "b2", "c2"):
        ctl.run(host, "labctl.sh", "reset")
