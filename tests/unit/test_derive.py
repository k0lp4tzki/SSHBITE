"""Edges, findings and metrics on the fixture DB (spec 4.3-4.5); diff (4.2); export (7)."""

import csv
import io
import json
from collections import Counter

import pytest

from sshbite import db as dbm
from sshbite.config import Config
from sshbite.derive import derive_scan
from sshbite.diff import diff_scans, render_text
from sshbite.export import COLUMNS, ExportFilter, csv_safe, export

from . import fixture_db as F


@pytest.fixture
def conn(tmp_path):
    return dbm.connect(str(tmp_path / "d.db"))


def _cfg(threshold=3):
    return Config.model_validate({"entry": {"host": "x"}, "rules": {"many_hosts_threshold": threshold}})


def _edges(conn, sid):
    out = {}
    for r in conn.execute("SELECT e.*, hd.display_name AS dst, hs.display_name AS src FROM edge e"
                          " JOIN host hd ON hd.id=e.dst_host_id LEFT JOIN host hs ON hs.id=e.src_host_id"
                          " WHERE e.scan_id=? AND e.kind='access'", (sid,)):
        out[(r["src"] or "unknown", r["src_user"], r["dst"], r["dst_user"], r["fp"])] = r
    return out


def test_access_edges(conn):
    sid, h = F.build(conn)
    derive_scan(conn, sid, _cfg())
    e = _edges(conn, sid)
    k1, k2, k3, k4 = F.K1[0], F.K2[0], F.K3[0], F.K4[0]
    assert e[("A", "alice", "B", "alice", k1)]["status"] == "confirmed"
    blocked = e[("A", "alice", "B", "root", k1)]
    assert blocked["status"] == "restricted_blocked" and blocked["effective"] == 0
    assert "dst_root" in json.loads(blocked["flags"])
    assert e[("unknown", None, "B", "root", k3)]["status"] == "unknown_origin"
    svc = e[("A", "svc", "B", "svc", k2)]
    assert "forced_command" in json.loads(svc["flags"]) and svc["effective"] == 1
    assert "dst_nologin" in json.loads(e[("A", "alice", "B", "backup", k1)]["flags"])
    denied = e[("A", "alice", "C", "bob", k1)]
    assert denied["effective"] == 0 and "sshd_denied" in json.loads(denied["flags"])
    assert e[("A", "alice", "C", "alice", k1)]["status"] == "restricted_ok"
    assert e[("A", "alice", "D", "alice", k1)]["effective"] == 0   # pubkeyauthentication no
    assert ("A", "alice", "A", "alice", k1) in e                     # self edge stored
    assert not [x for x in e if x[4] == k4 and x[2] == "C"]          # cert-authority: no edge
    assert len(e) == 10
    ev = conn.execute("SELECT count(*) FROM edge WHERE scan_id=? AND kind='evidence'", (sid,)).fetchone()[0]
    assert ev == 1   # the known_hosts reference; from= never makes an evidence edge


def test_metrics(conn):
    sid, h = F.build(conn)
    derive_scan(conn, sid, _cfg())
    m = {r["host_id"]: r for r in conn.execute("SELECT * FROM host_metric WHERE scan_id=?", (sid,))}
    a, b, c = m[h["A"]], m[h["B"]], m[h["C"]]
    # A -> B effective: alice(K1), svc(K2), backup(K1); A -> C: alice; self edge not counted
    assert a["out_hosts"] == 2 and a["out_users"] == 4 and a["out_keys"] == 2
    assert b["in_hosts"] == 1 and b["in_users"] == 2 and b["in_keys"] == 4 and b["in_unknown_keys"] == 2
    assert c["in_hosts"] == 1 and c["in_keys"] == 1
    assert a["in_hosts"] == 0           # self edge excluded
    assert a["ev_out_hosts"] == 1 and b["ev_in_hosts"] == 1
    assert m[h["D"]]["in_hosts"] == 0   # not effective


def test_findings(conn):
    sid, h = F.build(conn)
    derive_scan(conn, sid, _cfg(threshold=3))
    fs = conn.execute("SELECT * FROM finding WHERE scan_id=?", (sid,)).fetchall()
    c = Counter(f["rule"] for f in fs)
    assert c["key_strength_critical"] == 1
    assert c["key_strength_weak"] == 2                 # B:svc entry + A:svc private key
    assert c["root_authorized_key"] == 2               # K1 (from=) and K3; not the cert-authority entry
    sev = {f["fp"]: f["severity"] for f in fs if f["rule"] == "root_authorized_key"}
    assert sev == {F.K1[0]: "medium", F.K3[0]: "high"}
    assert c["key_unknown_origin"] == 2                # K3 on B:root, K4 on B:bob
    assert c["key_on_many_hosts"] == 1                 # K1 on A, B, C, D
    assert c["private_key_unencrypted"] == 1
    assert c["private_key_bad_permissions"] == 1       # mode 0644 and owner root != svc
    assert c["duplicate_key_across_users"] == 1        # K1 authorized for alice, root, backup on B
    assert c["key_for_disabled_user"] == 1
    assert c["permit_root_login_yes"] == 1 and c["password_authentication_yes"] == 1
    assert c["known_host_stale"] == 1 and c["host_unreachable"] == 1 and c["cert_authority_trusted"] == 1
    assert all(f["recommendation"] and len(f["ident"]) == 40 for f in fs)
    assert len({f["ident"] for f in fs}) == len(fs)


def test_derive_is_idempotent(conn):
    sid, _ = F.build(conn)
    derive_scan(conn, sid, _cfg())
    n = conn.execute("SELECT count(*) FROM edge").fetchone()[0], conn.execute("SELECT count(*) FROM finding").fetchone()[0]
    derive_scan(conn, sid, _cfg())
    assert n == (conn.execute("SELECT count(*) FROM edge").fetchone()[0],
                 conn.execute("SELECT count(*) FROM finding").fetchone()[0])


def test_diff(conn):
    s1, _ = F.build(conn, 1)
    derive_scan(conn, s1, _cfg())
    s2, _ = F.build(conn, 2)
    derive_scan(conn, s2, _cfg())
    d = diff_scans(conn, s1, s2)
    assert [x["fp"] for x in d["edges"]["removed"]] == [F.K4[0]]
    assert d["edges"]["added"] == []
    assert [(x["kind"], x["host"], x["user"]) for x in d["placements"]["removed"]] == [("authorized", "B", "bob")]
    assert {f["rule"] for f in d["findings"]["removed"]} == {"key_unknown_origin", "host_unreachable"}
    ch = d["hosts"]["changed"]
    assert len(ch) == 1 and ch[0]["host"] == "E" and ch[0]["changes"]["status"] == {"a": "unreachable", "b": "ok"}
    assert d["keys"]["removed"] == [] and d["keys"]["added"] == []   # K4 is still in the cert-authority entry
    assert "edges: 0 added, 1 removed" in render_text(d)
    same = diff_scans(conn, s1, s1)
    assert all(not same[c][k] for c in ("hosts", "keys", "placements", "edges", "findings") for k in same[c])


def test_export_columns_filters_and_injection(conn):
    sid, h = F.build(conn)
    derive_scan(conn, sid, _cfg())
    for what in COLUMNS:
        out = export(conn, sid, what, "csv")
        rows = list(csv.reader(io.StringIO(out)))
        assert rows[0] == COLUMNS[what]
    rows = list(csv.DictReader(io.StringIO(export(conn, sid, "edges", "csv", ExportFilter(kind="access")))))
    assert len(rows) == 10 and {r["kind"] for r in rows} == {"access"}
    f = list(csv.DictReader(io.StringIO(export(conn, sid, "findings", "csv",
                                               ExportFilter(min_severity="high", rules=["key_unknown_origin"])))))
    assert len(f) == 2
    assert f[0]["removal_hint"].startswith("delete line ") and " on B (SHA256:" in f[0]["removal_hint"]
    only_c = list(csv.DictReader(io.StringIO(export(conn, sid, "authorized", "csv", ExportFilter(host_glob="c")))))
    assert {r["host"] for r in only_c} == {"C"}
    doc = json.loads(export(conn, sid, "keys", "json"))
    assert doc["scan"]["id"] == sid and set(doc["items"][0]) == set(COLUMNS["keys"])
    for bad in ("=cmd|' /C calc'!A0", "+1", "-1", "@SUM(1)", "\tx"):
        assert csv_safe(bad).startswith("'")
    assert csv_safe("normal") == "normal"
