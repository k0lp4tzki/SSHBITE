"""Every endpoint against the hand-built fixture DB of P1 (tests/unit/fixture_db.py) and an empty DB."""

from __future__ import annotations

import pytest

from sshbite import db as dbm
from sshbite.config import Config
from sshbite.derive import derive_scan
from tests.unit import fixture_db as F

from .conftest import Client, _prepare, Server


@pytest.fixture
def fx(tmp_path):
    path = _prepare(tmp_path, None)
    conn = dbm.connect(path)
    cfg = Config.model_validate({"entry": {"host": "x"}, "rules": {"many_hosts_threshold": 3}})
    s1, h = F.build(conn, 1)
    derive_scan(conn, s1, cfg)
    conn.execute("UPDATE scan SET status='completed' WHERE id=?", (s1,))
    s2, _ = F.build(conn, 2)
    derive_scan(conn, s2, cfg)
    conn.execute("UPDATE scan SET status='completed' WHERE id=?", (s2,))
    conn.close()
    with Server(path) as srv:
        c = Client(srv.base)
        assert c.login().status == 204
        yield c, s1, s2, h


def u(fp):
    return fp.replace("+", "-").replace("/", "_")


def test_every_endpoint(fx):
    c, s1, s2, h = fx
    assert c.get("/api/scans").json()["total"] == 2
    assert c.get(f"/api/scans/{s1}").json()["id"] == s1
    assert c.get(f"/api/scans/{s1}/crawl").status == 200
    hosts = c.get(f"/api/scans/{s1}/hosts").json()
    assert hosts["total"] == 5 and {x["display_name"] for x in hosts["items"]} == set("ABCDE")
    assert "unresolved_hashed" in hosts["items"][0]
    d = c.get(f"/api/scans/{s1}/hosts/{h['B']}").json()
    assert {a["username"] for a in d["authorized"]} >= {"alice", "root", "bob", "svc", "backup"}
    assert any(k["matches_actual"] == "no" for k in c.get(f"/api/scans/{s1}/hosts/{h['B']}").json()["known_by"])
    keys = c.get(f"/api/scans/{s1}/keys").json()
    assert {k["fp"] for k in keys["items"]} == {F.K1[0], F.K2[0], F.K3[0], F.K4[0]}
    assert keys["items"][0]["strength"] == "critical"
    kd = c.get(f"/api/scans/{s1}/keys/{u(F.K1[0])}").json()
    assert kd["origin"] == "known" and kd["private_on"][0]["host"] == "A"
    assert c.req("PUT", f"/api/keys/{u(F.K3[0])}/label", {"label": "old dsa"}).json()["label"] == "old dsa"
    edges = c.get(f"/api/scans/{s1}/edges?kind=access&page_size=1000").json()
    statuses = {e["status"] for e in edges["items"]}
    assert statuses >= {"confirmed", "restricted_ok", "restricted_blocked", "unknown_origin"}
    ab = c.get(f"/api/scans/{s1}/edges?src_host_id={h['A']}&dst_host_id={h['B']}&kind=access").json()
    assert ab["total"] >= 1 and all(e["src"] == "A" and e["dst"] == "B" for e in ab["items"])
    hm = c.get(f"/api/scans/{s1}/heatmap").json()
    assert hm["group_by"] == "host" and hm["max"] >= 1
    cell = c.get(f"/api/scans/{s1}/heatmap/cell?group_by=host&src_group={h['A']}&dst_group={h['B']}").json()
    assert cell["value"] == 1 and cell["pairs"][0]["src"] == "A"
    assert c.get(f"/api/scans/{s1}/ranking?direction=out").json()["items"][0]["display_name"] == "A"
    g = c.get(f"/api/scans/{s1}/graph?center_host={h['B']}&hops=2").json()
    assert {n["label"] for n in g["nodes"] if n["kind"] == "host"} >= {"A", "B"}
    f = c.get(f"/api/scans/{s1}/findings").json()
    assert f["total"] > 0 and f["severity_counts"]
    diff = c.get(f"/api/diff?a={s1}&b={s2}").json()
    assert [e["dst_user"] for e in diff["edges"]["removed"] if e["kind"] == "access"] == ["bob"]
    for what in ("findings", "keys", "edges", "hosts", "authorized"):
        for fmt in ("csv", "json"):
            assert c.get(f"/api/scans/{s1}/export/{what}.{fmt}").status == 200, (what, fmt)
    assert c.get("/api/search?q=alice").json()["users"]


def test_pagination_bounds(fx):
    c, s1, _s2, _h = fx
    r = c.get(f"/api/scans/{s1}/findings?page_size=2&page=2").json()
    assert r["page"] == 2 and len(r["items"]) == 2 and r["page_size"] == 2
    assert c.get(f"/api/scans/{s1}/findings?page_size=0").status == 400
    assert c.get(f"/api/scans/{s1}/findings?page=0").status == 400
    assert c.get(f"/api/scans/{s1}/findings?page_size=1000").status == 200


def test_empty_database(make_server):
    with make_server(None) as s:
        c = Client(s.base)
        c.login()
        assert c.get("/api/scans").json() == {"items": [], "total": 0, "page": 1, "page_size": 100}
        assert c.get("/api/search?q=abc").json()["scan"] is None
        assert c.get("/api/scans/1/hosts").status == 404
