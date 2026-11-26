"""The API against real lab scan data (scans 1-3 of spec 9.3, from a P1 lab run against real sshd)."""

from __future__ import annotations

import csv
import io
from collections import Counter

from tests.e2e.lab import key_fp


def u(fp: str) -> str:
    return fp.replace("+", "-").replace("/", "_")


def hosts(c, sid=1) -> dict:
    return {h["display_name"]: h for h in c.get(f"/api/scans/{sid}/hosts?page_size=1000").json()["items"]}


def test_scans_list_and_detail(lab):
    r = lab.get("/api/scans").json()
    assert [s["id"] for s in r["items"]] == [3, 2, 1]
    assert r["total"] == 3 and r["page"] == 1
    assert all(s["running"] is False and s["status"] == "completed" for s in r["items"])
    s1 = lab.get("/api/scans/1").json()
    assert s1["counts"]["access_edges"] == 20 and s1["counts"]["effective_edges"] == 19
    assert s1["counts"]["unknown_origin_edges"] == 3
    assert s1["unresolved_hashed_total"] == 1
    assert s1["params"]["max_depth"] == 10 and "progress" in s1


def test_hosts_table_matches_9_3(lab):
    h = hosts(lab)
    assert h["a1"]["discovered_via"]["parent"] == "jump"
    assert (h["a1"]["discovered_via"]["file"], h["a1"]["discovered_via"]["line"]) == ("/home/ops/.ssh/config", 2)
    assert h["a1"]["route"] == ["jump", "a1"]
    assert h["c1"]["route"] == ["jump", "b3", "c1"]
    assert h["c2"]["route"] == ["jump", "b3", "c1", "c2"]
    assert h["b5"]["status"] == "partial" and h["b5"]["privilege"] == "unprivileged"
    assert h["a4"]["privilege"] == "sudo_password"
    assert h["172.30.1.99"]["status"] == "unreachable"
    assert h["a1"]["unresolved_hashed"] == 1
    out = {n: x["metrics"]["out_hosts"] for n, x in h.items()}
    assert (out["jump"], out["a1"], out["b3"], out["b2"], out["a5"], out["a3"]) == (7, 2, 2, 1, 1, 0)
    inn = {n: x["metrics"]["in_hosts"] for n, x in h.items()}
    assert (inn["a2"], inn["a3"], inn["b2"], inn["a4"]) == (3, 2, 2, 0)
    assert all(inn[n] == 1 for n in ("a1", "b1", "b3", "a5", "c1", "c2"))
    assert {n for n, x in h.items() if x["metrics"]["in_unknown_keys"] == 1} == {"b1", "a4", "c1"}


def test_hosts_filters_sort_pagination(lab):
    r = lab.get("/api/scans/1/hosts?status=partial").json()
    assert [x["display_name"] for x in r["items"]] == ["b5"]
    r = lab.get("/api/scans/1/hosts?sort=out_hosts&page_size=2").json()
    assert [x["display_name"] for x in r["items"]] == ["jump", "a1"] and r["total"] == 17
    r2 = lab.get("/api/scans/1/hosts?sort=out_hosts&page_size=2&page=2").json()
    assert r2["page"] == 2 and len(r2["items"]) == 2
    r = lab.get("/api/scans/1/hosts?sort=unresolved_hashed&page_size=1").json()
    assert r["items"][0]["display_name"] == "a1" and r["items"][0]["unresolved_hashed"] == 1
    r = lab.get("/api/scans/1/hosts?q=172.30.3").json()
    assert {x["display_name"] for x in r["items"]} == {"c1", "c2", "b3"}
    r = lab.get("/api/scans/1/hosts?group_kind=subnet&group=172.30.3.0/24").json()
    assert {x["display_name"] for x in r["items"]} == {"c1", "c2"}
    r = lab.get("/api/scans/1/hosts?privilege=sudo_password").json()
    assert [x["display_name"] for x in r["items"]] == ["a4"]


def test_host_detail_c1_b3_b5_unreachable(lab):
    h = hosts(lab)
    c1 = lab.get(f"/api/scans/1/hosts/{h['c1']['host_id']}").json()
    att = c1["host_scan"]["route_attempts"]
    assert att[0]["route"] == ["jump", "c1"] and att[0]["error"]
    assert att[-1]["route"] == ["jump", "b3", "c1"] and att[-1]["error"] is None
    assert c1["host_scan"]["discovered_via"]["parent"] == "b3"
    b3 = lab.get(f"/api/scans/1/hosts/{h['b3']['host_id']}").json()
    kb = {(k["host"], k["username"]): k for k in b3["known_by"]}
    assert kb[("b1", "admin")]["matches_actual"] == "no"   # stale
    b5 = lab.get(f"/api/scans/1/hosts/{h['b5']['host_id']}").json()
    assert any("sudo" in r for r in b5["host_scan"]["partial_reasons"])
    assert any("unreadable" in r for r in b5["host_scan"]["partial_reasons"])
    un = lab.get(f"/api/scans/1/hosts/{h['172.30.1.99']['host_id']}").json()
    routes = [a["route"] for a in un["host_scan"]["route_attempts"]]
    assert ["jump", "172.30.1.99"] in routes and ["jump", "a2", "172.30.1.99"] in routes
    a1 = lab.get(f"/api/scans/1/hosts/{h['a1']['host_id']}").json()
    assert {e["src"] for e in a1["edges_in"] if e["kind"] == "access"} == {"jump"}
    assert any(p["path"] == "/home/deploy/.ssh/id_rsa" and p["mode_bad"] for p in a1["private_keys"])
    assert any(k["hashed"] and k["resolved_value"] == "172.30.1.12" for k in a1["known_hosts"])
    assert lab.get("/api/scans/1/hosts/99999").json()["error"]["code"] == "host_not_found"


def test_c2_host_key_changed_in_scan2(lab):
    h = hosts(lab, 2)
    c2 = lab.get(f"/api/scans/2/hosts/{h['c2']['host_id']}").json()
    assert c2["host_scan"]["status"] == "hostkey_mismatch"
    f = [x for x in c2["findings"] if x["rule"] == "host_key_changed"][0]
    assert f["severity"] == "critical" and f["detail"]["old"] and f["detail"]["new"]["fp"]


def test_keys_list_and_dsa_detail(lab):
    dsa = key_fp("k_dsa")
    r = lab.get("/api/scans/1/keys?q=legacy-dsa").json()
    assert [k["fp"] for k in r["items"]] == [dsa]
    k = r["items"][0]
    assert (k["strength"], k["bits"], k["origin"], k["authorized_hosts"], k["private_holders"]) == ("critical", 1024, "unknown", 2, 0)
    d = lab.get(f"/api/scans/1/keys/{u(dsa)}").json()
    assert {(a["host"], a["username"]) for a in d["authorized_on"]} == {("b1", "root"), ("a4", "root")}
    assert d["origin"] == "unknown" and d["private_on"] == []
    assert lab.get("/api/scans/1/keys?origin=unknown").json()["total"] >= 2
    assert {x["strength"] for x in lab.get("/api/scans/1/keys?strength=critical").json()["items"]} == {"critical"}


def test_key_fleet_placements(lab):
    fleet = key_fp("k_fleet")
    d = lab.get(f"/api/scans/1/keys/{u(fleet)}").json()
    assert sorted(a["host"] for a in d["authorized_on"]) == ["a1", "a2", "a3", "a5", "b1", "b2", "b3"]
    assert [(p["host"], p["username"], p["path"]) for p in d["private_on"]] == [("jump", "ops", "/home/ops/.ssh/fleet_rsa")]
    assert d["strength"] == "ok" and d["bits"] == 3072
    assert any(f["rule"] == "key_on_many_hosts" for f in d["findings"])


def test_key_not_in_scan(lab):
    new = key_fp("k_new")
    r = lab.get(f"/api/scans/1/keys/{u(new)}")
    assert r.status == 404 and r.json()["error"]["code"] == "key_not_in_scan"
    assert lab.get(f"/api/scans/2/keys/{u(new)}").status == 200


def test_label_survives_and_shows_in_lists(lab):
    dsa = key_fp("k_dsa")
    r = lab.req("PUT", f"/api/keys/{u(dsa)}/label", {"label": "contractor 2019 – remove", "owner": "ops", "note": "n"})
    assert r.status == 200 and r.json()["updated_by"] == "admin"
    assert lab.get(f"/api/scans/3/keys/{u(dsa)}").json()["label"]["label"] == "contractor 2019 – remove"
    assert lab.get("/api/scans/1/keys?q=contractor").json()["items"][0]["fp"] == dsa
    assert dsa in [k["fp"] for k in lab.get("/api/search?q=contractor&scan=1").json()["keys"]]
    assert lab.req("PUT", f"/api/keys/{u(dsa)}/label", {"label": "x" * 81}).status == 400


def test_edges_filters(lab):
    h = hosts(lab)
    all_ = lab.get("/api/scans/1/edges?kind=access&page_size=1000").json()
    assert all_["total"] == 20
    assert sum(e["effective"] for e in all_["items"]) == 19
    assert sum(e["src_host_id"] is None for e in all_["items"]) == 3
    r = lab.get(f"/api/scans/1/edges?src_host_id={h['jump']['host_id']}&dst_host_id={h['a2']['host_id']}&kind=access").json()
    assert r["total"] == 1
    e = r["items"][0]
    assert (e["src"], e["src_user"], e["dst"], e["dst_user"], e["fp"]) == ("jump", "ops", "a2", "root", key_fp("k_fleet"))
    assert e["authorized_file"] == "/root/.ssh/authorized_keys" and e["private_key_path"] == "/home/ops/.ssh/fleet_rsa"
    r = lab.get(f"/api/scans/1/edges?host_id={h['b2']['host_id']}&kind=access&effective=false").json()
    assert [x["status"] for x in r["items"]] == ["restricted_blocked"]
    r = lab.get(f"/api/scans/1/edges?fp={u(key_fp('k_dsa'))}").json()
    assert r["total"] == 2
    r = lab.get(f"/api/scans/1/edges?dst_host_id={h['c1']['host_id']}&unknown_origin=true").json()
    assert r["total"] == 1 and r["items"][0]["fp"] == key_fp("k_orphan")


def test_heatmap_host_grouping(lab):
    hm = lab.get("/api/scans/1/heatmap").json()
    assert hm["group_by"] == "host" and hm["level"] == "groups"
    rows = {r["label"]: i for i, r in enumerate(hm["rows"])}
    cols = {c["label"]: i for i, c in enumerate(hm["cols"])}
    cells = {(r, c): v for r, c, v in hm["cells"]}
    assert cells[(rows["jump"], cols["a2"])] == 1
    assert hm["rows"][-1]["kind"] == "unknown"
    assert sum(v for (r, _c), v in cells.items() if r == rows["jump"]) == 7      # out_hosts of jump
    assert sum(v for (_r, c), v in cells.items() if c == cols["a2"]) == 3        # in_hosts of a2 (no unknown into a2)
    # users metric: jump -> a1 = ops->deploy and ops->root
    hu = lab.get("/api/scans/1/heatmap?group_by=host&metric=users").json()
    ru = {r["label"]: i for i, r in enumerate(hu["rows"])}
    cu = {c["label"]: i for i, c in enumerate(hu["cols"])}
    assert {(r, c): v for r, c, v in hu["cells"]}[(ru["jump"], cu["a1"])] == 2
    no_unknown = lab.get("/api/scans/1/heatmap?include_unknown=false").json()
    assert all(r["kind"] != "unknown" for r in no_unknown["rows"])
    ev = lab.get("/api/scans/1/heatmap?layer=evidence").json()
    assert all(r["kind"] != "unknown" for r in ev["rows"]) and ev["cells"]


def test_heatmap_cell_and_drilldown(lab):
    h = hosts(lab)
    cell = lab.get(f"/api/scans/1/heatmap/cell?group_by=host&src_group={h['jump']['host_id']}&dst_group={h['a2']['host_id']}").json()
    assert cell["value"] == 1
    assert cell["pairs"] == [{"src_host_id": h["jump"]["host_id"], "src": "jump", "dst_host_id": h["a2"]["host_id"],
                              "dst": "a2", "users": 1, "keys": 1, "dst_users": ["root"], "value": 1}]
    sub = lab.get("/api/scans/1/heatmap?group_by=subnet").json()
    labels = [r["label"] for r in sub["rows"]]
    assert "172.30.1.0/24" in labels and labels[-1] == "Unknown origin"
    d = lab.get("/api/scans/1/heatmap?group_by=subnet&src_group=172.30.2.0/24&dst_group=172.30.3.0/24").json()
    assert d["level"] == "hosts" and {r["label"] for r in d["cols"]} == {"c1", "c2"}
    rows = {r["label"]: i for i, r in enumerate(d["rows"])}
    assert sum(v for r, _c, v in d["cells"] if r == rows["b3"]) == 2
    unk = lab.get("/api/scans/1/heatmap/cell?group_by=subnet&src_group=~unknown&dst_group=172.30.2.0/24").json()
    assert unk["pairs"][0]["src"].startswith("unknown:SHA256:") and unk["pairs"][0]["src_host_id"] is None


def test_ranking(lab):
    out = lab.get("/api/scans/1/ranking?direction=out&metric=hosts&limit=3").json()["items"]
    assert out[0]["display_name"] == "jump" and out[0]["value"] == 7
    inn = lab.get("/api/scans/1/ranking?direction=in&metric=hosts").json()["items"]
    assert inn[0]["display_name"] == "a2" and inn[0]["value"] == 3
    unk = lab.get("/api/scans/1/ranking?direction=in&metric=unknown_keys").json()["items"]
    assert {x["display_name"] for x in unk} == {"b1", "a4", "c1"}


def test_graph(lab):
    h = hosts(lab)
    g = lab.get(f"/api/scans/1/graph?center_host={h['jump']['host_id']}&hops=1").json()
    names = {n["label"] for n in g["nodes"]}
    assert names == {"jump", "a1", "a2", "a3", "a5", "b1", "b2", "b3"} and not g["truncated"]
    k = lab.get(f"/api/scans/1/graph?center_key={u(key_fp('k_dsa'))}").json()
    assert {n["label"] for n in k["nodes"] if n["kind"] == "host"} == {"b1", "a4"}
    assert [n["kind"] for n in k["nodes"]].count("unknown") == 1
    assert all(l["fp"] == key_fp("k_dsa") for l in k["links"])
    ev = lab.get(f"/api/scans/1/graph?center_host={h['a1']['host_id']}&layer=evidence").json()
    assert all(l["kind"] == "evidence" for l in ev["links"]) and ev["links"]
    assert lab.get("/api/scans/1/graph").status == 400


def test_findings_counts_and_filters(lab):
    r = lab.get("/api/scans/1/findings?page_size=1000").json()
    counts = Counter(f["rule"] for f in r["items"])
    assert counts == Counter({"key_strength_critical": 4, "key_strength_weak": 3, "root_authorized_key": 10,
                              "key_on_many_hosts": 1, "key_unknown_origin": 3, "private_key_unencrypted": 7,
                              "private_key_bad_permissions": 1, "duplicate_key_across_users": 1,
                              "key_for_disabled_user": 1, "permit_root_login_yes": 1, "password_authentication_yes": 1,
                              "known_host_stale": 1, "host_unreachable": 1, "partial_scan": 1,
                              "cert_authority_trusted": 1})
    assert r["items"][0]["severity"] == "critical"
    j5 = lab.get("/api/scans/1/findings?rule=key_unknown_origin&severity_min=high").json()
    assert j5["total"] == 3 and {f["host"] for f in j5["items"]} == {"b1", "a4", "c1"}
    assert lab.get("/api/scans/1/findings?severity=critical").json()["total"] == 4
    assert lab.get("/api/scans/1/findings?q=legacy-dsa").json()["total"] >= 2
    h = hosts(lab)
    assert {f["rule"] for f in lab.get(f"/api/scans/1/findings?host_id={h['a2']['host_id']}").json()["items"]} >= {"permit_root_login_yes"}


def test_exports(lab):
    r = lab.get("/api/scans/1/export/edges.csv?kind=access")
    assert r.status == 200 and "attachment" in r.headers["Content-Disposition"]
    assert len(list(csv.DictReader(io.StringIO(r.text)))) == 20
    r = lab.get("/api/scans/1/export/findings.csv?rule=key_unknown_origin&severity_min=high")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 3 and all(x["removal_hint"].startswith("delete line") for x in rows)
    j = lab.get("/api/scans/1/export/keys.json").json()
    assert j["scan"]["id"] == 1 and j["items"]
    h = lab.get("/api/scans/1/export/hosts.csv?status=partial").text
    assert len(list(csv.DictReader(io.StringIO(h)))) == 1
    assert lab.get("/api/scans/1/export/nope.csv").status == 404


def test_diff_1_2(lab):
    d = lab.get("/api/diff?a=1&b=2").json()
    edges_removed = {(e["src"], e["src_user"], e["dst"], e["dst_user"]) for e in d["edges"]["removed"] if e["kind"] == "access"}
    assert edges_removed == {("jump", "ops", "a5", "root"), ("b3", "ops2", "c2", "svc")}
    assert [(e["src"], e["dst"], e["dst_user"]) for e in d["edges"]["added"] if e["kind"] == "access"] == [("unknown", "b2", "www")]
    assert [k["fp"] for k in d["keys"]["added"]] == [key_fp("k_new")]
    assert [k["fp"] for k in d["keys"]["removed"]] == [key_fp("k_ca")]
    assert {f["rule"] for f in d["findings"]["added"]} == {"host_key_changed", "key_unknown_origin"}
    assert [(c["host"], c["changes"]["status"]) for c in d["hosts"]["changed"]] == [("c2", {"a": "ok", "b": "hostkey_mismatch"})]
    dl = lab.get("/api/diff?a=1&b=2&download=1")
    assert "attachment" in dl.headers["Content-Disposition"]


def test_scan3(lab):
    h = hosts(lab, 3)
    assert h["c2"]["status"] == "ok"
    assert h["a4"]["status"] == "partial" and h["a4"]["privilege"] == "unprivileged"


def test_search(lab):
    r = lab.get("/api/search?q=legacy-dsa&scan=1").json()
    assert [k["fp"] for k in r["keys"]] == [key_fp("k_dsa")]
    r = lab.get("/api/search?q=alice&scan=1").json()
    assert {(x["host"], x["username"]) for x in r["users"]} == {("a5", "alice"), ("b2", "alice")}
    assert all(isinstance(x["host_id"], int) for x in r["users"])
    r = lab.get("/api/search?q=172.30.3.21&scan=1").json()
    assert [x["display_name"] for x in r["hosts"]] == ["c1"]
    assert lab.get("/api/search?q=zzzz-nothing").json() == {"hosts": [], "keys": [], "users": [], "scan": 3}


def test_crawl_tree(lab):
    t = lab.get("/api/scans/1/crawl").json()
    by = {x["display_name"]: x for x in t["hosts"]}
    assert by["jump"]["parent_host_id"] is None
    assert by["c1"]["parent_host_id"] == by["b3"]["host_id"] and by["c2"]["parent_host_id"] == by["c1"]["host_id"]
    outcomes = Counter(r["outcome"] for r in t["references"])
    assert outcomes["alias"] == 2 and outcomes["already"] >= 2
    assert t["unresolved_hashed_total"] == 1
