"""Spec 9.4 performance targets on `synth --hosts 2000 --seed 42`."""

from __future__ import annotations

import time

from sshbite import db as dbm
from sshbite.synth import synth

from .conftest import Client, Server, _prepare


def test_synth_2000_targets(tmp_path):
    path = _prepare(tmp_path, None)
    conn = dbm.connect(path)
    res = synth(conn, 2000, 42)
    conn.close()
    sid = res["scan_id"]
    with Server(path) as srv:
        c = Client(srv.base)
        c.login()

        def timed(url):
            t = time.perf_counter()
            r = c.get(url)
            return r, time.perf_counter() - t

        r, t_hm = timed(f"/api/scans/{sid}/heatmap?group_by=subnet")      # cold: builds the scan view
        hm = r.json()
        assert len([x for x in hm["rows"] if x["kind"] == "group"]) == 40 and len(hm["cols"]) == 40
        assert hm["rows"][-1]["kind"] == "unknown"
        assert t_hm < 1.0, t_hm
        r, t_auto = timed(f"/api/scans/{sid}/heatmap")
        assert r.json()["group_by"] == "subnet" and t_auto < 1.0
        src, dst = hm["rows"][0]["id"], hm["cols"][1]["id"]
        r, t_dd = timed(f"/api/scans/{sid}/heatmap?group_by=subnet&src_group={src}&dst_group={dst}")
        dd = r.json()
        assert dd["level"] == "hosts" and len(dd["rows"]) <= 100 and len(dd["cols"]) <= 100 and t_dd < 1.0
        r, t_all = timed(f"/api/scans/{sid}/heatmap?group_by=subnet&src_group=*&dst_group=*")
        assert len(r.json()["rows"]) == 100 and r.json()["hidden"] > 0 and t_all < 1.0
        r, t_rank = timed(f"/api/scans/{sid}/ranking?direction=out&metric=hosts&limit=25")
        assert r.json()["items"][0]["value"] > 200 and t_rank < 0.3, t_rank
        hub = r.json()["items"][0]["host_id"]
        r, t_graph = timed(f"/api/scans/{sid}/graph?center_host={hub}&hops=2")
        g = r.json()
        assert len(g["nodes"]) <= 150 and g["truncated"] and t_graph < 0.5, t_graph
        r, t_cell = timed(f"/api/scans/{sid}/heatmap/cell?group_by=subnet&src_group={src}&dst_group={dst}")
        assert len(r.json()["pairs"]) <= 5 and t_cell < 0.5
        print(f"\nsynth 2000: heatmap(subnet, cold) {t_hm*1000:.0f} ms, drill {t_dd*1000:.0f} ms, "
              f"ranking {t_rank*1000:.0f} ms, graph {t_graph*1000:.0f} ms, cell {t_cell*1000:.0f} ms")
