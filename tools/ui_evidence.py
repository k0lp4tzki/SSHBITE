"""Screenshots of the running web UI for review (package P2 evidence).

    .venv/bin/python tools/ui_evidence.py OUT_DIR [--running-scan-config lab/sshbite.lab.yaml]

Starts the real app on three databases - a copy of tests/fixtures/lab_scans.db (scans 1-3 of a real lab run),
`synth --hosts 2000 --seed 42` and an empty one - and walks every screen in Chromium at 1440x900.
With --running-scan-config it also runs a real `sshbite scan` against the lab and photographs the live progress.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402

from sshbite import db as dbm  # noqa: E402
from sshbite.synth import synth  # noqa: E402
from tests.e2e.lab import key_fp  # noqa: E402
from tests.web.conftest import LAB_DB, PASSWORD, Server, _prepare  # noqa: E402


def u(fp):
    return fp.replace("+", "-").replace("/", "_")


class Shooter:
    def __init__(self, browser, base, out: Path, scheme="dark", w=1440, h=900, login=True):
        self.ctx = browser.new_context(viewport={"width": w, "height": h}, color_scheme=scheme,
                                       permissions=["clipboard-read", "clipboard-write"])
        self.p = self.ctx.new_page()
        self.base, self.out = base, out
        self.errors = []
        self.p.on("pageerror", lambda e: self.errors.append(str(e)))
        if login:
            self.p.goto(base + "/login")
            self.p.fill("input[name=username]", "admin")
            self.p.fill("input[name=password]", PASSWORD)
            self.p.click("button[type=submit]")
            self.p.wait_for_url(lambda x: "/login" not in x)
            self.p.wait_for_load_state("networkidle")

    def go(self, path, wait=None, settle=600):
        self.p.goto(self.base + path)
        if wait:
            self.p.wait_for_selector(wait, timeout=20000)
        self.p.wait_for_load_state("networkidle")
        self.p.wait_for_timeout(settle)

    def shot(self, name, full=True):
        self.p.screenshot(path=str(self.out / f"{name}.png"), full_page=full)
        print("  ", name)

    def close(self):
        if self.errors:
            print("page errors:", self.errors)
        self.ctx.close()


def heat_ready(p):
    p.wait_for_selector('canvas.cells[data-rendered]:not([data-rendered="0"])', timeout=20000)


def hover_cell(p, src, dst):
    c = p.locator("canvas.cells")
    rows = c.get_attribute("data-rows").split("|")
    cols = c.get_attribute("data-cols").split("|")
    pitch = int(c.get_attribute("data-pitch"))
    upos = int(c.get_attribute("data-unknown-pos"))
    r, k = rows.index(src), cols.index(dst)
    y = r * pitch + (6 if upos >= 0 and r >= upos else 0) + pitch / 2
    box = c.bounding_box()
    p.mouse.move(box["x"] + k * pitch + pitch / 2, box["y"] + y)
    return box["x"] + k * pitch + pitch / 2, box["y"] + y


def lab_screens(b, base, out):
    ids = {}
    s = Shooter(b, base, out)
    p = s.p
    for sid in (1, 2, 3):
        ids[sid] = {h["display_name"]: h["host_id"] for h in
                    p.request.get(f"{base}/api/scans/{sid}/hosts?page_size=1000").json()["items"]}
    h1 = ids[1]
    dsa, fleet = key_fp("k_dsa"), key_fp("k_fleet")
    s.go("/s/1/", "[data-stat]")
    s.shot("02-dashboard-scan1-dark")
    s.go("/s/3/", "[data-stat]")
    s.shot("02-dashboard-scan3-dark")
    s.go("/s/1/heatmap")
    heat_ready(p)
    s.shot("03-heatmap-host-dark")
    hover_cell(p, "jump", "a2")
    p.wait_for_selector(".tooltip")
    p.wait_for_timeout(500)
    s.shot("03-heatmap-host-tooltip-jump-a2", full=False)
    x, y = hover_cell(p, "jump", "a2")
    p.mouse.click(x, y)
    p.get_by_role("dialog").wait_for()
    p.wait_for_timeout(400)
    s.shot("03-heatmap-host-drawer-jump-a2", full=False)
    p.keyboard.press("Escape")
    hover_cell(p, "Unknown origin", "b1")
    p.wait_for_selector(".tooltip")
    p.wait_for_timeout(500)
    s.shot("03-heatmap-host-tooltip-unknown-origin", full=False)
    s.go("/s/1/heatmap?group_by=subnet")
    heat_ready(p)
    s.shot("03-heatmap-subnet-lab")
    s.go("/s/1/heatmap?view=table")
    s.shot("03-heatmap-table-view")
    s.go("/s/1/heatmap?layer=evidence")
    heat_ready(p)
    s.shot("03-heatmap-evidence-layer")
    s.go(f"/s/1/graph?host={h1['jump']}", "svg.g", settle=2200)
    s.shot("04-graph-around-jump")
    s.go(f"/s/1/graph?host={h1['jump']}&hops=2&layer=both", "svg.g", settle=2200)
    s.shot("04-graph-around-jump-2hops-both")
    s.go(f"/s/1/graph?key={u(dsa)}", "svg.g", settle=2200)
    p.locator(".link .hit").first.click(force=True)
    p.wait_for_timeout(600)
    s.shot("04-graph-around-k_dsa")
    s.go("/s/1/hosts", "table")
    s.shot("05-hosts")
    s.go("/s/1/hosts?status=partial", "table")
    s.shot("05-hosts-filter-partial")
    for name, tab in (("a1", ""), ("a1", "users"), ("a1", "access"), ("a1", "sshd"), ("a1", "findings"), ("c1", ""),
                      ("c1", "users"), ("b5", ""), ("172.30.1.99", ""), ("b3", "known_by"), ("a2", "sshd"),
                      ("b2", "access")):
        s.go(f"/s/1/hosts/{h1[name]}" + (f"?tab={tab}" if tab else ""), "h1")
        s.shot(f"06-host-{name}" + (f"-{tab}" if tab else ""))
    s.go(f"/s/2/hosts/{ids[2]['c2']}", "h1")
    s.shot("06-host-c2-scan2-host-key-changed")
    s.go(f"/s/3/hosts/{ids[3]['a4']}", "h1")
    s.shot("06-host-a4-scan3-partial")
    s.go("/s/1/keys", "table")
    s.shot("07-keys")
    s.go(f"/s/1/keys/{u(fleet)}", "header.kh")
    s.shot("08-key-k_fleet")
    s.go(f"/s/1/keys/{u(fleet)}?tab=private", "header.kh")
    s.shot("08-key-k_fleet-private-half")
    s.go(f"/s/1/keys/{u(dsa)}", "header.kh")
    p.get_by_label("Label").fill("contractor 2019 – remove")
    p.get_by_role("button", name="Save label").click()
    p.get_by_text("Saved", exact=True).wait_for()
    p.reload()
    p.wait_for_selector("form.lf")
    p.wait_for_timeout(500)
    s.shot("08-key-k_dsa-label-after-reload")
    s.go("/s/1/findings", "table")
    s.shot("09-findings-all")
    s.go("/s/1/findings?rule=key_unknown_origin&min=high", "table")
    s.shot("09-findings-key_unknown_origin-high")
    s.go("/s/1/crawl", "table")
    s.shot("10-crawl-tree")
    s.go("/scans", "table")
    p.locator("input[type=checkbox]").nth(1).check()
    p.locator("input[type=checkbox]").nth(2).check()
    s.shot("11-scans-two-selected")
    for tab in ("hosts", "keys", "placements", "edges", "findings"):
        s.go(f"/diff?a=1&b=2&tab={tab}", "table")
        s.shot(f"12-diff-1-2-{tab}")
    s.go("/s/1/", "[data-stat]")
    p.get_by_placeholder("Search hosts, keys, users").fill("alice")
    p.wait_for_selector(".results .res")
    s.shot("13-search-users", full=False)
    p.get_by_placeholder("Search hosts, keys, users").fill("legacy-dsa")
    p.wait_for_timeout(600)
    s.shot("13-search-legacy-dsa", full=False)
    # states: loading and error, by holding / failing the API in the browser
    p.route("**/api/scans/1/heatmap?*", lambda r: (time.sleep(1.5), r.continue_()))
    p.goto(base + "/s/1/heatmap")
    p.wait_for_timeout(700)
    s.shot("14-state-loading-heatmap", full=False)
    p.unroute("**/api/scans/1/heatmap?*")
    p.route("**/api/scans/1/hosts?*", lambda r: (time.sleep(1.5), r.continue_()))
    p.goto(base + "/s/1/hosts")
    p.wait_for_timeout(700)
    s.shot("14-state-loading-hosts-skeleton", full=False)
    p.unroute("**/api/scans/1/hosts?*")
    p.route("**/api/scans/1/findings?*", lambda r: r.fulfill(status=503, content_type="application/json",
            body=json.dumps({"error": {"code": "database_unavailable", "message": "database is locked"}})))
    s.go("/s/1/findings")
    s.shot("14-state-error-findings", full=False)
    s.close()

    # light theme
    s = Shooter(b, base, out, scheme="light")
    s.go("/s/1/", "[data-stat]")
    s.shot("20-light-dashboard")
    s.go("/s/1/heatmap")
    heat_ready(s.p)
    s.shot("20-light-heatmap")
    s.go(f"/s/1/hosts/{h1['a1']}?tab=users", "h1")
    s.shot("20-light-host-a1-users")
    s.go(f"/s/1/hosts/{h1['c1']}", "h1")
    s.shot("20-light-host-c1")
    s.go("/s/1/findings", "table")
    s.shot("20-light-findings")
    s.go(f"/s/1/graph?host={h1['jump']}", "svg.g", settle=2200)
    s.shot("20-light-graph-jump")
    s.close()

    # login screens
    s = Shooter(b, base, out, login=False)
    p = s.p
    conn = dbm.connect(str(Path(base_db[base])))
    from sshbite.users import add_user
    add_user(conn, "lockme", PASSWORD)
    conn.close()
    p.goto(base + "/login")
    p.wait_for_selector("form")
    s.shot("01-login")
    p.fill("input[name=username]", "lockme")
    p.fill("input[name=password]", "wrong password")
    p.click("button[type=submit]")
    p.get_by_text("Wrong username or password.").wait_for()
    s.shot("01-login-error")
    for i in range(5):
        p.fill("input[name=password]", f"wrong {i}")
        p.click("button[type=submit]")
        p.wait_for_timeout(300)
    p.get_by_text(re.compile("This account is locked")).wait_for()
    s.shot("01-login-lockout")
    p.goto(base + "/login?expired=1")
    s.shot("01-login-session-ended")
    s.close()

    # sizes
    s = Shooter(b, base, out, w=1280, h=800)
    s.go("/s/1/heatmap")
    heat_ready(s.p)
    s.shot("40-heatmap-1280x800", full=False)
    s.go(f"/s/1/hosts/{h1['a1']}?tab=users", "h1")
    s.shot("40-host-a1-users-1280x800", full=False)
    s.close()
    s = Shooter(b, base, out, w=375, h=812)
    s.go("/s/1/", "[data-stat]")
    s.shot("41-dashboard-375")
    s.go(f"/s/1/hosts/{h1['c1']}", "h1")
    s.shot("41-host-c1-375")
    s.go("/s/1/heatmap")
    heat_ready(s.p)
    s.shot("41-heatmap-375")
    s.close()


def synth_screens(b, base, out):
    s = Shooter(b, base, out)
    p = s.p
    s.go("/s/1/", "[data-stat]")
    s.shot("30-synth-dashboard")
    t0 = time.monotonic()
    s.go("/s/1/heatmap", settle=0)
    heat_ready(p)
    print(f"   synth subnet heatmap rendered in {time.monotonic() - t0:.2f} s")
    p.wait_for_timeout(300)
    s.shot("30-synth-heatmap-subnet-2000")
    c = p.locator("canvas.cells")
    rows, cols = c.get_attribute("data-rows").split("|"), c.get_attribute("data-cols").split("|")
    hover_cell(p, rows[0], cols[1])
    p.wait_for_selector(".tooltip .pairs")
    s.shot("30-synth-heatmap-tooltip-top-pairs", full=False)
    x, y = hover_cell(p, rows[0], cols[1])
    p.mouse.click(x, y)
    p.wait_for_url(re.compile(".*src=.*"))
    heat_ready(p)
    p.wait_for_timeout(300)
    s.shot("30-synth-heatmap-drilldown-subnet-cell")
    c = p.locator("canvas.cells")
    rows, cols = c.get_attribute("data-rows").split("|"), c.get_attribute("data-cols").split("|")
    hover_cell(p, rows[0], cols[0])
    p.wait_for_timeout(500)
    s.shot("30-synth-heatmap-drilldown-hover", full=False)
    s.go("/s/1/heatmap?src=*&dst=*")
    heat_ready(p)
    s.shot("30-synth-heatmap-top-100x100")
    hub = p.request.get(f"{base}/api/scans/1/ranking?direction=out&limit=1").json()["items"][0]["host_id"]
    s.go(f"/s/1/graph?host={hub}", "svg.g", settle=2500)
    s.shot("30-synth-graph-hub-truncated")
    for path, name in (("/s/1/hosts", "hosts"), ("/s/1/keys", "keys"), ("/s/1/findings", "findings"),
                       ("/s/1/crawl", "crawl-tree"), (f"/s/1/hosts/{hub}", "host-hub")):
        s.go(path, settle=800)
        s.shot(f"30-synth-{name}", full=False)
    s.close()


def empty_screens(b, base, out):
    s = Shooter(b, base, out)
    s.go("/", "h2")
    s.shot("50-empty-dashboard")
    s.go("/scans", "table")
    s.shot("50-empty-scans")
    s.close()


def running_scan(b, out, config: Path):
    """A real lab scan, photographed while it runs."""
    import yaml

    tmp = Path(tempfile.mkdtemp())
    db = tmp / "running.db"
    shutil.copy(LAB_DB, db)
    db.chmod(0o600)
    cfg = yaml.safe_load(config.read_text())
    cfg["database"] = str(db)
    cpath = tmp / "c.yaml"
    cpath.write_text(yaml.safe_dump(cfg))
    cpath.chmod(0o600)
    conn = dbm.connect(str(db))
    from sshbite.users import add_user
    add_user(conn, "admin", PASSWORD)
    conn.close()
    with Server(str(db)) as srv:
        s = Shooter(b, srv.base, out)
        s.go("/s/3/", "[data-stat]")
        env = dict(os.environ, SSHBITE_SUDO_PASSWORD="labsudo")
        proc = subprocess.Popen([sys.executable, "-m", "sshbite.cli", "-c", str(cpath), "scan", "--label", "live"],
                                cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        shot_mid = False
        for _ in range(240):
            time.sleep(0.5)
            prog = s.p.locator("section.prog p")
            if prog.count():
                m = re.search(r"(\d+) done", prog.inner_text())
                if m and int(m.group(1)) >= 5 and not shot_mid:
                    s.shot("15-dashboard-running-scan-progress", full=False)
                    shot_mid = True
            if s.p.locator(".toast").count():
                s.shot("15-dashboard-scan-completed-toast", full=False)
                break
        output, _ = proc.communicate(timeout=300)
        (out / "15-running-scan-console.txt").write_text(output)
        s.go("/s/4/", "[data-stat]")
        s.shot("15-dashboard-scan4-after-live-scan", full=False)
        s.close()


base_db: dict[str, str] = {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--running-scan-config")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    (tmp / "lab").mkdir()
    (tmp / "syn").mkdir()
    (tmp / "empty").mkdir()
    syn_path = _prepare(tmp / "syn", None)
    conn = dbm.connect(syn_path)
    synth(conn, 2000, 42)
    conn.close()
    lab_path = _prepare(tmp / "lab", LAB_DB)
    with Server(lab_path) as lab, Server(syn_path) as syn, Server(_prepare(tmp / "empty", None)) as empty, \
            sync_playwright() as pwr:
        base_db[lab.base] = lab_path
        b = pwr.chromium.launch(args=["--no-sandbox"])
        print("lab data")
        lab_screens(b, lab.base, out)
        print("synthetic 2000")
        synth_screens(b, syn.base, out)
        print("empty")
        empty_screens(b, empty.base, out)
        if a.running_scan_config:
            print("running scan")
            running_scan(b, out, Path(a.running_scan_config))
        b.close()


if __name__ == "__main__":
    main()
