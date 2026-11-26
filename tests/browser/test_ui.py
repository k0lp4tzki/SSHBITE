"""Browser checks (spec 9.4, design checklist §10 items 3, 4, 5, 12, 13) with Playwright + Chromium.

Runs against real lab scan data (tests/fixtures/lab_scans.db: scans 1-3 of a P1 lab run), against
`synth --hosts 2000 --seed 42` and against an empty database. Needs the built frontend
(`npm ci && npm run build` in frontend/) and `pip install playwright` (browsers: `playwright install chromium`).
Set SSHBITE_EVIDENCE_DIR to keep screenshots.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pytest

pw = pytest.importorskip("playwright.sync_api")

from sshbite import db as dbm  # noqa: E402
from sshbite.synth import synth  # noqa: E402
from sshbite.web.app import static_dir  # noqa: E402
from tests.e2e.lab import key_fp  # noqa: E402
from tests.web.conftest import LAB_DB, PASSWORD, Server, _prepare  # noqa: E402

pytestmark = pytest.mark.skipif(not (static_dir() / "index.html").is_file(), reason="frontend not built")
EVIDENCE = os.environ.get("SSHBITE_EVIDENCE_DIR")


def u(fp: str) -> str:
    return fp.replace("+", "-").replace("/", "_")


# ---------------------------------------------------------------- fixtures

@pytest.fixture(scope="module")
def servers(tmp_path_factory):
    lab_dir = tmp_path_factory.mktemp("lab")
    syn_dir = tmp_path_factory.mktemp("syn")
    empty_dir = tmp_path_factory.mktemp("empty")
    syn_path = _prepare(syn_dir, None)
    conn = dbm.connect(syn_path)
    synth(conn, 2000, 42)
    conn.close()
    with Server(_prepare(lab_dir, LAB_DB)) as lab, Server(syn_path) as syn, Server(_prepare(empty_dir, None)) as empty:
        yield {"lab": lab, "syn": syn, "empty": empty}


@pytest.fixture(scope="module")
def browser():
    with pw.sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        yield b
        b.close()


class Session:
    """A logged-in page that records every request it makes."""

    def __init__(self, browser, base: str, scheme: str = "dark", width: int = 1440, height: int = 900, login=True,
                 reduced: bool = False):
        self.base = base
        self.ctx = browser.new_context(viewport={"width": width, "height": height}, color_scheme=scheme,
                                       permissions=["clipboard-read", "clipboard-write"],
                                       reduced_motion="reduce" if reduced else "no-preference")
        self.page = self.ctx.new_page()
        self.requests: list[str] = []
        self.errors: list[str] = []
        self.page.on("request", lambda r: self.requests.append(r.url))
        self.page.on("pageerror", lambda e: self.errors.append(str(e)))
        if login:
            self.login()

    def login(self, user="admin", password=PASSWORD):
        p = self.page
        p.goto(self.base + "/login")
        p.fill("input[name=username]", user)
        p.fill("input[name=password]", password)
        p.click("button[type=submit]")
        p.wait_for_url(lambda url: "/login" not in url)
        p.wait_for_load_state("networkidle")

    def go(self, path: str, wait: str | None = None):
        self.page.goto(self.base + path)
        if wait:
            self.page.wait_for_selector(wait, timeout=15000)
        else:
            self.page.wait_for_load_state("networkidle")

    def shot(self, name: str, full=True):
        if EVIDENCE:
            Path(EVIDENCE).mkdir(parents=True, exist_ok=True)
            self.page.screenshot(path=str(Path(EVIDENCE) / f"{name}.png"), full_page=full)

    def close(self):
        assert not self.errors, self.errors
        self.ctx.close()


@pytest.fixture
def lab(browser, servers):
    s = Session(browser, servers["lab"].base)
    yield s
    s.close()


@pytest.fixture
def syn(browser, servers):
    s = Session(browser, servers["syn"].base)
    yield s
    s.close()


def heat(page):
    c = page.locator("canvas.cells")
    c.wait_for(timeout=15000)
    page.wait_for_selector('canvas.cells[data-rendered]:not([data-rendered="0"])', timeout=15000)
    return {k: c.get_attribute(f"data-{k}") for k in ("pitch", "gap", "rows", "cols", "rendered", "unknown-pos")}


def click_cell(page, src: str, dst: str):
    h = heat(page)
    rows, cols, pitch = h["rows"].split("|"), h["cols"].split("|"), int(h["pitch"])
    r, c = rows.index(src), cols.index(dst)
    upos = int(h["unknown-pos"])
    y = r * pitch + (6 if upos >= 0 and r >= upos else 0) + pitch / 2
    page.locator("canvas.cells").click(position={"x": c * pitch + pitch / 2, "y": y})


# ---------------------------------------------------------------- spec 9.4

def test_1_login_logout_wrong_password_and_lockout(browser, servers):
    from sshbite.users import add_user
    conn = dbm.connect(servers["lab"].db_path)
    add_user(conn, "lockme", PASSWORD)
    add_user(conn, "auditor", PASSWORD)
    conn.close()
    s = Session(browser, servers["lab"].base, login=False)
    p = s.page
    p.goto(s.base + "/s/1/heatmap")
    p.wait_for_url(re.compile(r".*/login.*"))
    p.fill("input[name=username]", "lockme")
    p.fill("input[name=password]", "wrong password")
    p.click("button[type=submit]")
    p.get_by_text("Wrong username or password.").wait_for()
    assert p.input_value("input[name=password]") == ""
    s.shot("01-login-error")
    for i in range(4):
        p.fill("input[name=password]", f"wrong {i}")
        p.click("button[type=submit]")
        p.get_by_text("Wrong username or password.").wait_for()
    p.fill("input[name=password]", "wrong 6")   # the 6th failure
    p.click("button[type=submit]")
    p.get_by_text(re.compile(r"This account is locked after 5 failed attempts\. Try again in 1[45] minutes\.")).wait_for()
    s.shot("01-login-lockout")
    s.close()
    # another account works and logout ends the session
    s = Session(browser, servers["lab"].base, login=False)
    s.login("auditor")
    p = s.page
    p.wait_for_url(re.compile(r".*/s/3/$"))
    p.get_by_role("button", name=re.compile("auditor")).click()
    p.get_by_role("menuitem", name="Log out").click()
    p.wait_for_url(re.compile(r".*/login$"))
    p.goto(s.base + "/s/1/")
    p.wait_for_url(re.compile(r".*/login.*"))
    s.close()


def test_2_dashboard_counts_equal_api(lab):
    p = lab.page
    for sid in (1, 2, 3):
        lab.go(f"/s/{sid}/", wait="[data-stat]")
        api = p.request.get(f"{lab.base}/api/scans/{sid}").json()["counts"]
        for sev in ("critical", "high", "medium", "low", "info"):
            want = api["findings"].get(sev, 0)
            el = p.locator(f'[data-stat="Findings by severity:{sev}"] .figure')
            got = int(el.inner_text().replace(",", "")) if el.count() else 0
            assert got == want, (sid, sev)
        hosts = api["hosts"]
        assert int(p.locator('[data-stat="Hosts by status:ok"] .figure').inner_text()) == hosts.get("ok", 0)
        if hosts.get("partial"):
            assert int(p.locator('[data-stat="Hosts by status:partial"] .figure').inner_text()) == hosts["partial"]
        keys = p.request.get(f"{lab.base}/api/scans/{sid}/keys?page_size=1").json()["strength_counts"]
        for k, v in keys.items():
            assert int(p.locator(f'[data-stat="Keys by strength:{k}"] .figure').inner_text()) == v
        top = p.request.get(f"{lab.base}/api/scans/{sid}/findings?page_size=10").json()["items"]
        assert p.locator(".tf li").count() == len(top) == 10
    lab.go("/s/1/", wait="[data-stat]")
    assert p.locator(".rank").first.locator("li").first.inner_text().startswith("a2")
    assert p.locator(".rank").nth(1).locator("li").first.inner_text().startswith("jump")


def test_3_heatmap_host_grouping_jump_a2(lab):
    p = lab.page
    lab.go("/s/1/heatmap")
    h = heat(p)
    assert int(h["pitch"]) >= 20                      # numbers are printed in the cells (checklist 6)
    rows, cols = h["rows"].split("|"), h["cols"].split("|")
    assert "jump" in rows and "a2" in cols and rows[-1] == "Unknown origin"
    # value via the keyboard grid and its live region
    p.locator("canvas.cells").focus()
    r, c = rows.index("jump"), cols.index("a2")
    for _ in range(r):
        p.keyboard.press("ArrowDown")
    for _ in range(c):
        p.keyboard.press("ArrowRight")
    p.get_by_text("jump to a2: 1 host pair").wait_for(state="attached")
    p.locator(".tooltip").get_by_text("jump → a2").wait_for()
    lab.shot("03-heatmap-host-tooltip-jump-a2", full=False)
    p.keyboard.press("Escape")
    p.mouse.move(0, 0)
    click_cell(p, "jump", "a2")
    d = p.get_by_role("dialog", name="jump → a2")
    d.wait_for()
    d.get_by_text("1 access edge").wait_for()
    assert "ops" in d.inner_text() and "root" in d.inner_text()
    lab.shot("03-heatmap-host-drawer-jump-a2", full=False)
    p.keyboard.press("Escape")
    # the table view lists the same cell
    p.get_by_role("button", name="Table view").click()
    row = p.locator("tr", has_text="jump").filter(has_text="a2").first
    assert row.locator("td").nth(2).inner_text().strip() == "1"
    # a label opens the Host screen
    p.get_by_role("button", name="Matrix view").click()
    heat(p)
    box = p.locator("canvas.rows").bounding_box()
    rows = heat(p)["rows"].split("|")
    pitch = int(heat(p)["pitch"])
    p.mouse.click(box["x"] + box["width"] - 20, box["y"] + rows.index("a1") * pitch + pitch / 2)
    p.wait_for_url(re.compile(r".*/s/1/hosts/\d+$"))
    p.get_by_role("heading", name="a1").wait_for()


def test_4_subnet_heatmap_2000_hosts_fast_and_drilldown(syn):
    p = syn.page
    t0 = time.monotonic()
    syn.go("/s/1/heatmap")
    h = heat(p)
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0, elapsed
    rows, cols = h["rows"].split("|"), h["cols"].split("|")
    assert len(cols) == 40 and len(rows) == 41 and rows[-1] == "Unknown origin"
    assert int(h["pitch"]) >= 12          # every label drawn
    p.get_by_text("SYNTHETIC DATA").first.wait_for()
    syn.shot("04-heatmap-subnet-2000")
    click_cell(p, rows[0], cols[1])
    p.wait_for_url(re.compile(r".*src=.*dst=.*"))
    p.get_by_role("navigation", name="Breadcrumb").get_by_text(f"{rows[0]} → {cols[1]}").wait_for()
    h2 = heat(p)
    assert len(h2["rows"].split("|")) == 50 and all(x.startswith("syn-") for x in h2["rows"].split("|"))
    syn.shot("04-heatmap-drilldown-2000")
    p.keyboard.press("Backspace")
    p.wait_for_url(re.compile(r".*/s/1/heatmap$"))
    assert len(heat(p)["cols"].split("|")) == 40
    # all groups -> all: top 100 x 100, every 2nd label, truncation note
    syn.go("/s/1/heatmap?src=*&dst=*")
    h3 = heat(p)
    assert len(h3["rows"].split("|")) == 100 and len(h3["cols"].split("|")) == 100
    p.get_by_text(re.compile(r"Showing the top 100 × 100 hosts by total; [\d,]+ more hosts hidden\.")).wait_for()


def test_5_host_discovered_via_and_routes(lab):
    p = lab.page
    hosts = {h["display_name"]: h["host_id"] for h in p.request.get(f"{lab.base}/api/scans/1/hosts?page_size=100").json()["items"]}
    lab.go(f"/s/1/hosts/{hosts['a1']}", wait="h1")
    line = " ".join(p.locator(".line").first.inner_text().split())
    assert "discovered via jump /home/ops/.ssh/config:2" in line
    assert "route jump → a1" in line
    lab.shot("05-host-a1")
    lab.go(f"/s/1/hosts/{hosts['c1']}", wait="h1")
    assert "route jump → b3 → c1" in " ".join(p.locator(".line").first.inner_text().split())
    lab.shot("05-host-c1")


def test_6_key_dsa(lab):
    p = lab.page
    lab.go("/s/1/", wait="[data-stat]")
    p.get_by_placeholder("Search hosts, keys, users").fill("legacy-dsa")
    p.locator(".results .res").first.click()
    p.wait_for_url(re.compile(r".*/s/1/keys/.*"))
    p.get_by_role("tab", name="Authorized on (2)").wait_for()
    rows = [r.split("\t")[:2] for r in p.locator("table").first.locator("tbody tr").all_inner_texts()]
    assert sorted(rows) == [["a4", "root"], ["b1", "root"]]
    head = p.locator("header.kh").inner_text()
    # design-revision §5.4: Origin is a context field (label above value), no longer the inline "origin:" label
    assert "Critical" in head and "dsa 1024" in head and "Origin\nUnknown" in head
    lab.shot("06-key-dsa")


def test_7_label_persists_and_put_without_csrf_403(lab):
    p = lab.page
    dsa = key_fp("k_dsa")
    lab.go(f"/s/1/keys/{u(dsa)}", wait="form.lf")
    p.get_by_label("Label").fill("contractor 2019 – remove")
    p.get_by_role("button", name="Save label").click()
    p.get_by_text("Saved", exact=True).wait_for()
    p.reload()
    p.wait_for_selector("form.lf")
    assert p.get_by_label("Label").input_value() == "contractor 2019 – remove"
    assert "contractor 2019 – remove" in p.locator("header.kh").inner_text()
    r = p.request.put(f"{lab.base}/api/keys/{u(dsa)}/label", data={"label": "x"})
    assert r.status == 403
    assert p.request.get(f"{lab.base}/api/scans/1/keys/{u(dsa)}").json()["label"]["label"] == "contractor 2019 – remove"


def test_8_synthetic_banner_on_every_screen(syn):
    p = syn.page
    hub = p.request.get(f"{syn.base}/api/scans/1/ranking?direction=out&limit=1").json()["items"][0]["host_id"]
    fp = p.request.get(f"{syn.base}/api/scans/1/keys?page_size=1").json()["items"][0]["fp"]
    for path in ("/s/1/", "/s/1/heatmap", f"/s/1/graph?host={hub}", "/s/1/hosts", f"/s/1/hosts/{hub}", "/s/1/keys",
                 f"/s/1/keys/{u(fp)}", "/s/1/findings", "/s/1/crawl"):
        syn.go(path)
        banner = p.get_by_role("note")
        banner.wait_for()
        assert "SYNTHETIC DATA – generated by sshbite synth, not from real hosts" in banner.inner_text(), path


def test_9_no_request_leaves_the_origin(browser, servers):
    s = Session(browser, servers["lab"].base)
    hosts = s.page.request.get(f"{s.base}/api/scans/1/hosts?page_size=100").json()["items"]
    for path in ("/s/1/", "/s/1/heatmap", "/s/1/graph?host=1", "/s/1/hosts", f"/s/1/hosts/{hosts[0]['host_id']}",
                 "/s/1/keys", "/s/1/findings", "/s/1/crawl", "/scans", "/diff?a=1&b=2"):
        s.go(path)
    s.page.wait_for_timeout(500)
    assert s.requests
    # design-revision §3.4: Mono only for copyable strings - the last page above (/diff, hosts tab) has none any
    # more, so the font check runs on a page with fingerprints
    s.go("/s/1/findings")
    outside = [r for r in s.requests if not (r.startswith(s.base + "/") or r.startswith("data:"))]
    assert outside == []
    # fonts come from the origin (checklist 12)
    fonts = s.page.evaluate("[...document.fonts].filter(f => f.status === 'loaded').map(f => f.family)")
    assert any("Plex Sans" in f for f in fonts) and any("Plex Mono" in f for f in fonts)
    assert any("/fonts/ibm-plex" in r for r in s.requests)
    s.close()


def test_10_empty_states_on_empty_db(browser, servers):
    s = Session(browser, servers["empty"].base)
    p = s.page
    p.get_by_role("heading", name="No scans yet").wait_for()
    p.get_by_text("sshbite scan --ask-sudo-password").wait_for()
    p.get_by_text("This page updates as soon as a scan is running.").wait_for()
    s.shot("10-empty-dashboard")
    s.go("/scans")
    p.get_by_text("No scans yet. Run sshbite scan.").wait_for()
    for path in ("/s/1/heatmap", "/s/1/hosts", "/diff"):
        s.go(path)
        p.get_by_role("heading", name="No scans yet").wait_for()
    s.close()


def test_empty_lists_and_filters(lab):
    p = lab.page
    lab.go("/s/1/findings?q=nothing-matches-this")
    p.get_by_text("No findings of this kind in scan #1.").wait_for()
    lab.go("/s/1/hosts?q=nothing-matches-this")
    p.get_by_text("No hosts match these filters in scan #1.").wait_for()
    lab.go("/s/1/keys?q=nothing-matches-this")
    p.get_by_text("No keys match these filters in scan #1.").wait_for()


# ---------------------------------------------------------------- design checklist §10

def _ratio(a, b):
    def lum(rgb):
        def f(c):
            c = c / 255
            return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
        return 0.2126 * f(rgb[0]) + 0.7152 * f(rgb[1]) + 0.0722 * f(rgb[2])
    la, lb = sorted([lum(a), lum(b)], reverse=True)
    return (la + 0.05) / (lb + 0.05)


TEXT_PAIRS = [(fg, bg) for fg in ("text-primary", "text-secondary", "text-muted", "accent")
              for bg in ("bg-page", "bg-surface", "bg-raised", "bg-sunken", "bg-hover", "bg-selected")]
TEXT_PAIRS += [(s, s + "-bg") for s in ("critical", "high", "medium", "low", "info", "good")]
TEXT_PAIRS += [(s, bg) for s in ("critical", "high", "medium", "low", "info", "good") for bg in ("bg-surface", "bg-raised")]
TEXT_PAIRS += [("on-accent", "accent"), ("synthetic-text", "synthetic-bg"), ("accent", "accent-subtle")]
TEXT_PAIRS += [(f"ink-{i}", f"ramp-{i}") for i in range(1, 10)]   # numbers printed in heatmap cells


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_c3_contrast_computed_in_both_themes(browser, servers, scheme):
    s = Session(browser, servers["lab"].base, scheme=scheme)
    s.go("/s/1/", wait="[data-stat]")
    vals = s.page.evaluate("""names => { const cs = getComputedStyle(document.documentElement);
        return Object.fromEntries(names.map(n => [n, cs.getPropertyValue('--' + n).trim()])); }""",
                           sorted({x for pair in TEXT_PAIRS for x in pair}))

    missing = [(k, v) for k, v in vals.items() if not re.fullmatch(r"#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}", v)]
    assert not missing, missing

    def rgb(h):
        h = h.lstrip("#")
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

    report = []
    fails = []
    for fg, bg in TEXT_PAIRS:
        r = _ratio(rgb(vals[fg]), rgb(vals[bg]))
        report.append(f"{scheme:5} {fg:16} on {bg:14} {vals[fg]} / {vals[bg]}  {r:5.2f}:1")
        if r < 4.5:
            fails.append(report[-1])
    if EVIDENCE:
        Path(EVIDENCE, f"contrast-{scheme}.txt").write_text("\n".join(report) + "\n")
    # non-text marks >= 3:1: severity colours and the accent against the surface
    for mark in ("critical", "high", "medium", "low", "info", "good", "accent", "border-strong"):
        if mark == "border-strong":
            continue  # input borders carry no information on their own; labels and placeholders do
        assert _ratio(rgb(vals[mark]), rgb(vals["bg-surface"])) >= 3
    assert not fails, fails
    s.close()


def test_c4_severity_and_strength_have_glyph_and_label(lab):
    p = lab.page
    for path in ("/s/1/findings", "/s/1/keys", "/s/1/hosts", "/s/1/"):
        lab.go(path)
        badges = p.locator(".badge:not(.compact)")
        assert badges.count() > 0
        for i in range(badges.count()):
            b = badges.nth(i)
            assert b.locator("svg.glyph").count() == 1, (path, b.inner_text())
            assert b.inner_text().strip(), path
        for i in range(p.locator(".badge.compact").count()):   # compact form: glyph + count + hidden label
            b = p.locator(".badge.compact").nth(i)
            assert b.locator("svg.glyph").count() == 1 and b.locator(".sr-only").inner_text().strip()
    # the five severities have five different shapes
    lab.go("/s/1/", wait="[data-stat]")
    shapes = p.evaluate("""() => Object.fromEntries(['critical','high','medium','low','info'].map(s => {
        const a = document.querySelector(`[data-stat="Findings by severity:${s}"] svg`);
        return [s, a ? a.innerHTML.replace(/class="[^"]*"/g, '') : null]; }))""")
    present = {k: v for k, v in shapes.items() if v}
    assert len(set(present.values())) == len(present) >= 4
    if EVIDENCE:
        p.evaluate("document.documentElement.style.filter = 'grayscale(1)'")
        lab.shot("c4-dashboard-greyscale", full=False)
        lab.go("/s/1/findings")
        p.evaluate("document.documentElement.style.filter = 'grayscale(1)'")
        lab.shot("c4-findings-greyscale", full=False)


def test_c5_fingerprints_mono_and_exact_copy(lab):
    p = lab.page
    fleet = key_fp("k_fleet")
    lab.go(f"/s/1/keys/{u(fleet)}", wait="header.kh")
    fam = p.evaluate("getComputedStyle(document.querySelector('header.kh .fp')).fontFamily")
    assert "IBM Plex Mono" in fam
    shown = p.locator("header.kh .fp").inner_text()
    assert " " not in fleet and shown.replace(" ", "") == fleet
    p.locator("header.kh button.copy").click()
    p.get_by_text("Copied").wait_for()
    assert p.evaluate("navigator.clipboard.readText()") == fleet
    lab.shot("c5-key-fleet")
    for path in ("/s/1/findings", "/s/1/keys"):
        lab.go(path)
        fams = p.evaluate("[...document.querySelectorAll('.fp')].map(e => getComputedStyle(e).fontFamily)")
        assert fams and all("IBM Plex Mono" in f for f in fams)


SCREENS = ["/s/1/", "/s/1/heatmap", "/s/1/graph?host=1", "/s/1/hosts", "/s/1/hosts/2", "/s/1/hosts/2?tab=users",
           "/s/1/keys", "/s/1/findings", "/s/1/crawl", "/scans", "/diff?a=1&b=2"]


def test_c13_no_horizontal_page_scroll_at_1280_and_375(browser, servers):
    for width, height in ((1280, 800), (375, 812)):
        s = Session(browser, servers["lab"].base, width=width, height=height)
        for path in SCREENS + [f"/s/1/keys/{u(key_fp('k_dsa'))}"]:
            s.go(path)
            s.page.wait_for_timeout(300)
            sw = s.page.evaluate("document.documentElement.scrollWidth")
            assert sw <= width, (width, path, sw)
        if width == 1280:
            s.go("/s/1/heatmap")
            heat(s.page)
            s.shot("13-heatmap-1280x800", full=False)
        else:
            s.go("/s/1/")
            s.page.wait_for_selector("[data-stat]")
            s.shot("13-dashboard-375")
        s.close()


# ---------------------------------------------------------------- corrections from the QA check (check-6)

def _host_ids(s, scan: int) -> dict[str, int]:
    return {h["display_name"]: h["host_id"]
            for h in s.page.request.get(f"{s.base}/api/scans/{scan}/hosts?page_size=1000").json()["items"]}


def test_f1_route_attempts_on_host_detail_and_crawl_tree(lab):
    """c1 was reached via b3 after the direct route failed: both attempts are on its page without a tab click."""
    p = lab.page
    ids = _host_ids(lab, 1)
    lab.go(f"/s/1/hosts/{ids['c1']}", wait="h1")
    t = p.get_by_role("table", name="Route attempts")
    t.wait_for()
    rows = [" ".join(r.split()) for r in t.locator("tbody tr").all_inner_texts()]
    assert rows == ["jump → c1 172.30.3.21: timeout", "jump → b3 → c1 ok"], rows
    assert p.get_by_role("tab", name="Overview").get_attribute("aria-selected") == "true"
    lab.shot("f1-host-c1-route-attempts", full=False)
    # c2 likewise (direct jump → c2 failed, jump → b3 → c1 → c2 worked); a1 had no failed attempt: no block
    lab.go(f"/s/1/hosts/{ids['c2']}", wait="h1")
    assert p.get_by_role("table", name="Route attempts").locator("tbody tr").count() == 2
    lab.go(f"/s/1/hosts/{ids['a1']}", wait="h1")
    assert p.get_by_role("table", name="Route attempts").count() == 0
    # an unreachable host keeps its table in the strip
    lab.go(f"/s/1/hosts/{ids['172.30.1.99']}", wait="h1")
    strip = p.locator(".strip", has_text="Not scanned: unreachable.")
    assert strip.locator("tbody tr").count() == 2
    # crawl tree: "1 failed attempt" (design-revision §5.8: the ↺ glyph is gone) opens the inline list
    lab.go("/s/1/crawl", wait="tr[data-tree]")
    row = p.locator("tr[data-tree]", has=p.locator("td.hcell").get_by_role("link", name="c1", exact=True))
    row.get_by_role("button", name="1 failed attempt").click()
    lst = row.get_by_role("list", name="Route attempts")
    assert [" ".join(x.split()) for x in lst.locator("li").all_inner_texts()] == \
        ["jump → c1 172.30.3.21: timeout", "jump → b3 → c1 ok"]


def test_f2_tabs_of_a_host_that_was_not_scanned(lab):
    p = lab.page
    ids = _host_ids(lab, 2)
    lab.go(f"/s/2/hosts/{ids['c2']}", wait="h1")
    p.get_by_text("Host key changed – not scanned.").wait_for()
    tabs = {b.inner_text(): b.is_disabled() for b in p.get_by_role("tab").all()}
    assert tabs == {"Overview": False, "Users": True, "Access": True, "Known by (1)": False, "sshd": True,
                    "Accounts": True, "Findings (1)": False}, tabs
    for label, disabled in tabs.items():
        assert not (disabled and "(" in label), label          # no count on a disabled tab
    p.get_by_role("tab", name="Findings (1)").click()
    p.wait_for_url(re.compile(r".*tab=findings"))
    row = p.locator("table.ft tbody tr")
    assert row.count() == 1 and "Host key changed" in row.inner_text() and "Critical" in row.inner_text()
    lab.shot("f2-host-c2-scan2-findings", full=False)
    # a disabled or unknown ?tab= falls back to Overview; the page is never empty
    for bad in ("users", "accounts", "bogus", "%3Cscript%3E"):
        lab.go(f"/s/2/hosts/{ids['c2']}?tab={bad}", wait="h1")
        assert p.get_by_role("tab", name="Overview").get_attribute("aria-selected") == "true", bad
        p.get_by_role("heading", name="Host", exact=True).wait_for()
    lab.go(f"/s/1/hosts/{ids['a1']}?tab=bogus", wait="h1")
    p.get_by_role("heading", name="Access counts").wait_for()


def test_f4_synthetic_banner_on_scans_and_diff(syn, lab):
    for path in ("/scans", "/diff", "/diff?a=1&b=1"):
        syn.go(path)
        banner = syn.page.get_by_role("note")
        banner.wait_for()
        assert "SYNTHETIC DATA – generated by sshbite synth, not from real hosts" in banner.inner_text(), path
    # real scans: no banner
    for path in ("/scans", "/diff?a=1&b=2"):
        lab.go(path)
        assert lab.page.get_by_role("note").count() == 0, path


def test_f5_search_by_keyboard(lab):
    p = lab.page
    dsa = key_fp("k_dsa")
    lab.go("/s/1/", wait="[data-stat]")
    box = p.get_by_role("combobox", name="Search hosts, keys, users")
    box.fill("legacy-dsa")
    p.get_by_role("listbox", name="Search results").get_by_role("option").first.wait_for()
    box.press("ArrowDown")
    assert box.get_attribute("aria-activedescendant") == "search-opt-0"
    assert p.locator("#search-opt-0").get_attribute("aria-selected") == "true"
    lab.shot("f5-search-keyboard-selected", full=False)
    box.press("Enter")
    p.wait_for_url(re.compile(r".*/s/1/keys/" + re.escape(u(dsa)) + "$"))
    p.get_by_role("tab", name="Authorized on (2)").wait_for()
    # Enter without an active result opens the first result
    box.fill("c1")
    p.get_by_role("listbox", name="Search results").get_by_role("option").first.wait_for()
    assert box.get_attribute("aria-activedescendant") is None
    box.press("Enter")
    p.wait_for_url(re.compile(r".*/s/1/hosts/\d+"))
    p.get_by_role("heading", name="c1").wait_for()
    # ArrowUp moves back, Esc closes the popover
    box.fill("a")
    box.press("End")
    box.type("1")
    p.get_by_role("listbox", name="Search results").get_by_role("option").first.wait_for()
    n = p.get_by_role("listbox", name="Search results").get_by_role("option").count()
    for _ in range(n + 2):
        box.press("ArrowDown")
    assert box.get_attribute("aria-activedescendant") == f"search-opt-{n - 1}"
    box.press("ArrowUp")
    assert box.get_attribute("aria-activedescendant") == f"search-opt-{max(n - 2, 0)}"
    box.press("Escape")
    assert p.get_by_role("listbox", name="Search results").count() == 0


def _fp_lines(page) -> list[int]:
    return page.evaluate("""() => [...document.querySelectorAll('table .fp')].map(e =>
        Math.round(e.getBoundingClientRect().height / parseFloat(getComputedStyle(e).lineHeight)))""")


def test_f3_fingerprints_and_narrow_tables(browser, servers):
    s = Session(browser, servers["lab"].base, scheme="light", width=1280, height=800)
    p = s.page
    s.go("/s/1/findings", wait="table.ft tbody tr")
    lines = _fp_lines(p)
    assert lines and set(lines) == {1}, lines                     # every fingerprint on one line
    rec = p.locator("table.ft thead th", has_text="Recommendation").bounding_box()
    assert rec["x"] + 60 < 1280                                   # the Recommendation column is in view
    wrap = p.evaluate("(() => { const w = document.querySelector('.table-wrap'); return [w.scrollWidth, w.clientWidth] })()")
    assert wrap[0] <= wrap[1] + 1, wrap                           # nothing cut off at 1280
    title = p.locator("table.ft tbody tr .rec .l1").first.get_attribute("title")
    assert title                                                  # truncated text keeps the full value in title
    # crawl tree at 1280: Discovered via fits and carries the full value in title
    s.go("/s/1/crawl", wait="tr[data-tree]")
    wrap = p.evaluate("(() => { const w = document.querySelector('.table-wrap'); return [w.scrollWidth, w.clientWidth] })()")
    assert wrap[0] <= wrap[1] + 1, wrap
    via = p.locator("tr[data-tree]", has=p.locator("td.hcell").get_by_role("link", name="a2", exact=True)).locator("td.via")
    assert via.get_attribute("title") == "a1 /home/deploy/.ssh/known_hosts:1 (hashed)"
    s.close()
    # the 480 px edge drawer shows all columns, Flags included, with the fingerprint on one line
    s = Session(browser, servers["lab"].base, scheme="light", width=1440, height=900)
    p = s.page
    s.go("/s/1/heatmap")
    click_cell(p, "jump", "a2")
    d = p.get_by_role("dialog", name="jump → a2")
    d.get_by_text("1 access edge").wait_for()
    assert [t.strip() for t in d.locator("thead th").all_inner_texts()] == \
        ["From", "To", "Key", "Status", "Effective", "Flags"]
    dbox = d.bounding_box()
    flags = d.locator("thead th", has_text="Flags").bounding_box()
    assert flags["x"] + flags["width"] <= dbox["x"] + dbox["width"] + 1
    assert set(_fp_lines(p)) == {1}
    s.close()
    # 375 px: the findings table scrolls inside its panel, the page itself does not
    s = Session(browser, servers["lab"].base, scheme="dark", width=375, height=800)
    p = s.page
    s.go("/s/1/findings", wait="table.ft tbody tr")
    assert p.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
    wrap = p.evaluate("(() => { const w = document.querySelector('.table-wrap'); return [w.scrollWidth, w.clientWidth] })()")
    assert wrap[0] > wrap[1]
    assert set(_fp_lines(p)) == {1}
    first = p.locator("table.ft tbody tr td").first
    assert first.evaluate("e => getComputedStyle(e).position") == "sticky"
    s.close()


def test_f6_accounts_count_diff_route_removed(lab):
    p = lab.page
    ids = _host_ids(lab, 1)
    lab.go(f"/s/1/hosts/{ids['a1']}", wait="h1")
    p.get_by_role("tab", name="Accounts (2 of 21)").click()
    assert p.locator(".tabpanel tbody tr").count() == 2
    p.get_by_label("Show all accounts").check()
    p.get_by_role("tab", name="Accounts (21)").wait_for()
    assert p.locator(".tabpanel tbody tr").count() == 21
    # design-revision §5.6: a changed row shows a Field | Before | After table instead of the sentence chain
    lab.go("/diff?a=1&b=2")
    row = p.locator("table.t > tbody > tr", has_text="c2")
    sub = row.get_by_role("table", name="Changes")
    rows = [[" ".join(c.split()) for c in r.split("\t")] for r in sub.locator("tbody tr").all_inner_texts()]
    assert ["Route", "jump → b3 → c1 → c2", "removed"] in rows and ["Privilege", "root", "removed"] in rows, rows
    assert ["Status", "OK", "Host key changed"] in rows, rows
    assert "→ –" not in row.inner_text()


def test_f6_crawl_tree_reaches_every_one_of_2000_hosts(syn):
    p = syn.page
    total = p.request.get(f"{syn.base}/api/scans/1/crawl").json()
    n_rows = len(total["hosts"]) + len(total["references"])
    syn.go("/s/1/crawl", wait="tr[data-tree]")
    p.get_by_role("button", name="Expand all").click()
    p.get_by_text(f"{n_rows:,} rows shown").wait_for()
    assert p.locator("tr[data-tree]").count() < 300               # virtualised
    # keyboard: End reaches the last row, ArrowUp walks back
    p.locator("tr[data-tree]").first.focus()
    p.keyboard.press("End")
    p.wait_for_function(f"document.activeElement && document.activeElement.dataset.idx === '{n_rows - 1}'")
    # scrolling: every host appears; walk the page in steps and collect the host links seen
    seen = set()
    height = p.evaluate("document.documentElement.scrollHeight")
    y = 0
    while y < height:
        p.evaluate(f"window.scrollTo(0, {y})")
        p.wait_for_timeout(30)
        seen.update(p.eval_on_selector_all("tr[data-tree] td.hcell .hn",
                                           "els => els.map(e => e.title)"))
        y += 700
    names = {h["display_name"] for h in total["hosts"]}
    assert names <= seen, len(names - seen)


# ---------------------------------------------------------------- design-revision v2, checklist §7

REV_SCREENS = ["/s/1/", "/s/1/heatmap", "/s/1/graph?host=2", "/s/1/crawl", "/s/1/hosts", "/s/1/hosts/2",
               "/s/1/hosts/2?tab=users", "/s/1/hosts/11", "/s/1/keys", "/s/1/findings", "/scans",
               "/diff?a=1&b=2", "/diff?a=1&b=2&tab=hosts"]

# every computed colour of every element (and of the SVG marks), as [r, g, b, a]
_COLOURS_JS = """() => {
  const props = ['color', 'background-color', 'border-top-color', 'border-right-color', 'border-bottom-color',
                 'border-left-color', 'outline-color', 'fill', 'stroke', 'text-decoration-color'];
  const out = new Map();
  const ctx = document.createElement('canvas').getContext('2d');
  for (const el of [document.documentElement, ...document.querySelectorAll('body *')]) {
    const cs = getComputedStyle(el);
    for (const p of props) {
      const v = cs.getPropertyValue(p);
      if (!v || v === 'none' || v.startsWith('url(')) continue;
      ctx.fillStyle = '#000'; ctx.fillStyle = v;          // normalises any CSS colour to #rrggbb / rgba()
      const n = ctx.fillStyle;
      if (!out.has(n)) out.set(n, `${el.tagName.toLowerCase()}.${String(el.className.baseVal ?? el.className).split(' ')[0]} ${p}`);
    }
  }
  return [...out.entries()];
}"""


def _rgba(s: str):
    if s.startswith("#"):
        return tuple(int(s[i:i + 2], 16) for i in (1, 3, 5)) + (1.0,)
    m = re.match(r"rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?\)", s)
    if m:
        return (float(m[1]), float(m[2]), float(m[3]), float(m[4] or 1))
    m = re.match(r"color\(srgb ([\d.e-]+) ([\d.e-]+) ([\d.e-]+)(?: / ([\d.e-]+))?\)", s)   # from color-mix()
    assert m, s
    return (float(m[1]) * 255, float(m[2]) * 255, float(m[3]) * 255, float(m[4] or 1))


def _is_green(r, g, b) -> bool:
    import colorsys
    h, l, s = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    return 0.05 < l < 0.97 and s > 0.15 and 75 <= h * 360 <= 170


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_r1_no_indigo_paper_or_green_in_computed_styles(browser, servers, scheme):
    """§7.1: the computed styles of the main screens carry no #4338b8, no #f6f5f1 and no green."""
    s = Session(browser, servers["lab"].base, scheme=scheme, width=1280, height=800)
    bad = []
    for path in REV_SCREENS:
        s.go(path)
        s.page.wait_for_timeout(200)
        for colour, where in s.page.evaluate(_COLOURS_JS):
            r, g, b, a = _rgba(colour)
            if a == 0:
                continue
            hx = "#%02x%02x%02x" % (round(r), round(g), round(b))
            if hx in ("#4338b8", "#f6f5f1") or _is_green(r, g, b):
                bad.append((path, colour, where))
    # the login screen too
    s.page.context.clear_cookies()
    s.go("/login")
    for colour, where in s.page.evaluate(_COLOURS_JS):
        r, g, b, a = _rgba(colour)
        if a and (_is_green(r, g, b) or "#%02x%02x%02x" % (round(r), round(g), round(b)) in ("#4338b8", "#f6f5f1")):
            bad.append(("/login", colour, where))
    assert not bad, bad[:20]
    s.close()


_SIZES_JS = """() => {
  const out = [];
  for (const el of document.querySelectorAll('body *')) {
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own && !['INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName)) continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') continue;
    out.push([parseFloat(cs.fontSize), cs.fontFamily, cs.textTransform, el.tagName.toLowerCase() + '.' +
      String(el.className.baseVal ?? el.className).split(' ')[0], el.textContent.trim().slice(0, 30)]);
  }
  return out;
}"""


def test_r3_only_the_type_scale_sizes(browser, servers):
    """§7.3: only 11 (axes and legend values, Condensed), 12, 13, 14, 16 and 20 px; no uppercase transform."""
    s = Session(browser, servers["lab"].base, scheme="light", width=1280, height=800)
    bad = []
    for path in REV_SCREENS + ["/s/1/keys/" + u(key_fp("k_dsa"))]:
        s.go(path)
        s.page.wait_for_timeout(200)
        for size, family, transform, tag, text in s.page.evaluate(_SIZES_JS):
            if size not in (11, 12, 13, 14, 16, 20) or (size == 11 and "Condensed" not in family):
                bad.append((path, size, tag, text))
            if transform == "uppercase":
                bad.append((path, "uppercase", tag, text))
    # tooltip, drawer and search popover are on screen only after an action
    s.go("/s/1/heatmap")
    click_cell(s.page, "jump", "a2")
    s.page.get_by_role("dialog", name="jump → a2").get_by_text("1 access edge").wait_for()
    bad += [("drawer", sz, tag, t) for sz, _f, _t, tag, t in s.page.evaluate(_SIZES_JS) if sz not in (11, 12, 13, 14, 16, 20)]
    s.page.keyboard.press("Escape")
    s.page.get_by_placeholder("Search hosts, keys, users").fill("a1")
    s.page.get_by_role("listbox", name="Search results").get_by_role("option").first.wait_for()
    bad += [("search", sz, tag, t) for sz, _f, _t, tag, t in s.page.evaluate(_SIZES_JS) if sz not in (11, 12, 13, 14, 16, 20)]
    s.page.context.clear_cookies()
    s.go("/login")
    bad += [("/login", sz, tag, t) for sz, _f, _t, tag, t in s.page.evaluate(_SIZES_JS) if sz not in (11, 12, 13, 14, 16, 20)]
    assert not bad, bad[:20]
    s.close()


_TEXT_JS = """() => ({
  dots: [...document.querySelectorAll('body *')].filter(e => [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.includes(' · ')))
          .map(e => e.textContent.trim().slice(0, 60)),
  arrows: [...document.querySelectorAll('a, button, [role=button], [role=tab], [role=menuitem]')]
          .map(e => (e.innerText ?? e.textContent ?? '').trim()).filter(t => /[→›»▸▾▼]$/.test(t)),
  body: document.body.innerText,
})"""


def test_r4_no_middle_dot_chains_and_no_trailing_arrows(browser, servers):
    """§7.4: no " · " and no arrow at the end of a link or button; the arrow stays inside routes ("jump → a2")."""
    s = Session(browser, servers["lab"].base, scheme="light", width=1280, height=800)
    bad = []
    for path in REV_SCREENS + ["/s/1/keys/" + u(key_fp("k_dsa")), "/s/2/hosts/" + str(_host_ids(s, 2)["c2"]),
                               "/diff?a=1&b=2&tab=edges", "/diff?a=1&b=2&tab=findings"]:
        s.go(path)
        s.page.wait_for_timeout(200)
        r = s.page.evaluate(_TEXT_JS)
        bad += [(path, "dot", t) for t in r["dots"]] + [(path, "arrow", t) for t in r["arrows"]]
        assert " · " not in r["body"], path
    # the tooltip and the drawer
    s.go("/s/1/heatmap")
    p = s.page
    p.locator("canvas.cells").focus()
    rows, cols = heat(p)["rows"].split("|"), heat(p)["cols"].split("|")
    for _ in range(rows.index("jump")):
        p.keyboard.press("ArrowDown")
    for _ in range(cols.index("a2")):
        p.keyboard.press("ArrowRight")
    tip = p.locator(".tooltip")
    tip.get_by_text("Click to list the edges").wait_for()
    assert [x.strip() for x in tip.inner_text().split("\n") if x.strip()][:2] == ["jump → a2", "1 host pair"]
    assert " · " not in tip.inner_text()
    p.keyboard.press("Enter")
    d = p.get_by_role("dialog", name="jump → a2")
    d.get_by_text("1 access edge").wait_for()
    d.get_by_role("link", name="Open jump").wait_for()
    d.get_by_role("link", name="Open a2").wait_for()
    r = p.evaluate(_TEXT_JS)
    bad += [("drawer", "dot", t) for t in r["dots"]] + [("drawer", "arrow", t) for t in r["arrows"]]
    assert not bad, bad[:20]
    s.close()


def test_r8_sidebar_reaches_the_bottom_on_the_crawl_tree(browser, servers):
    """§7.8: at 1280 x 800 the sidebar background reaches the bottom of /s/1/crawl, scrolled down too."""
    s = Session(browser, servers["lab"].base, scheme="light", width=1280, height=800)
    p = s.page
    s.go("/s/1/crawl", wait="tr[data-tree]")
    page_h = p.evaluate("document.documentElement.scrollHeight")
    assert page_h > 800                                            # a long page
    assert p.evaluate("document.documentElement.scrollWidth") <= 1280
    col = p.evaluate("(() => { const r = document.querySelector('.side-col').getBoundingClientRect(); return [r.top + scrollY, r.bottom + scrollY, getComputedStyle(document.querySelector('.side-col')).backgroundColor]; })()")
    assert col[0] == 0 and abs(col[1] - page_h) <= 1, (col, page_h)
    page_bg = p.evaluate("getComputedStyle(document.body).backgroundColor")
    assert col[2] == page_bg
    p.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    p.wait_for_timeout(100)
    hit = p.evaluate("document.elementFromPoint(100, 795).closest('.side-col') !== null")
    assert hit
    # the nav stays in view (sticky) and Crawl tree is the active item
    assert p.get_by_role("navigation", name="Main").get_by_role("link", name="Crawl tree").get_attribute("aria-current") == "page"
    s.shot("r8-crawl-scrolled-1280x800", full=False)
    s.close()


def test_r_crawl_filter_finds_a_collapsed_host_at_2000(syn):
    """check-9 N3: the crawl tree filter finds a late host by name, also when its branch is collapsed."""
    p = syn.page
    syn.go("/s/1/crawl", wait="tr[data-tree]")
    target = "syn-1987"
    assert p.locator("td.hcell .hn", has_text=target).count() == 0           # collapsed at first
    p.get_by_label("Filter by host name or IP").fill(target)
    p.locator("tr.hit td.hcell .hn", has_text=target).first.wait_for()
    hits = p.locator("tr.hit td.hcell .hn").all_inner_texts()
    assert hits and all(target in h for h in hits), hits
    # by IP as well
    ip = next(h for h in p.request.get(f"{syn.base}/api/scans/1/hosts?page_size=1000&q={target}").json()["items"]
              if h["display_name"].startswith(target))["ips"][0]
    p.get_by_label("Filter by host name or IP").fill(ip)
    p.locator("tr.hit td.hcell .hn", has_text=target).first.wait_for()


# ---------------------------------------------------------------- check-12 polish

_GRAPH_JS = """() => {
  const svg = document.querySelector('svg.g'), pane = svg.getBoundingClientRect();
  const c = document.querySelector('svg.g g.node[data-centre]');
  const m = c.querySelector('circle.host, rect.unk').getBoundingClientRect();
  const nodes = [...document.querySelectorAll('svg.g g.node')].map((g) => g.getBoundingClientRect());
  return { pane: [pane.left, pane.top, pane.width, pane.height], centre: [m.left + m.width / 2, m.top + m.height / 2],
    box: [Math.min(...nodes.map((r) => r.left)), Math.min(...nodes.map((r) => r.top)),
          Math.max(...nodes.map((r) => r.right)), Math.max(...nodes.map((r) => r.bottom))],
    k: +svg.dataset.fit };
}"""


def _graph_settled(p):
    p.wait_for_selector("svg.g[data-fit] g.node[data-centre]", timeout=15000)
    p.wait_for_timeout(1900)            # the layout settles within 1.5 s, then fits once more
    return p.evaluate(_GRAPH_JS)


@pytest.mark.parametrize("scheme,reduced", [("light", False), ("dark", False), ("light", True)])
def test_g1_graph_centre_in_the_middle_and_fitted(browser, servers, scheme, reduced):
    """check-12 F1: the centre node's centre is within 10 % of the pane centre; the graph fills the pane with
    about 40 px margin, at most 1.5x; Fit does the same. Host centres a2 and jump (2 hops), key centre K_DSA."""
    s = Session(browser, servers["lab"].base, scheme=scheme, width=1280, height=800, reduced=reduced)
    p = s.page
    ids = _host_ids(s, 1)
    for name, path in (("a2", f"/s/1/graph?host={ids['a2']}"), ("K_DSA", f"/s/1/graph?key={u(key_fp('k_dsa'))}"),
                       ("jump-2", f"/s/1/graph?host={ids['jump']}&hops=2")):
        s.go(path, wait="svg.g")
        g = _graph_settled(p)
        x, y, w, h = g["pane"]
        cx, cy = g["centre"]
        assert abs(cx - (x + w / 2)) <= 0.1 * w and abs(cy - (y + h / 2)) <= 0.1 * h, (name, g)
        assert 0 < g["k"] <= 1.5, (name, g)
        l, t, r, b = g["box"]
        assert l >= x + 20 and r <= x + w - 20 and t >= y + 20 and b <= y + h - 20, (name, g)   # inside, with margin
        # it fills the pane: on one axis the graph reaches the 40 px margin (or the 1.5x cap is reached)
        fills = min(t - y, y + h - b) <= 56 or min(l - x, x + w - r) <= 56
        assert fills or g["k"] >= 1.49, (name, g)
        # Fit after a pan returns to the same view
        box = p.locator("svg.g").bounding_box()
        p.mouse.move(box["x"] + 30, box["y"] + 30)
        p.mouse.down()
        p.mouse.move(box["x"] + 130, box["y"] + 90, steps=4)
        p.mouse.up()
        moved = p.evaluate(_GRAPH_JS)
        assert abs(moved["centre"][0] - cx) > 50
        p.get_by_role("button", name="Fit", exact=True).click()
        p.wait_for_timeout(100)
        again = p.evaluate(_GRAPH_JS)
        assert abs(again["centre"][0] - cx) < 2 and abs(again["centre"][1] - cy) < 2, (name, again, g)
        s.shot(f"g1-graph-{name}-{scheme}{'-reduced' if reduced else ''}", full=False)
    s.close()


def test_g2_users_tab_columns_line_up_and_nothing_is_cut(browser, servers):
    """check-12 F2: on a2's Users tab every table kind has the same column grid in every user panel, and at
    1280 px no cell is cut off (Origin included)."""
    s = Session(browser, servers["lab"].base, scheme="light", width=1280, height=800)
    p = s.page
    s.go(f"/s/1/hosts/{_host_ids(s, 1)['a2']}?tab=users", wait="section.user")
    r = p.evaluate("""() => {
      const out = {};
      for (const t of document.querySelectorAll('section.user table.t')) {
        const head = [...t.querySelectorAll('thead th')];
        const key = head.map((h) => h.textContent.trim()).join('|');
        (out[key] ||= []).push(head.map((h) => Math.round(h.getBoundingClientRect().left)));
      }
      const cut = [...document.querySelectorAll('section.user table.t td')].filter((td) => td.scrollWidth > td.clientWidth + 1)
        .map((td) => td.textContent.trim());
      const wraps = [...document.querySelectorAll('section.user .table-wrap')].filter((w) => w.scrollWidth > w.clientWidth + 1).length;
      return { out, cut, wraps };
    }""")
    auth = r["out"]["File:line|Strength|Type|Fingerprint|Comment|Options|Origin"]
    assert len(auth) >= 3 and all(x == auth[0] for x in auth), auth
    for k, v in r["out"].items():
        assert all(x == v[0] for x in v), (k, v)
    assert not r["cut"] and r["wraps"] == 0, r
    # option chips share the chip border
    colours = p.evaluate("[...new Set([...document.querySelectorAll('.kchip')].map((c) => getComputedStyle(c).borderTopColor))]")
    assert len(colours) == 1, colours
    s.close()


def test_g3_dashboard_recommendation_readable_and_tabs_at_375(browser, servers):
    """check-12 F3/F4: the dashboard shows each top recommendation in full (up to two lines) at 1280 px; at
    375 px the host tab bar shows that more tabs follow and scrolls them into view."""
    s = Session(browser, servers["lab"].base, scheme="light", width=1280, height=800)
    p = s.page
    s.go("/s/1/", wait="ol.tf li")
    rec = p.evaluate("[...document.querySelectorAll('ol.tf .c4 .clamp')].map((e) => [e.textContent, e.scrollHeight <= e.clientHeight + 1, e.getAttribute('title')])")
    assert any(t == "Replace with ed25519, remove this line/file" for t, _, _ in rec)
    assert all(full and title == t for t, full, title in rec), rec
    s.close()
    s = Session(browser, servers["lab"].base, scheme="light", width=375, height=812)
    p = s.page
    s.go(f"/s/1/hosts/{_host_ids(s, 1)['a2']}", wait="[role=tablist]")
    right = p.get_by_role("button", name="Scroll tabs right")
    right.wait_for()
    assert p.get_by_role("button", name="Scroll tabs left").count() == 0
    right.click()
    p.get_by_role("button", name="Scroll tabs left").wait_for()
    p.get_by_role("tab", name="Findings").click()
    p.wait_for_timeout(200)
    inside = p.evaluate("""() => { const bar = document.querySelector('[role=tablist]').getBoundingClientRect();
      const t = document.querySelector('[role=tab][aria-selected=true]').getBoundingClientRect();
      return t.left >= bar.left - 1 && t.right <= bar.right + 1; }""")
    assert inside
    assert p.evaluate("document.documentElement.scrollWidth") <= 375
    s.close()


def test_g4_drilldown_group_by_says_so(syn):
    """check-12 F6: in the drill-down the Group by control reads 'Host (drill-down)'; choosing a grouping leaves it."""
    p = syn.page
    syn.go("/s/1/heatmap?src=10.66.16.0%2F24&dst=10.66.17.0%2F24")
    heat(p)
    sel = p.get_by_label("Group by")
    assert sel.evaluate("(e) => e.options[e.selectedIndex].text") == "Host (drill-down)"
    sel.select_option("subnet")
    p.wait_for_url(re.compile(r".*group_by=subnet$"))
    assert len(heat(p)["cols"].split("|")) == 40
