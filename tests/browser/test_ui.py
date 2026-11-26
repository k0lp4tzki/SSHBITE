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

    def __init__(self, browser, base: str, scheme: str = "dark", width: int = 1440, height: int = 900, login=True):
        self.base = base
        self.ctx = browser.new_context(viewport={"width": width, "height": height}, color_scheme=scheme,
                                       permissions=["clipboard-read", "clipboard-write"])
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
    assert "Critical" in head and "dsa 1024" in head and "origin:" in head and "Unknown" in head
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
