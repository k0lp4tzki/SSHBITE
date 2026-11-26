"""Screenshots for the corrections of the QA check (check-6), taken from running SSHBITE instances.

    .venv/bin/python tools/ui_evidence_corrections.py OUT_DIR --lab URL [--lab-user U --lab-password P]
                     --fixture URL --mixed URL [--password P]

--lab      an instance with a real lab scan as scan 1 (e.g. the lab demo of compose.lab.yaml)
--fixture  an instance on a copy of tests/fixtures/lab_scans.db (scans 1-3 of a real lab run): scan 2 and diffs
--mixed    an instance with real scans plus `sshbite synth --hosts 2000 --seed 42` as the newest scan
Every screen is checked for page errors; the script prints what it saw.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402

from tests.e2e.lab import key_fp  # noqa: E402
from tests.web.conftest import PASSWORD  # noqa: E402


def u(fp):
    return fp.replace("+", "-").replace("/", "_")


class Shooter:
    def __init__(self, browser, base, out: Path, user="admin", password=PASSWORD, scheme="light", w=1440, h=900):
        self.ctx = browser.new_context(viewport={"width": w, "height": h}, color_scheme=scheme, accept_downloads=True)
        self.p = self.ctx.new_page()
        self.base, self.out = base.rstrip("/"), out
        self.errors: list[str] = []
        self.requests: list[str] = []
        self.p.on("pageerror", lambda e: self.errors.append(str(e)))
        self.p.on("request", lambda r: self.requests.append(r.url))
        self.p.goto(self.base + "/login")
        self.p.fill("input[name=username]", user)
        self.p.fill("input[name=password]", password)
        self.p.click("button[type=submit]")
        self.p.wait_for_url(lambda x: "/login" not in x)
        self.p.wait_for_load_state("networkidle")

    def go(self, path, wait=None, settle=500):
        self.p.goto(self.base + path)
        if wait:
            self.p.wait_for_selector(wait, timeout=20000)
        self.p.wait_for_load_state("networkidle")
        self.p.wait_for_timeout(settle)

    def shot(self, name, full=False):
        self.p.screenshot(path=str(self.out / f"{name}.png"), full_page=full)
        print("  shot", name)

    def ids(self, sid):
        return {h["display_name"]: h["host_id"] for h in
                self.p.request.get(f"{self.base}/api/scans/{sid}/hosts?page_size=1000").json()["items"]}

    def close(self):
        outside = [r for r in self.requests if not (r.startswith(self.base + "/") or r.startswith("data:"))]
        print(f"  {len(self.requests)} requests, {len(outside)} outside the origin; page errors: {self.errors or 'none'}")
        self.ctx.close()


def click_cell(p, src, dst):
    c = p.locator("canvas.cells")
    p.wait_for_selector('canvas.cells[data-rendered]:not([data-rendered="0"])', timeout=20000)
    rows = c.get_attribute("data-rows").split("|")
    cols = c.get_attribute("data-cols").split("|")
    pitch = int(c.get_attribute("data-pitch"))
    upos = int(c.get_attribute("data-unknown-pos"))
    r, k = rows.index(src), cols.index(dst)
    y = r * pitch + (6 if upos >= 0 and r >= upos else 0) + pitch / 2
    c.click(position={"x": k * pitch + pitch / 2, "y": y})


def text(loc):
    return " ".join(loc.inner_text().split())


def lab(b, a, out):
    print("lab instance (scan 1 from the lab):", a.lab)
    s = Shooter(b, a.lab, out, a.lab_user, a.lab_password)
    p = s.p
    ids = s.ids(1)
    # F1: c1 with both attempts, no tab clicked
    s.go(f"/s/1/hosts/{ids['c1']}", "h1")
    t = p.get_by_role("table", name="Route attempts")
    print("  c1 route attempts:", [" ".join(r.split()) for r in t.locator("tbody tr").all_inner_texts()])
    s.shot("c6-01-host-c1-route-attempts-1440")
    # F6b: accounts
    s.go(f"/s/1/hosts/{ids['a1']}?tab=accounts", "h1")
    print("  a1 tabs:", [x.strip() for x in p.get_by_role("tab").all_inner_texts()])
    s.shot("c6-11-host-a1-accounts-2-of-21")
    # F2: unknown tab
    s.go(f"/s/1/hosts/{ids['c1']}?tab=bogus", "h1")
    print("  ?tab=bogus selected:", p.locator("[role=tab][aria-selected=true]").inner_text())
    s.shot("c6-12-host-c1-tab-bogus-falls-back-to-overview")
    # F3: drawer at 1440
    s.go("/s/1/heatmap")
    click_cell(p, "jump", "a2")
    d = p.get_by_role("dialog", name="jump → a2")
    d.get_by_text("1 access edge").wait_for()
    p.wait_for_timeout(300)
    print("  drawer columns:", [x.strip() for x in d.locator("thead th").all_inner_texts()],
          "row:", text(d.locator("tbody tr").first))
    s.shot("c6-03-heatmap-drawer-jump-a2-1440")
    p.keyboard.press("Escape")
    # F5: search by keyboard
    s.go("/s/1/", "[data-stat]")
    box = p.get_by_role("combobox", name="Search hosts, keys, users")
    box.fill("legacy-dsa")
    p.get_by_role("listbox", name="Search results").get_by_role("option").first.wait_for()
    box.press("ArrowDown")
    p.wait_for_timeout(200)
    print("  search active:", box.get_attribute("aria-activedescendant"))
    s.shot("c6-08-search-legacy-dsa-arrowdown-selected")
    box.press("Enter")
    p.wait_for_url(re.compile(r".*/s/1/keys/" + re.escape(u(key_fp("k_dsa"))) + "$"))
    p.get_by_role("tab", name="Authorized on (2)").wait_for()
    p.wait_for_timeout(300)
    print("  after Enter:", p.url)
    s.shot("c6-09-key-k_dsa-after-enter")
    # F6a: export of the filtered findings
    s.go("/s/1/findings?rule=key_unknown_origin&min=high", "table.ft tbody tr")
    with p.expect_download() as dl:
        p.get_by_role("link", name=re.compile(r"Export CSV \(3\)")).click()
    print("  filtered export file:", dl.value.suggested_filename)
    s.shot("c6-15-findings-key_unknown_origin-high-1440")
    # crawl tree at 1280 with c1's attempts open
    s.close()
    s = Shooter(b, a.lab, out, a.lab_user, a.lab_password, w=1280, h=800)
    p = s.p
    s.go("/s/1/findings", "table.ft tbody tr")
    print("  findings 1280: fingerprint line counts",
          sorted(set(p.evaluate("""() => [...document.querySelectorAll('table .fp')].map(e =>
            Math.round(e.getBoundingClientRect().height / parseFloat(getComputedStyle(e).lineHeight)))"""))))
    s.shot("c6-04-findings-1280")
    s.go("/s/1/crawl", "tr[data-tree]")
    row = p.locator("tr[data-tree]", has=p.locator("td.hcell").get_by_role("link", name="c1", exact=True))
    row.get_by_role("button", name="↺ 1 failed attempt").click()
    row.scroll_into_view_if_needed()
    p.wait_for_timeout(300)
    print("  crawl c1 attempts:", row.get_by_role("list", name="Route attempts").all_inner_texts())
    s.shot("c6-14-crawl-tree-1280-c1-attempts-open")
    s.close()
    s = Shooter(b, a.lab, out, a.lab_user, a.lab_password, scheme="dark", w=375, h=800)
    p = s.p
    s.go("/s/1/findings", "table.ft tbody tr")
    s.shot("c6-05-findings-375-dark")
    p.locator(".table-wrap").first.evaluate("w => w.scrollLeft = 340")
    p.wait_for_timeout(200)
    s.shot("c6-05b-findings-375-dark-scrolled-sideways")
    s.go(f"/s/1/hosts/{ids['c1']}", "h1")
    s.shot("c6-01b-host-c1-route-attempts-375-dark")
    s.close()


def fixture(b, a, out):
    print("fixture instance (scans 1-3 of a real lab run):", a.fixture)
    s = Shooter(b, a.fixture, out, password=a.password)
    p = s.p
    ids = s.ids(2)
    s.go(f"/s/2/hosts/{ids['c2']}", "h1")
    print("  c2 scan 2 tabs:", {x.inner_text(): x.is_disabled() for x in p.get_by_role("tab").all()})
    p.get_by_role("tab", name="Findings (1)").click()
    p.locator("table.ft tbody tr").first.wait_for()
    p.wait_for_timeout(300)
    print("  c2 finding:", text(p.locator("table.ft tbody tr").first))
    s.shot("c6-02-host-c2-scan2-findings-tab")
    s.go("/diff?a=1&b=2")
    print("  diff 1-2 hosts:", text(p.locator("tbody tr").first))
    s.shot("c6-13-diff-1-2-hosts-route-removed")
    s.close()


def mixed(b, a, out):
    print("mixed instance (real scans + synthetic scan):", a.mixed)
    s = Shooter(b, a.mixed, out, password=a.password)
    p = s.p
    scans = p.request.get(f"{a.mixed}/api/scans").json()["items"]
    syn = next(x["id"] for x in scans if x["synthetic"])
    real = next(x["id"] for x in scans if not x["synthetic"])
    s.go(f"/s/{syn}/")
    s.go("/scans")
    print("  /scans banner:", p.get_by_role("note").count(), "top bar:", text(p.locator(".scansel .sel")))
    s.shot("c6-06-scans-synthetic-scan-selected")
    s.go(f"/diff?a={real}&b={syn}", settle=3000)
    print("  /diff banner:", p.get_by_role("note").count())
    s.shot("c6-07-diff-real-vs-synthetic")
    s.go(f"/s/{real}/")
    s.go("/scans")
    print("  /scans with a real scan selected, banner:", p.get_by_role("note").count())
    s.close()
    s = Shooter(b, a.mixed, out, password=a.password, w=1440, h=900)
    p = s.p
    s.go(f"/s/{syn}/crawl", "tr[data-tree]")
    p.get_by_role("button", name="Expand all").click()
    p.wait_for_timeout(500)
    print("  crawl rows:", p.get_by_text("rows shown").inner_text(), "in DOM:", p.locator("tr[data-tree]").count())
    s.shot("c6-10a-crawl-2000-expanded-top")
    p.locator("tr[data-tree]").first.focus()
    p.keyboard.press("End")
    p.wait_for_timeout(600)
    for _ in range(12):
        p.keyboard.press("ArrowUp")
    p.wait_for_timeout(300)
    print("  focused late row:", p.evaluate("document.activeElement.dataset.idx"),
          p.evaluate("document.activeElement.innerText.split('\\t')[0]"))
    s.shot("c6-10-crawl-2000-scrolled-to-late-host")
    p.keyboard.press("End")
    p.wait_for_timeout(400)
    print("  last row of the tree:", p.evaluate("document.activeElement.dataset.idx"),
          p.evaluate("document.activeElement.innerText.split('\\t')[0].trim()"))
    s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--lab")
    ap.add_argument("--lab-user", default="admin")
    ap.add_argument("--lab-password", default=PASSWORD)
    ap.add_argument("--fixture")
    ap.add_argument("--mixed")
    ap.add_argument("--password", default=PASSWORD)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        b = pw.chromium.launch(args=["--no-sandbox"])
        if a.lab:
            lab(b, a, out)
        if a.fixture:
            fixture(b, a, out)
        if a.mixed:
            mixed(b, a, out)
        b.close()


if __name__ == "__main__":
    main()
