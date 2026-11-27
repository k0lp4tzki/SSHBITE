"""Screenshots of the UI after the walk (walk.py): `sshbite -c $WALK_DIR/sshbite.yaml serve` must run, with the
UI user admin / 'correct horse battery'. Usage: python3 screens.py OUTDIR  (Chromium with --no-sandbox)."""
import os
import sqlite3
import sys

from playwright.sync_api import sync_playwright

base = "http://127.0.0.1:8722"
db = sqlite3.connect(os.path.join(os.environ.get("WALK_DIR", "/tmp/sshbite-walk"), "sshbite.db"))


def hid(sid, name):
    return db.execute("SELECT hs.host_id FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=? "
                      "AND h.display_name=?", (sid, name)).fetchone()[0]


out = sys.argv[1]
SHOTS = [("01-hostliste-installed-ok-root", "/s/1/hosts"),
         ("02-host-a4-collector-error-sudoers-fehlt", f"/s/2/hosts/{hid(2, 'a4')}"),
         ("03-hostliste-kaputte-installationen", "/s/7/hosts"),
         ("04-host-a5-collector-error-version", f"/s/7/hosts/{hid(7, 'a5')}"),
         ("05-host-b2-collector-error-keine-regel", f"/s/7/hosts/{hid(7, 'b2')}")]
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-sandbox"])
    for w, h, suf in [(1440, 900, "desktop"), (390, 844, "handy")]:
        ctx = b.new_context(viewport={"width": w, "height": h}, color_scheme="light")
        pg = ctx.new_page()
        pg.goto(base + "/login")
        pg.fill("input[name=username]", "admin")
        pg.fill("input[name=password]", "correct horse battery")
        pg.click("button[type=submit]")
        pg.wait_for_url(lambda u: "/login" not in u)
        pg.wait_for_load_state("networkidle")
        for name, path in SHOTS:
            pg.goto(base + path)
            pg.wait_for_load_state("networkidle")
            pg.wait_for_timeout(500)
            pg.screenshot(path=f"{out}/{name}-{suf}.png", full_page=True)
        ctx.close()
    b.close()
