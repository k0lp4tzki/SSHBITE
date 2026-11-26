#!/usr/bin/env python3
"""Lab evidence: screenshots of the SSHBITE UI for the lab scans (scan list, hosts of scan 2 and 3, diff 1->2)."""
import sys
from playwright.sync_api import sync_playwright

BASE, OUT, PW = "http://127.0.0.1:8722", sys.argv[1], sys.argv[2]
with sync_playwright() as p:
    b = p.chromium.launch(args=["--no-sandbox"])
    pg = b.new_page(viewport={"width": 1440, "height": 900})
    pg.goto(BASE + "/login")
    pg.fill("input[autocomplete=username], input[name=username], input[type=text]", "admin")
    pg.fill("input[type=password]", PW)
    pg.keyboard.press("Enter")
    pg.wait_for_timeout(1500)
    for path, name in (("/scans", "lab-ui-01-scans"), ("/s/2/hosts", "lab-ui-02-scan2-minimal-hosts"),
                       ("/s/3/hosts", "lab-ui-03-scan3-a5-versionsfehler"), ("/diff?a=1&b=2", "lab-ui-04-diff-heute-vs-minimal")):
        pg.goto(BASE + path)
        pg.wait_for_timeout(1800)
        pg.screenshot(path=f"{OUT}/{name}.png", full_page=True)
    b.close()
