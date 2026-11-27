"""Package B walk with the CLI on the AlmaLinux 9 host r1 (spec J5 and the r1 journey), then the UI screenshots.

  python3 evidence/hardening/walk_r1.py            export, install r1 (lab/installed.sh), scan it in mode installed,
                                                   scan it again without setpriv (chmod 000, restored at once),
                                                   uninstall r1; transcript to walk-r1.txt, database in WALK_DIR
  python3 evidence/hardening/walk_r1.py screens OUT  with `sshbite -c $WALK_DIR/sshbite.yaml serve` running:
                                                   screenshots desktop 1440 px and phone 390 px into OUT
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests.e2e import lab as L  # noqa: E402
from tests.e2e.test_lab_installed import AK  # noqa: E402

W = Path(os.environ.get("WALK_DIR", "/tmp/sshbite-walk-r1"))
SB = str(Path(sys.executable).parent / "sshbite")
OUT: list[str] = []
ctl = L.LabControl(L.lab_hosts())


def sh(args: list[str], shown: str, **kw) -> str:
    p = subprocess.run(args, capture_output=True, text=True, cwd=str(W), **kw)
    OUT.append(f"$ {shown}\n{p.stdout}{p.stderr}(exit {p.returncode})\n")
    return p.stdout


def walk() -> None:
    shutil.rmtree(W, ignore_errors=True)
    W.mkdir(parents=True)
    host, port = L.find_r1()
    key = W / "audit_ed25519"
    shutil.copy(L.KEYS / "audit_ed25519", key)
    key.chmod(0o600)
    pin = " ".join((L.KEYS / "r1_host_ed25519.pub").read_text().split()[:2])
    cfg = W / "sshbite.yaml"
    cfg.write_text(f"database: {W}/sshbite.db\nentry:\n  host: {host}\n  port: {port}\n  host_keys: [\"{pin}\"]\n"
                   f"audit:\n  user: sshbite\n  key_file: {key}\nprivilege:\n  mode: installed\n")
    cfg.chmod(0o600)
    c = ["-c", str(cfg)]
    sh([SB, *c, "collector", "export", "export"], "sshbite collector export export")
    OUT.append("# r1: install the export as docs/install.md says (lab/installed.sh apply, variant A)\n")
    OUT.append(ctl.run_text("r1", L.installed_apply_script(W / "export", L.installed_line(*AK["r1"]))))
    try:
        sh([SB, *c, "config", "validate", "--connect"], "sshbite config validate --connect")
        sh([SB, *c, "scan", "--no-crawl", "--label", "r1 installed"], "sshbite scan --no-crawl --label 'r1 installed'")
        sh([SB, *c, "scans", "show", "latest"], "sshbite scans show latest")
        mode = ctl.run_text("r1", "stat -c %a /usr/bin/setpriv").strip()
        OUT.append(f"# r1: chmod 000 /usr/bin/setpriv (was {mode})\n")
        ctl.run_text("r1", "chmod 000 /usr/bin/setpriv")
        try:
            sh([SB, *c, "scan", "--no-crawl", "--label", "r1 without setpriv"],
               "sshbite scan --no-crawl --label 'r1 without setpriv'")
        finally:
            ctl.run_text("r1", f"chmod {mode} /usr/bin/setpriv")
            OUT.append(f"# r1: chmod {mode} /usr/bin/setpriv (restored)\n")
        sh([SB, *c, "scans", "show", "latest"], "sshbite scans show latest")
    finally:
        OUT.append("# r1: lab/installed.sh remove\n" + ctl.run_text("r1", L.installed_remove_script()))
    p = subprocess.run([SB, *c, "user", "add", "admin", "--password-stdin"], input="correct horse battery\n",
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    (Path(__file__).parent / "walk-r1.txt").write_text("\n".join(OUT).replace(str(W), "$WALK_DIR"))
    print("\n".join(OUT))


def screens(out: str) -> None:
    import sqlite3

    from playwright.sync_api import sync_playwright

    db = sqlite3.connect(W / "sshbite.db")

    def hid(sid: int) -> int:
        return db.execute("SELECT hs.host_id FROM host_scan hs JOIN host h ON h.id=hs.host_id WHERE hs.scan_id=? "
                          "AND h.display_name='r1'", (sid,)).fetchone()[0]

    shots = [("06-hostliste-r1-installed-ok-root", "/s/1/hosts"),
             ("07-host-r1-ok-root-unreadable-by-account", f"/s/1/hosts/{hid(1)}"),
             ("08-hostliste-r1-ohne-setpriv-partial", "/s/2/hosts"),
             ("09-host-r1-partial-setpriv-fehlt", f"/s/2/hosts/{hid(2)}")]
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox"])
        for w, h, suf in [(1440, 900, "desktop"), (390, 844, "handy")]:
            ctx = b.new_context(viewport={"width": w, "height": h}, color_scheme="light")
            pg = ctx.new_page()
            pg.goto("http://127.0.0.1:8722/login")
            pg.fill("input[name=username]", "admin")
            pg.fill("input[name=password]", "correct horse battery")
            pg.click("button[type=submit]")
            pg.wait_for_url(lambda u: "/login" not in u)
            for name, path in shots:
                pg.goto("http://127.0.0.1:8722" + path)
                pg.wait_for_load_state("networkidle")
                pg.wait_for_timeout(500)
                pg.screenshot(path=f"{out}/{name}-{suf}.png", full_page=True)
            ctx.close()
        b.close()


if __name__ == "__main__":
    if sys.argv[1:2] == ["screens"]:
        screens(sys.argv[2])
    else:
        walk()
