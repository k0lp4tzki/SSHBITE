"""Walk of the journeys J1-J4 against the lab, as the operator would do them (writes walk.txt).

The owner's installation step on the hosts is lab/installed.sh through the lab-control sshd; every other
step is the sshbite CLI. Run from the repository root with the lab reachable (SSHBITE_LAB_ENTRY=jump:22).
Leaves the hosts installed and the database in WALK_DIR for the UI screenshots; `walk.py remove` restores.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.e2e import lab as L  # noqa: E402
from tests.e2e.test_lab_installed import AK, HOSTS, P  # noqa: E402

W = Path(os.environ.get("WALK_DIR", "/tmp/sshbite-walk"))
OUT: list[str] = []
ctl = L.LabControl(L.expected()["hosts"])


def say(text: str) -> None:
    OUT.append(text)
    print(text)


def sh(cmd: str, shown: str | None = None, cwd: Path | None = None, env: dict | None = None) -> int:
    e = {k: v for k, v in os.environ.items() if k != "SSHBITE_SUDO_PASSWORD"}
    e["PATH"] = str(Path(sys.executable).parent) + ":" + e["PATH"]
    e.update(env or {})
    p = subprocess.run(cmd, shell=True, cwd=cwd or W, capture_output=True, text=True, env=e, timeout=600)
    say(f"$ {shown or cmd}\n{p.stdout}{p.stderr}(exit {p.returncode})\n")
    return p.returncode


def host(h: str, text: str, what: str) -> None:
    out = ctl.run_text(h, "set -eu\n" + text + "\n")
    say(f"[{h} as root] {what}\n{out}")


def apply(h: str, export: Path) -> None:
    out = ctl.run_text(h, L.installed_apply_script(export, L.installed_line(*AK[h])))
    say(f"[{h} as root] install the exported files (docs/install.md), authorized_keys variant {AK[h][0]} "
        f"from={AK[h][1]}\n{out.splitlines()[0]}")


def config(name: str, privilege: dict | None, **extra) -> str:
    host_, _, port = os.environ.get("SSHBITE_LAB_ENTRY", "jump:22").rpartition(":")
    subprocess.run(["sh", str(L.LAB / "up.sh")], check=True, capture_output=True,
                   env=dict(os.environ, LAB_NO_START="1", LAB_ENTRY_HOST=host_, LAB_ENTRY_PORT=port))
    data = yaml.safe_load((L.LAB / "sshbite.lab.yaml").read_text())
    data["database"] = str(W / "sshbite.db")
    if privilege:
        data["privilege"] = privilege
    data.update(extra)
    p = W / name
    p.write_text(yaml.safe_dump(data, sort_keys=False))
    p.chmod(0o600)
    return str(p)


def main() -> None:
    if sys.argv[1:] == ["remove"]:
        for h in HOSTS:
            print(h, ctl.run_text(h, L.installed_remove_script()).strip())
        return
    W.mkdir(parents=True, exist_ok=True)
    sudo_cfg = config("sshbite-sudo.yaml", None)
    cfg = config("sshbite.yaml", {"mode": "installed"})

    say("##### J1 install hardened: export, check, install, configure, validate, scan")
    sh("sshbite collector export ./sshbite-export", "sshbite collector export ./sshbite-export")
    sh("sha256sum -c SHA256SUMS", "cd sshbite-export && sha256sum -c SHA256SUMS", cwd=W / "sshbite-export")
    sh("cat sshbite-export/sudoers.d-sshbite")
    for h in HOSTS:
        apply(h, W / "sshbite-export")
    host("a1", "visudo -cf /etc/sudoers.d/sshbite; sudo -l -U sshbite | tail -2; "
               "stat -c '%U %a %n' /usr /usr/local /usr/local/libexec /usr/local/libexec/sshbite/*",
         "the checks of docs/install.md")
    sh(f"grep -A2 '^privilege' {cfg}", "grep -A2 '^privilege' sshbite.yaml")
    sh(f"sshbite -c {cfg} config validate --connect", "sshbite config validate --connect")
    sh(f"sshbite -c {cfg} scan --label 'J1 installed'", "sshbite scan --label 'J1 installed'")
    sh(f"sshbite -c {cfg} scans show latest | head -24", "sshbite scans show latest | head -24")

    say("##### J2 errors are visible: a4 without its sudoers file, in a full crawl")
    host("a4", "rm /etc/sudoers.d/sshbite", "rm /etc/sudoers.d/sshbite")
    sh(f"sshbite -c {cfg} config validate --connect", "sshbite config validate --connect   # entry is fine")
    sh(f"sshbite -c {cfg} scan --label 'J2 a4 not rolled out'", "sshbite scan --label 'J2 a4 not rolled out'")
    sh(f"sshbite -c {cfg} scans show latest | grep -A3 '^a4 '", "sshbite scans show latest | grep -A3 '^a4 '")
    apply("a4", W / "sshbite-export")

    say("##### J3 after an update: the hosts have another collector version; reinstall only sshbite-collect")
    for h in HOSTS:
        ctl.run_text(h, f"set -eu\nsed -i 's/^B=[0-9a-f]*$/B=0123456789ab/' {P}\n")
    say("[every host as root] the installed collector is now an older version: "
        f"sed -i 's/^B=.*/B=0123456789ab/' {P}\n")
    sh(f"sshbite -c {cfg} config validate --connect", "sshbite config validate --connect")
    sh(f"sshbite -c {cfg} scan --label 'J3 old collector' | tail -7", "sshbite scan --label 'J3 old collector'")
    sh(f"sshbite -c {cfg} scans show latest | grep -m2 'error:'", "sshbite scans show latest | grep -m2 'error:'")
    sh("rm -rf sshbite-export-new && sshbite collector export ./sshbite-export-new && "
       "cd sshbite-export-new && sha256sum -c SHA256SUMS && diff -s sshbite-gate ../sshbite-export/sshbite-gate",
       "sshbite collector export ./sshbite-export-new && cd sshbite-export-new && sha256sum -c SHA256SUMS && "
       "diff -s sshbite-gate ../sshbite-export/sshbite-gate")
    collect = (W / "sshbite-export-new" / "sshbite-collect").read_text()
    for h in HOSTS:
        ctl.run_text(h, f"set -eu\ncat > /tmp/sshbite-collect <<'SSHBITE_EXPORT_EOF'\n{collect}SSHBITE_EXPORT_EOF\n"
                        f"install -m 0755 -o root -g root /tmp/sshbite-collect {P}\nrm /tmp/sshbite-collect\n")
    say(f"[every host as root] install -m 0755 -o root -g root sshbite-collect {P}\n")
    sh(f"sshbite -c {cfg} scan --label 'J3 collector reinstalled' | tail -7",
       "sshbite scan --label 'J3 collector reinstalled'")

    say("##### J4 switching from mode sudo: files installed, config still on sudo -> the gate refuses")
    sh(f"SSHBITE_SUDO_PASSWORD=labsudo sshbite -c {sudo_cfg} scan --no-crawl --label 'J4 still mode sudo' | tail -7",
       "SSHBITE_SUDO_PASSWORD=*** sshbite scan --no-crawl --label 'J4 still mode sudo'   # privilege.mode: sudo")
    sh(f"sshbite -c {sudo_cfg} scans show latest | grep -A3 '^jump '", "sshbite scans show latest | grep -A3 '^jump '")
    sh(f"sshbite -c {cfg} scan --label 'J4 switched to installed' | tail -7",
       "sshbite scan --label 'J4 switched to installed'   # privilege.mode: installed")
    sh(f"sshbite -c {cfg} scan --ask-sudo-password", "sshbite scan --ask-sudo-password")

    say("##### J2 all error texts (entry + seeds a2 a3 a4 a5 b2, --no-crawl), for the UI")
    seeds = W / "seeds.txt"
    seeds.write_text("".join(f"{L.expected()['hosts'][h][0]}\n" for h in ("a2", "a3", "a4", "a5", "b2")))
    fcfg = config("sshbite-failures.yaml", {"mode": "installed"}, seeds={"hosts_file": str(seeds)})
    from tests.e2e.test_lab_installed import BREAK
    for h, (cmd, _t) in BREAK.items():
        host(h, cmd, cmd)
    sh(f"sshbite -c {fcfg} scan --no-crawl --label 'J2 broken installations'",
       "sshbite scan --no-crawl --label 'J2 broken installations'   # seeds: a2 a3 a4 a5 b2")
    sh(f"sshbite -c {fcfg} scans show latest", "sshbite scans show latest")
    for h in BREAK:
        apply(h, W / "sshbite-export-new")
    sh(f"sshbite -c {cfg} scan --label 'after repair' | tail -7", "sshbite scan --label 'after repair'")
    (Path(__file__).parent / "walk.txt").write_text("\n".join(OUT) + "\n")


if __name__ == "__main__":
    main()
