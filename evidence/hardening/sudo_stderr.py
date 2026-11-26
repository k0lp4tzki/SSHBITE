"""What Debian's sudo (lab, bookworm) prints for `sudo -n -l P` / `sudo -n P` in the failure cases of spec 4.3,
sent with the audit key through the installed gate on a2, and which SSHBITE message each case gets.
Writes sudo-stderr.md. Installs a2 first (lab/installed.sh apply) and restores it at the end (remove)."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

import asyncssh
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sshbite.cli import main  # noqa: E402
from sshbite.privilege import installed_probe_error  # noqa: E402
from tests.e2e import lab as L  # noqa: E402
from tests.e2e.test_lab_installed import AK, P  # noqa: E402

ctl = L.LabControl(L.expected()["hosts"])
CASES = [
    ("rule present (reference)", ":"),
    ("missing rule (sshbite has a rule, but not for P)",
     f"sed -i 's|NOPASSWD: {P} \"\"|NOPASSWD: /bin/true|' /etc/sudoers.d/sshbite"),
    ("rule without NOPASSWD", "sed -i 's/NOPASSWD: //' /etc/sudoers.d/sshbite"),
    ("collector file missing", f"rm {P}"),
    ("sudoers file missing (no rule for sshbite at all)", "rm /etc/sudoers.d/sshbite"),
]


async def probe() -> list[tuple[str, int, str]]:
    key = asyncssh.read_private_key(str(L.KEYS / "audit_ed25519"))
    kh = lambda h: ([asyncssh.read_public_key(str(L.KEYS / f"{h}_host_ed25519.pub"))], [], [])  # noqa: E731
    out = []
    async with asyncssh.connect("jump", 22, username="sshbite", client_keys=[key], known_hosts=kh("jump"),
                                config=None, agent_path=None) as j:
        async with asyncssh.connect("172.30.1.12", 22, tunnel=j, username="sshbite", client_keys=[key],
                                    known_hosts=kh("a2"), config=None, agent_path=None) as c:
            for cmd in (f"sudo -n -l {P}", f"sudo -n {P}"):
                r = await c.run(cmd, check=False)
                out.append((cmd, r.exit_status, (r.stderr or "").strip()))
    return out


def main_() -> None:
    with tempfile.TemporaryDirectory() as d:
        exp = Path(d) / "export"
        assert CliRunner().invoke(main, ["-c", "/nonexistent", "collector", "export", str(exp)]).exit_code == 0
        install = L.installed_apply_script(exp, L.installed_line(*AK["a2"]))
    sudo_version = ctl.run_text("a2", "sudo -V | head -1").strip()
    lines = ["# sudo stderr on the lab's Debian host (a2) and the resulting SSHBITE message", "",
             f"`{sudo_version}`, requests sent with the audit key through jump and the installed gate.", "",
             "| Case | Request | Exit | stderr | SSHBITE message (host status collector_error) |", "|---|---|---|---|---|"]
    try:
        for name, cmd in CASES:
            ctl.run_text("a2", install)
            ctl.run_text("a2", f"set -eu\n{cmd}\n")
            for req, rc, err in asyncio.run(probe()):
                msg = "–" if rc == 0 else (installed_probe_error(P, rc, err) if "-l" in req else "(not sent: the probe failed)")
                lines.append(f"| {name} | `{req}` | {rc} | {err.splitlines()[0] if err else '(empty)'} | {msg} |")
    finally:
        ctl.run_text("a2", L.installed_remove_script())
    (Path(__file__).parent / "sudo-stderr.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main_()
