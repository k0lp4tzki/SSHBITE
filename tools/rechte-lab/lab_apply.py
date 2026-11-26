#!/usr/bin/env python3
"""Lab helper (test only): roll the minimal-rights configuration from deliverables/config/ onto lab hosts.

Usage: lab_apply.py minimal   - gate + collector + sudoers + restricted authorized_keys on every lab host
       lab_apply.py installmd - today's setup: the sudoers line of docs/install.md (/bin/true, /bin/sh -s),
                                plain authorized_keys line, account-owned home - on every host
Runs as root over the lab-control sshd (port 2200), exactly the steps of chapter 4 of the document.
"""
import asyncio
import sys
from pathlib import Path

import asyncssh

ROOT = Path(__file__).resolve().parents[2]
CFG = ROOT / "deliverables" / "config"
LABKEY = ROOT / "lab" / "keys" / "labctl_ed25519"
PUB = (ROOT / "lab" / "keys" / "audit_ed25519.pub").read_text().split()[:2]
SCANNER = "172.30.1.2"    # address the lab sees for the scanner (SSH_CLIENT on jump)
GATE = 'command="/usr/local/libexec/sshbite/sshbite-gate"'

# host -> authorized_keys options (variant A/B/C of authorized_keys.sshbite)
HOSTS = {
    "jump": f'restrict,port-forwarding,permitopen="*:22",from="{SCANNER}",{GATE}',
    **{h: f'restrict,from="172.30.1.5",{GATE}' for h in ("a1", "a2", "a3", "a4", "a5")},
    **{h: f'restrict,from="172.30.2.5",{GATE}' for h in ("b1", "b2", "b4", "b5")},
    "b3": f'restrict,port-forwarding,permitopen="*:22",from="172.30.2.5",{GATE}',
    "c1": f'restrict,port-forwarding,permitopen="*:22",from="172.30.3.13",{GATE}',
    "c2": f'restrict,from="172.30.3.21",{GATE}',
}

MINIMAL = r'''set -eu
install -d -m 0755 -o root -g root /usr/local/libexec/sshbite
install -m 0755 -o root -g root /tmp/sb/sshbite-gate /usr/local/libexec/sshbite/sshbite-gate
install -m 0755 -o root -g root /tmp/sb/sshbite-collect /usr/local/libexec/sshbite/sshbite-collect
visudo -cf /tmp/sb/sudoers.d-sshbite
install -m 0440 -o root -g root /tmp/sb/sudoers.d-sshbite /etc/sudoers.d/sshbite
chown -R root:root /home/sshbite
chmod 0755 /home/sshbite /home/sshbite/.ssh
install -m 0644 -o root -g root /tmp/sb/ak /home/sshbite/.ssh/authorized_keys
passwd -l sshbite >/dev/null
rm -rf /tmp/sb
'''
INSTALLMD = r'''set -eu
# back to the lab's original audit account (lab/image/lib.sh common): own home, plain key, no gate
rm -rf /usr/local/libexec/sshbite
chown -R sshbite:sshbite /home/sshbite
chmod 0700 /home/sshbite/.ssh
cat > /home/sshbite/.ssh/authorized_keys
chown sshbite:sshbite /home/sshbite/.ssh/authorized_keys
chmod 0600 /home/sshbite/.ssh/authorized_keys
printf '%s\n' '# docs/install.md' 'Defaults:sshbite !lecture' 'sshbite ALL=(root) NOPASSWD: /bin/true, /bin/sh -s' > /etc/sudoers.d/sshbite
chmod 0440 /etc/sudoers.d/sshbite
visudo -cf /etc/sudoers.d/sshbite
'''


async def apply(host: str, mode: str) -> str:
    async with asyncssh.connect(host, 2200, username="root", client_keys=[str(LABKEY)], known_hosts=None,
                                agent_path=None, config=None) as c:
        if mode == "minimal":
            await c.run("rm -rf /tmp/sb; mkdir -m 700 /tmp/sb", check=True)
            for f in ("sshbite-gate", "sshbite-collect", "sudoers.d-sshbite"):
                await c.run(f"cat > /tmp/sb/{f}", input=(CFG / f).read_bytes(), encoding=None, check=True)
            line = f"{HOSTS[host]} {PUB[0]} {PUB[1]} sshbite-audit\n"
            await c.run("cat > /tmp/sb/ak", input=line, check=True)
            r = await c.run(MINIMAL)
        else:
            r = await c.run(INSTALLMD, input=f"{PUB[0]} {PUB[1]} sshbite-audit\n")
        return f"{host}: exit {r.exit_status} {r.stdout.strip()} {r.stderr.strip()}"


async def main(mode: str) -> None:
    for line in await asyncio.gather(*(apply(h, mode) for h in HOSTS)):
        print(line)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
