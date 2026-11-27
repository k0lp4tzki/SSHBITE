"""Render the lab's key-dependent seed files (authorized_keys, known_hosts, ssh config) from lab/keys.

Run by gen_keys.sh; the output under lab/seed/<host>/files/ is committed. Paths below
mirror the target filesystem. Hashed known_hosts lines use the salt
sha1("sshbite-lab-<host>-<line>") (20 bytes) so that they are reproducible.
Standard library only.
"""

import base64
import hashlib
import hmac
from pathlib import Path

LAB = Path(__file__).resolve().parent
KEYS = LAB / "keys"


def pub(name: str, comment: bool = True) -> str:
    parts = (KEYS / f"{name}.pub").read_text().split()
    return " ".join(parts[:3] if comment else parts[:2])


def hk(host: str) -> str:
    """ed25519 host key without comment."""
    return pub(f"{host}_host_ed25519", comment=False)


def hashed(host: str, line: int, name: str) -> str:
    salt = hashlib.sha1(f"sshbite-lab-{host}-{line}".encode()).digest()
    mac = hmac.new(salt, name.encode(), hashlib.sha1).digest()
    return f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(mac).decode()}"


FILES: dict[str, dict[str, str]] = {
    "jump": {
        "/home/ops/.ssh/config": "Host a1\n    HostName 172.30.1.11\n    User deploy\nHost b1\n    User admin\n"
                                 "Host bastion-old\n    HostName 203.0.113.10\n",
        "/home/ops/.ssh/known_hosts": f"172.30.1.11 {hk('a1')}\n",
    },
    "a1": {
        "/home/deploy/.ssh/authorized_keys": f'expiry-time="20991231" {pub("k_ops")}\n',
        "/home/deploy/.ssh/known_hosts": (
            f"{hashed('a1', 1, '172.30.1.12')} {hk('a2')}\n"
            f"{hashed('a1', 2, 'oldsrv.corp.example')} {pub('random_1', False)}\n"
            f"172.30.1.5 {hk('jump')}\n"),
        "/home/deploy/.ssh/config": "Host a3\n",
        "/root/.ssh/authorized_keys": f"{pub('k_fleet')}\n",
    },
    "a2": {
        "/home/deploy/.ssh/authorized_keys": f"{pub('k_deploy')}\n",
        "/home/deploy/.ssh/config": "Host a4\n    HostName 172.30.1.14\n",
        "/home/deploy/.ssh/known_hosts": f"172.30.1.99 {pub('random_2', False)}\n",
        "/var/backups/.ssh/authorized_keys":
            f'command="/usr/local/bin/backup.sh",no-port-forwarding,no-pty {pub("k_backup")}\n',
        "/root/.ssh/authorized_keys": f"{pub('k_fleet')}\n",
    },
    "a3": {
        "/home/app/.ssh/authorized_keys": f"{pub('k_deploy')}\n",
        "/home/app/.ssh/config": "Host a5\n",
        "/etc/ssh/ssh_known_hosts": f"a1,172.30.1.11 {hk('a1')}\n",
        "/root/.ssh/authorized_keys": f"{pub('k_fleet')}\n",
    },
    "a4": {
        "/root/.ssh/authorized_keys": f"{pub('k_dsa')}\n",
    },
    "a5": {
        "/home/alice/.ssh/config": "Host db\n    HostName 172.30.2.12\n    ProxyJump 172.30.1.11\n",
        "/root/.ssh/authorized_keys": f"{pub('k_fleet')}\n",
    },
    "b1": {
        "/home/admin/.ssh/authorized_keys": f'from="172.30.2.5" {pub("k_ops")}\n',
        "/home/admin/.ssh/known_hosts": f"b2 {hk('b2')}\nb3,172.30.2.13 {pub('b3_old_host_ed25519', False)}\n",
        "/home/admin/.ssh/config": "Host b5\n",
        "/root/.ssh/authorized_keys": f"{pub('k_fleet')}\n{pub('k_dsa')}\n",
    },
    "b2": {
        "/home/www/.ssh/known_hosts": f"git.example.com {pub('random_3', False)}\n",
        "/home/www/.ssh/authorized_keys": "# www: deploy keys go here\n",
        "/home/monitor/.ssh/authorized_keys": f'from="10.0.0.0/8" {pub("k_mon")}\n',
        "/home/alice/.ssh/authorized_keys": f"{pub('k_dup')}\n",
        "/root/.ssh/authorized_keys": f"{pub('k_fleet')}\n",
    },
    "b3": {
        "/home/ops2/.ssh/config": "Host c1\n    HostName 172.30.3.21\n    User svc\nHost legacy\n"
                                  "    HostName 10.20.30.40\n",
        "/home/ops2/.ssh/known_hosts": f"172.30.2.14 {hk('b4')}\n",
        "/root/.ssh/authorized_keys": f"{pub('k_fleet')}\n",
    },
    "b4": {},
    "b5": {
        "/home/carol/.ssh/authorized_keys": f"{pub('k_carol')}\n",
    },
    "c1": {
        "/home/svc/.ssh/authorized_keys": f"{pub('k_bridge')}\n",
        "/root/.ssh/authorized_keys": f"restrict {pub('k_orphan')}\n",
        "/root/.ssh/known_hosts": f"172.30.3.22 {hk('c2')}\n",
    },
    "c2": {
        "/home/svc/.ssh/authorized_keys": f"{pub('k_bridge')}\n",
        "/root/.ssh/authorized_keys": f'cert-authority,principals="ops" {pub("k_ca")}\n',
    },
    # AlmaLinux 9, stand-alone on lab_r (spec 8.2): no other host refers to it. authorized_keys2 is
    # root-owned 0600 in alice's home - sshd (reading as alice) cannot use it, and neither may SSHBITE.
    "r1": {
        "/home/alice/.ssh/authorized_keys": f"{pub('k_ops')}\n",
        "/home/alice/.ssh/authorized_keys2": f"{pub('k_orphan')}\n",
        "/home/alice/.ssh/known_hosts": f"172.30.1.5 {hk('jump')}\n",
    },
}


def main() -> None:
    for host, files in FILES.items():
        base = LAB / "seed" / host / "files"
        for path, content in files.items():
            p = base / path.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        (base).mkdir(parents=True, exist_ok=True)
        keep = base / ".keep"
        if not files:
            keep.write_text("")
    # the line appended to b2's www authorized_keys before scan 2 (spec 9.3)
    (LAB / "seed" / "b2" / "k_new.line").write_text(pub("k_new") + "\n")


if __name__ == "__main__":
    main()
