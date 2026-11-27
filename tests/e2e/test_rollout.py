"""tools/rollout: the host agent (plan, apply, verify, remove) and the checks of sshbite-rollout's own files.

Runs against a throw-away container of a lab host image (Debian 12 with sshd and sudo), not against the
running lab: `docker run` starts it, the agent goes in through `docker exec -i ... sh -s`, exactly the text
sshbite-rollout would pipe through SSH. SSHBITE_ROLLOUT_TEST_IMAGE selects another image.
"""

from __future__ import annotations

import base64
import hashlib
import os
import pathlib
import shutil
import subprocess
import time
import uuid

import pytest

from sshbite.collector import bundle

pytestmark = pytest.mark.e2e

REPO = pathlib.Path(__file__).resolve().parents[2]
AGENT = REPO / "tools" / "rollout" / "host-agent.sh"
IMAGE = os.environ.get("SSHBITE_ROLLOUT_TEST_IMAGE", "sshbite-lab-a1")
P = "/usr/local/libexec/sshbite/sshbite-collect"
PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHu369rolloutTestKeyNotARealOne0000000000000000 sshbite-audit"
FILES = ("authorized_keys.sshbite", "sshbite-collect", "sshbite-gate", "sshbite-resolve", "sudoers.d-sshbite")
WATCHED = "/etc/passwd /etc/group /etc/shadow /etc/sudoers /etc/sudoers.d /etc/ssh /home /usr/local"


def _docker(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True, timeout=120)


@pytest.fixture()
def host():
    if not shutil.which("docker"):
        pytest.skip("docker is not available")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        pytest.skip(f"image {IMAGE} is not built (lab/up.sh builds the lab images)")
    name = "sshbite-rollout-test-" + uuid.uuid4().hex[:8]
    r = _docker("run", "-d", "--name", name, "--hostname", "rollout", IMAGE)
    assert r.returncode == 0, r.stderr
    try:
        for _ in range(50):
            if sh(name, "test -s /run/sshd.pid && sshd -t").returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError("sshd did not start in the test container")
        # the lab images bring their own audit account with a sudo rule of the legacy mode; these tests
        # start from a host without any SSHBITE file
        sh(name, "rm -f /etc/sudoers.d/sshbite")
        yield name
    finally:
        _docker("rm", "-f", name)


def sh(name: str, script: str) -> subprocess.CompletedProcess:
    return _docker("exec", "-i", "-u", "0", name, "sh", "-c", script)


def out(name: str, script: str) -> str:
    r = sh(name, script)
    assert r.returncode == 0, r.stdout + r.stderr
    return r.stdout


def ak_line(files: dict[str, bytes], variant: str, from_: str) -> str:
    lines = [x for x in files["authorized_keys.sshbite"].decode().splitlines() if not x.startswith("#")]
    line = lines["ABC".index(variant)]
    for ph in ("<SCANNER-IP>", "<ENTRY-HOST-IP>", "<PREVIOUS-HOP-IP>"):
        line = line.replace(ph, from_)
    return line.replace("<AUDIT-PUBLIC-KEY>", PUBKEY)


def agent(name: str, action: str, *, user: str = "auditx", variant: str = "B", from_: str = "192.0.2.10",
          files: bool = True, adopt: str = "no", rm_foreign: str = "no", hostkeys: str = "no"):
    """Build the text sshbite-rollout sends (its function `bundle`) and run it in the container."""
    rendered = bundle.render(P, user)
    head = [f"ACTION='{action}'", f"AUDIT_USER='{user}'", f"VARIANT='{variant}'", f"FROM='{from_}'",
            f"COLLECTOR_PATH='{P}'", f"ADOPT='{adopt}'", f"RM_FOREIGN='{rm_foreign}'", f"WANT_HOSTKEYS='{hostkeys}'"]
    if files:
        head.append(f"AK_LINE='{ak_line(rendered, variant, from_)}'")
        head.append("HAVE_FILES='yes'")
        head.append('expect_sum() {\n  case "$1" in')
        head += [f"    {n}) echo '{hashlib.sha256(rendered[n]).hexdigest()}' ;;" for n in FILES]
        head.append('  esac\n}\nemit_file() {\n  case "$1" in')
        for n in FILES:
            head.append(f"    {n}) base64 -d <<'SSHBITE_ROLLOUT_B64'\n{base64.encodebytes(rendered[n]).decode()}SSHBITE_ROLLOUT_B64\n    ;;")
        head.append("  esac\n}")
    else:
        head += ["AK_LINE=''", "HAVE_FILES='no'", "expect_sum() { :; }", "emit_file() { :; }"]
    r = _docker("exec", "-i", "-u", "0", name, "sh", "-s", stdin="\n".join(head) + "\n" + AGENT.read_text())
    lines = [tuple(x.split("\t", 1)) for x in r.stdout.splitlines() if "\t" in x]
    return r.returncode, lines, r.stdout + r.stderr


def levels(lines, level: str) -> list[str]:
    return [text for lvl, text in lines if lvl == level]


def snapshot(name: str) -> str:
    return out(name, f"find {WATCHED} -xdev -printf '%p %y %m %U %G %s %T@\\n' | sort; "
                     "ls -d /var/lib/sshbite-rollout 2>&1 || true")


def test_plan_and_check_change_nothing(host):
    before = snapshot(host)
    rc, lines, raw = agent(host, "check")
    assert rc == 0 and not levels(lines, "FAIL") and not levels(lines, "PLAN"), raw
    rc, lines, raw = agent(host, "plan", variant="A", hostkeys="yes")
    assert rc == 0 and not levels(lines, "FAIL"), raw
    plans = "\n".join(levels(lines, "PLAN"))
    for want in ("Konto auditx anlegen", f"{P} installieren", "/etc/sudoers.d/sshbite installieren",
                 "/home/auditx/.ssh/authorized_keys schreiben", "Match User auditx"):
        assert want in plans, raw
    assert levels(lines, "HOSTKEY") and all(k.split()[0] in ("ssh-ed25519", "ssh-rsa") or k.startswith("ecdsa-")
                                            for k in levels(lines, "HOSTKEY")), raw
    # before the first build there are no files to compare: still a plan, still no change
    rc, lines, raw = agent(host, "plan", files=False)
    assert rc == 0 and levels(lines, "PLAN"), raw
    assert snapshot(host) == before


def test_apply_verify_repair_remove(host):
    before = snapshot(host)
    sshd_config = out(host, "sha256sum /etc/ssh/sshd_config")
    root_before = out(host, "sshd -T -C user=root,host=192.0.2.10,addr=192.0.2.10")
    rc, lines, raw = agent(host, "apply", variant="A", hostkeys="yes")
    assert rc == 0 and not levels(lines, "FAIL"), raw
    assert len(levels(lines, "DONE")) >= 8 and levels(lines, "HOSTKEY"), raw
    rendered = bundle.render(P, "auditx")
    # the account: own group, /bin/sh, locked, created by the script
    assert out(host, "getent passwd auditx").strip().endswith(":/home/auditx:/bin/sh")
    assert out(host, "id -Gn auditx").split() == ["auditx"]
    assert out(host, "getent shadow auditx | cut -d: -f2")[0] in "!*"
    # files: root-owned, the exported bytes
    for src, dest in (("sshbite-collect", P), ("sshbite-gate", "/usr/local/libexec/sshbite/sshbite-gate"),
                      ("sshbite-resolve", "/usr/local/libexec/sshbite/sshbite-resolve")):
        assert out(host, f"stat -c '%U %G %a' {dest}").strip() == "root root 755"
        assert out(host, f"sha256sum {dest}").split()[0] == hashlib.sha256(rendered[src]).hexdigest()
    assert out(host, "stat -c '%U %G %a' /etc/sudoers.d/sshbite").strip() == "root root 440"
    listed = out(host, "sudo -l -U auditx").split("may run the following commands")[1].splitlines()[1:]
    assert [x.strip() for x in listed if x.strip()] == [f'(root) NOPASSWD: {P} ""']
    # home, .ssh and the key line belong to root; the line is variant A with the from= given
    assert out(host, "stat -c '%U %a' /home/auditx /home/auditx/.ssh /home/auditx/.ssh/authorized_keys").split() \
        == ["root", "755", "root", "755", "root", "644"]
    assert out(host, "cat /home/auditx/.ssh/authorized_keys") == ak_line(rendered, "A", "192.0.2.10") + "\n"
    assert out(host, "ls -A /home/auditx/.ssh").split() == ["authorized_keys"]
    # sshd: the block works for the account and for nobody else, and the config is valid
    eff = out(host, "sshd -t && sshd -T -C user=auditx,host=192.0.2.10,addr=192.0.2.10")
    assert "allowtcpforwarding local" in eff and "allowstreamlocalforwarding no" in eff
    assert out(host, "sshd -T -C user=root,host=192.0.2.10,addr=192.0.2.10") == root_before
    # again: nothing left to do
    rc, lines, raw = agent(host, "apply", variant="A")
    assert rc == 0 and not levels(lines, "DONE") and not levels(lines, "FAIL"), raw
    rc, lines, raw = agent(host, "verify", variant="A")
    assert rc == 0 and not levels(lines, "FAIL"), raw
    # a second key line and a replaced collector: verify fails without changing anything, apply repairs
    sh(host, "echo 'ssh-ed25519 AAAAintruder x' >> /home/auditx/.ssh/authorized_keys; echo '#!/bin/sh' > " + P)
    rc, lines, raw = agent(host, "verify", variant="A")
    assert rc == 1 and len(levels(lines, "FAIL")) == 2, raw
    assert "intruder" in out(host, "cat /home/auditx/.ssh/authorized_keys")
    rc, lines, raw = agent(host, "apply", variant="A")
    assert rc == 0 and len(levels(lines, "DONE")) == 2, raw
    assert "intruder" not in out(host, "cat /home/auditx/.ssh/authorized_keys")
    # another from= is a planned change, not a silent one
    rc, lines, raw = agent(host, "plan", variant="A", from_="192.0.2.99")
    assert rc == 0 and any('from="192.0.2.99"' in x for x in levels(lines, "PLAN")), raw
    # remove: first the list, then the state from before (backups stay)
    rc, lines, raw = agent(host, "remove-plan", variant="A")
    assert rc == 0 and len(levels(lines, "PLAN")) >= 6 and not levels(lines, "DONE"), raw
    assert out(host, "id -u auditx").strip().isdigit()
    rc, lines, raw = agent(host, "remove", variant="A")
    assert rc == 0 and not levels(lines, "FAIL"), raw
    assert sh(host, "id auditx").returncode != 0
    assert sh(host, "test -e /home/auditx || test -e /usr/local/libexec/sshbite || test -e /etc/sudoers.d/sshbite").returncode != 0
    assert out(host, "sha256sum /etc/ssh/sshd_config") == sshd_config
    assert out(host, "sshd -t && sshd -T -C user=root,host=192.0.2.10,addr=192.0.2.10") == root_before
    after = snapshot(host)

    def stable(snap: str) -> list[str]:
        # useradd/userdel rewrite the account databases and leave their own backups ("passwd-")
        skip = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/subuid", "/etc/subgid",
                "/usr/local/libexec ", "/usr/local ", "/home ", "/etc/ssh ", "/etc/sudoers.d ", "/var/lib/sshbite-rollout",
                "ls: ")
        return [x.rsplit(" ", 1)[0] for x in snap.splitlines() if not x.startswith(skip)]

    assert stable(after) == stable(before)


def test_existing_account_and_foreign_rules_need_consent(host):
    out(host, "useradd -m -s /bin/bash -G sudo legacy && mkdir -p /home/legacy/.ssh "
              "&& echo 'ssh-ed25519 AAAAold old' > /home/legacy/.ssh/authorized_keys "
              "&& echo 'ssh-ed25519 AAAAold2 old' > /home/legacy/.ssh/authorized_keys2 "
              "&& chown -R legacy: /home/legacy/.ssh "
              "&& echo 'legacy ALL=(root) NOPASSWD: ALL' > /etc/sudoers.d/legacy-all && chmod 440 /etc/sudoers.d/legacy-all "
              "&& printf 'legacy ALL=(root) NOPASSWD: /bin/true\\nother ALL=(root) /bin/true\\n' > /etc/sudoers.d/mixed "
              "&& chmod 440 /etc/sudoers.d/mixed")
    before = snapshot(host)
    rc, lines, raw = agent(host, "apply", user="legacy")
    fails = "\n".join(levels(lines, "FAIL"))
    assert rc == 1 and "gibt es schon" in fails and "legacy-all" in fails and "mixed" in fails, raw
    assert not levels(lines, "DONE") and snapshot(host) == before
    # consent for the account and the removable file is not enough while a mixed file is left
    rc, lines, raw = agent(host, "apply", user="legacy", adopt="yes", rm_foreign="yes")
    assert rc == 1 and "mixed" in "\n".join(levels(lines, "FAIL")) and not levels(lines, "DONE"), raw
    assert snapshot(host) == before
    out(host, "sed -i '/^legacy /d' /etc/sudoers.d/mixed")
    rc, lines, raw = agent(host, "apply", user="legacy", adopt="yes", rm_foreign="yes")
    assert rc == 0 and not levels(lines, "FAIL"), raw
    assert out(host, "id -Gn legacy").split() == ["legacy"]
    assert out(host, "getent passwd legacy | cut -d: -f7").strip() == "/bin/sh"
    assert out(host, "ls -A /home/legacy/.ssh; ls /etc/sudoers.d").split().count("authorized_keys2") == 0
    assert sh(host, "test -e /etc/sudoers.d/legacy-all").returncode != 0
    assert out(host, "cat /etc/sudoers.d/mixed").strip() == "other ALL=(root) /bin/true"
    backups = out(host, "find /var/lib/sshbite-rollout/backup -type f | sed 's|.*/backup/[^/]*/||' | sort").split()
    assert backups == ["authorized_keys", "dot-ssh/authorized_keys2", "sudoers.d-legacy-all"]
    listed = out(host, "sudo -l -U legacy").split("may run the following commands")[1].splitlines()[1:]
    assert [x.strip() for x in listed if x.strip()] == [f'(root) NOPASSWD: {P} ""']
    # the next runs know the account without the option; remove leaves an adopted account alone
    rc, lines, raw = agent(host, "verify", user="legacy")
    assert rc == 0 and not levels(lines, "FAIL"), raw
    rc, lines, raw = agent(host, "remove", user="legacy")
    assert rc == 0 and out(host, "id -un legacy").strip() == "legacy", raw
    assert sh(host, "test -e /etc/sudoers.d/sshbite || test -e /home/legacy/.ssh/authorized_keys").returncode != 0


def test_global_all_rule_before_and_after_includedir(host):
    """SUSE's default sudoers: fine before the includedir line (a warning), fatal after it (sudo takes the last match)."""
    inc = out(host, "grep -E '^[#@]includedir' /etc/sudoers").strip()
    out(host, f"sed -i 's|^{inc}$|Defaults targetpw\\nALL   ALL=(ALL) ALL   # WARNING!\\n{inc}|' /etc/sudoers && visudo -c")
    rc, lines, raw = agent(host, "apply")
    assert rc == 0 and not levels(lines, "FAIL"), raw
    assert any("ALL ALL=(ALL) ALL" in x for x in levels(lines, "WARN")), raw
    out(host, "sed -i '/^Defaults targetpw$/d; /^ALL   ALL=(ALL) ALL/d' /etc/sudoers "
              "&& printf 'Defaults targetpw\\nALL ALL=(ALL) ALL\\n' >> /etc/sudoers && visudo -c")
    rc, lines, raw = agent(host, "verify")
    assert rc == 1 and any("überstimmt" in x for x in levels(lines, "FAIL")), raw


def test_rollout_refuses_bad_settings(host):
    """sshbite-rollout reads its two files as data and stops (exit 2) before it touches anything."""
    out(host, "mkdir -p /opt/repo/tools /etc/sshbite")
    for src, dest in ((REPO / "tools" / "rollout", "/opt/repo/tools/rollout"), (REPO / "pyproject.toml", "/opt/repo/pyproject.toml")):
        assert _docker("cp", str(src), f"{host}:{dest}").returncode == 0
    run = "/opt/repo/tools/rollout/sshbite-rollout"

    def plan(conf: str, hosts: str = "") -> subprocess.CompletedProcess:
        _docker("exec", "-i", "-u", "0", host, "sh", "-c", "cat > /etc/sshbite/rollout.conf", stdin=conf)
        _docker("exec", "-i", "-u", "0", host, "sh", "-c", "cat > /etc/sshbite/rollout.hosts", stdin=hosts)
        return sh(host, f"{run} plan")

    base = "MODE=docker\nENTRY_HOST=192.0.2.5\n"
    for conf, hosts, want in (
        ("AUDIT_USER=root\n" + base, "", "AUDIT_USER='root'"),
        ("AUDIT_USER=a b\n" + base, "", "AUDIT_USER='a b'"),
        ("AUDIT_USER=x;id\n" + base, "", "AUDIT_USER='x;id'"),
        ("AUDIT_USER=$(id)\n" + base, "", "AUDIT_USER='$(id)'"),
        ("MODE=docker\n", "", "ENTRY_HOST fehlt"),
        ("MODE=docker\nENTRY_HOST=127.0.0.1\n", "", "Loopback"),
        (base + "COLLECTOR_PATH=/tmp/../x/c\n", "", "COLLECTOR_PATH"),
        (base + "SSH_OPTS=-o ProxyCommand=$(id)\n", "", "SSH_OPTS"),
        (base + "NOPE=1\n", "", "unbekannter Schlüssel NOPE"),
        (base, "192.0.2.6\n192.0.2.6\n", "steht doppelt"),
        (base, "192.0.2.6 hop\n", "ein hop braucht from="),
        (base, "192.0.2.6 from=$(id)\n", "from= braucht"),
        (base, "192.0.2.6 nonsense\n", "unbekannte Angabe"),
    ):
        r = plan(conf, hosts)
        assert r.returncode == 2 and want in r.stderr, (conf, hosts, r.stdout, r.stderr)
    assert sh(host, "id auditx || test -e /var/lib/sshbite-rollout || test -e /etc/sshbite/audit_ed25519").returncode != 0
    assert sh(host, f"{run} nonsense").returncode == 2
    assert "sshbite-rollout init" in out(host, f"{run} --help")
