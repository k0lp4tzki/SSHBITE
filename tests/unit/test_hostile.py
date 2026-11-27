"""Hostile target data (independent review findings): symlinks, odd numbers, option-like names, passwords."""

import os
import subprocess
from pathlib import Path

import pytest

from sshbite import collector
from sshbite.parse import records, ssh_config
from sshbite.parse.host import build
from sshbite.privilege import SudoSecret


def _run_collector(tmp_path: Path, home: Path) -> str:
    """Run collect.sh unprivileged with a fake getent that lists one user whose home is `home`."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "getent").write_text(f"#!/bin/sh\necho 'mallory:x:{os.getuid()}:{os.getgid()}::{home}:/bin/sh'\n")
    (bindir / "getent").chmod(0o755)
    script = collector.collect_script().replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={bindir}:/usr/bin:/bin", 1)
    return subprocess.run(["/bin/sh", "-s"], input=script, capture_output=True, text=True, timeout=60).stdout


def test_symlinks_in_ssh_dir_are_not_followed(tmp_path):
    secret = tmp_path / "shadow-like"
    secret.write_text("root:$6$SECRETHASH:19000:0:99999:7:::\n")
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "known_hosts").symlink_to(secret)
    (home / ".ssh" / "authorized_keys").symlink_to(secret)
    (home / ".ssh" / "id_rsa").symlink_to(secret)
    out = _run_collector(tmp_path, home)
    assert "#END" in out
    assert "SECRETHASH" not in out
    assert f"#X {home}/.ssh/known_hosts\tsymlink not followed" in out
    assert f"#X {home}/.ssh/authorized_keys\tsymlink not followed" in out


def test_symlinked_ssh_dir_is_not_followed(tmp_path):
    other = tmp_path / "rootssh"
    other.mkdir()
    (other / "authorized_keys").write_text("ssh-ed25519 AAAA SECRETLINE\n")
    home = tmp_path / "home"
    home.mkdir()
    (home / ".ssh").symlink_to(other)
    out = _run_collector(tmp_path, home)
    assert "SECRETLINE" not in out and f"#X {home}/.ssh\tsymlink not followed" in out


def test_odd_ports_do_not_crash():
    entries, _ = ssh_config.parse("Host x\n  Port \u00b2\n  ProxyJump j:\u00b2,k:99999999999999999999,ok:2222\n", "f")
    assert entries[0].port is None
    assert ssh_config.proxyjump_hops(entries[0].proxyjump) == [("j:\u00b2", None), ("k:99999999999999999999", None),
                                                                  ("ok", 2222)]


def test_huge_numbers_from_passwd_and_shadow():
    text = ("#SSHBITE 1 x\n#S ACCOUNTS\n#V cmd\tpasswd\n|big:x:99999999999999999999999:1::/home/big:/bin/sh\n"
            "#S SHADOW\n#V cmd\tshadow\n|big:$:3000000\n#END 1\n")
    d = build(records.parse(text))
    assert d.accounts["big"].uid is None and d.accounts["big"].expiry is None


def test_names_starting_with_dash_are_never_sent():
    from sshbite.crawl import _NAME_RE

    assert not _NAME_RE.match("-sfiles") and _NAME_RE.match("b1") and _NAME_RE.match("a-1.corp")
    assert 'getent hosts -- "$n"' in collector.resolve_script()


@pytest.mark.parametrize("pw", ["a\nreboot", "a\rb"])
def test_password_with_line_break_is_refused(pw):
    with pytest.raises(ValueError):
        SudoSecret().set(pw)


def _run_collector_as_root(tmp_path: Path, home: Path) -> tuple[str, str]:
    """Run collect.sh as if it were root (fake `id -u` = 0) for one account with a non-zero uid.

    The fake setpriv marks what it runs (SP=1) and runs the command; the fake ssh-keygen behaves like
    OpenSSH run as the owner of a 0644 key: refuses the file ("bad permissions"), but derives the public
    half from a key given on stdin. Every call is logged so the test can see who opened which path."""
    import asyncssh

    key = asyncssh.generate_private_key("ssh-ed25519")
    pub = key.export_public_key().decode().strip()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"

    def tool(name: str, body: str) -> None:
        (bindir / name).write_text("#!/bin/sh\n" + body)
        (bindir / name).chmod(0o755)

    tool("getent", f"echo 'mallory:x:{os.getuid() or 4242}:{os.getgid()}::{home}:/bin/sh'\n")
    tool("id", 'if [ "$1" = -u ]; then echo 0; else /usr/bin/id "$@"; fi\n')
    tool("setpriv", 'shift 5\nSP=1 exec "$@"\n')
    tool("ssh-keygen", f"""echo "${{SP:-0}} $*" >> {log}
eval "f=\\${{$#}}"
if [ "$f" = /dev/stdin ]; then
  grep -q 'PRIVATE KEY-----' && echo '{pub}' && exit 0
  echo 'Load key "/dev/stdin": invalid format'; exit 255
fi
echo '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
echo '@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @'
echo '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
echo "Permissions 0644 for '$f' are too open."
echo "Load key \\"$f\\": bad permissions"
exit 255
""")
    script = collector.collect_script().replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={bindir}:/usr/bin:/bin", 1)
    out = subprocess.run(["/bin/sh", "-s"], input=script, capture_output=True, text=True, timeout=60).stdout
    return out, log.read_text() if log.exists() else ""


def test_owners_0644_private_key_is_still_found_unencrypted(tmp_path):
    """CEO correction 1: ssh-keygen refuses a group/other-readable key when it runs as the owner. The account
    then reads the key (setpriv) and pipes it to the collector's ssh-keygen; no path below ~ is opened as root."""
    if not (Path("/usr/bin/setpriv").exists() or Path("/bin/setpriv").exists()):
        pytest.skip("the collector checks for /usr/bin/setpriv or /bin/setpriv; neither exists here")
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    k = home / ".ssh" / "id_rsa"
    k.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
    k.chmod(0o644)
    out, calls = _run_collector_as_root(tmp_path, home)
    assert "#END" in out and "#V setpriv\tyes" in out
    c = records.parse(out)
    assert c.keygen[str(k)]["y"][0] == 0
    d = build(c)
    pk = [p for p in d.private_keys if p.path == str(k)]
    assert len(pk) == 1 and pk[0].encrypted == "no" and pk[0].alg == "ssh-ed25519" and pk[0].fp
    # who opened what: every ssh-keygen with a path below ~ ran as the account; the collector's own
    # ssh-keygen only got /dev/stdin
    lines = calls.splitlines()
    assert f"1 -y -P  -f {k}" in lines and "0 -y -P  -f /dev/stdin" in lines
    assert all(ln.startswith("1 ") or ln.endswith(" -f /dev/stdin") for ln in lines), lines


def test_encrypted_0644_key_stays_encrypted_through_the_pipe(tmp_path):
    """The fallback does not turn an unreadable or encrypted key into 'unencrypted'."""
    if not (Path("/usr/bin/setpriv").exists() or Path("/bin/setpriv").exists()):
        pytest.skip("the collector checks for /usr/bin/setpriv or /bin/setpriv; neither exists here")
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    k = home / ".ssh" / "id_enc"
    # header line passes privkey's check, the body has no BEGIN line the fake accepts on stdin
    k.write_text("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\n")
    k.chmod(0o644)
    out, _ = _run_collector_as_root(tmp_path, home)
    d = build(records.parse(out))
    pk = [p for p in d.private_keys if p.path == str(k)]
    assert len(pk) == 1 and pk[0].encrypted != "no" and pk[0].fp is None


def test_entry_gone_between_ls_and_read_is_reported_as_vanished(tmp_path):
    """CEO correction 2: a listed name that no longer exists is 'vanished while reading', not a name with a tab."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "getent").write_text(f"#!/bin/sh\necho 'mallory:x:{os.getuid()}:{os.getgid()}::{home}:/bin/sh'\n")
    (bindir / "getent").chmod(0o755)
    # ls lists a file that is not there (as if it was removed right after the listing)
    (bindir / "ls").write_text('#!/bin/sh\nif [ "$1" = -A ]; then echo known_hosts.gone; else /bin/ls "$@"; fi\n')
    (bindir / "ls").chmod(0o755)
    script = collector.collect_script().replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={bindir}:/usr/bin:/bin", 1)
    out = subprocess.run(["/bin/sh", "-s"], input=script, capture_output=True, text=True, timeout=60).stdout
    assert f"#X {home}/.ssh/known_hosts.gone\tvanished while reading" in out
    assert "name with tab or newline skipped" not in out
