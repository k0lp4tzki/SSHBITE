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
