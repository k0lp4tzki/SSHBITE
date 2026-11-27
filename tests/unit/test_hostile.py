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


def _run_collector_as_root(tmp_path: Path, home: Path, extra_users: str = "", fifo_glob: str = "") -> tuple[str, str]:
    """Run collect.sh as if it were root (fake `id -u` = 0) for one account with a non-zero uid.

    The fake setpriv marks how it runs the command (SP=1: as the account with --reuid; SP=2: real uid nobody,
    effective uid the account) and runs it. The fake ssh-keygen behaves like OpenSSH: run with the real uid of
    the owner of a 0644 key it refuses the file ("bad permissions"); with another real uid it derives the
    public half. Every call is logged so the test can see who opened which path."""
    import asyncssh

    key = asyncssh.generate_private_key("ssh-ed25519")
    pub = key.export_public_key().decode().strip()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"

    def tool(name: str, body: str) -> None:
        (bindir / name).write_text("#!/bin/sh\n" + body)
        (bindir / name).chmod(0o755)

    tool("getent", f"echo 'mallory:x:{os.getuid() or 4242}:{os.getgid()}::{home}:/bin/sh'\n"
                   "echo 'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin'\n" + extra_users)
    tool("id", 'if [ "$1" = -u ]; then echo 0; else /usr/bin/id "$@"; fi\n')
    # fifo_glob: the account swaps a matching file for a FIFO between the collector's checks and the read
    # (the race of check-4 finding 1, made certain): head then blocks in open() until timeout ends it
    swap = (f'if [ "$1" = head ]; then eval "f=\\${{$#}}"; case "$f" in {fifo_glob}) rm -f "$f"; mkfifo "$f" ;; esac; fi\n'
            if fifo_glob else "")
    tool("setpriv", 'sp=1\nwhile [ "$1" != -- ]; do case "$1" in --ruid=*) sp=2 ;; esac; shift; done\nshift\n'
                    + swap + 'SP=$sp exec "$@"\n')
    tool("ssh-keygen", f"""echo "${{SP:-0}} $*" >> {log}
eval "f=\\${{$#}}"
if [ "${{SP:-0}}" = 2 ]; then
  grep -q 'BEGIN OPENSSH PRIVATE KEY-----' "$f" && echo '{pub}' && exit 0
  echo "Load key \\"$f\\": incorrect passphrase supplied to decrypt private key"; exit 255
fi
echo '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
echo '@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @'
echo '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@'
echo "Permissions 0644 for '$f' are too open."
echo "Load key \\"$f\\": bad permissions"
exit 255
""")
    script = collector.collect_script().replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={bindir}:/usr/bin:/bin", 1)
    out = subprocess.run(["/bin/sh", "-s"], input=script, capture_output=True, text=True, timeout=120).stdout
    return out, log.read_text() if log.exists() else ""


def _need_setpriv_and_timeout():
    if not (Path("/usr/bin/setpriv").exists() or Path("/bin/setpriv").exists()):
        pytest.skip("the collector checks for /usr/bin/setpriv or /bin/setpriv; neither exists here")
    if not (Path("/usr/bin/timeout").exists() or Path("/bin/timeout").exists()):
        pytest.skip("the collector checks for /usr/bin/timeout or /bin/timeout; neither exists here")


def test_owners_0644_private_key_is_still_found_unencrypted(tmp_path):
    """CEO correction 1 and check-4 finding 4: ssh-keygen refuses a group/other-readable key when its real uid is
    the owner. It then runs again with the real uid of nobody and the effective uid of the account; no ssh-keygen
    runs as root on the account's bytes, and none reads stdin."""
    _need_setpriv_and_timeout()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    k = home / ".ssh" / "id_rsa"
    k.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
    k.chmod(0o644)
    out, calls = _run_collector_as_root(tmp_path, home)
    assert "#END" in out and "#V setpriv\tyes" in out and "#V timeout\tyes" in out
    c = records.parse(out)
    assert c.keygen[str(k)]["y"][0] == 0
    d = build(c)
    pk = [p for p in d.private_keys if p.path == str(k)]
    assert len(pk) == 1 and pk[0].encrypted == "no" and pk[0].alg == "ssh-ed25519" and pk[0].fp
    lines = calls.splitlines()
    assert f"1 -y -P  -f {k}" in lines and f"2 -y -P  -f {k}" in lines and f"1 -l -f {k}" in lines
    assert all(ln[0] in "12" for ln in lines), lines          # never as root
    assert not any("/dev/stdin" in ln or ln.endswith(" -") for ln in lines), lines


def test_encrypted_0644_key_stays_encrypted(tmp_path):
    """The second try does not turn an unreadable or encrypted key into 'unencrypted'."""
    _need_setpriv_and_timeout()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    k = home / ".ssh" / "id_enc"
    # header line passes privkey's check, the body has no BEGIN line the fake accepts
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


# ---------------------------------------------------------------- check-4 findings 1 and 2

def _write_key_line(path: Path, comment: str) -> str:
    import asyncssh

    line = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip() + " " + comment
    path.write_text(line + "\n")
    return line


def test_fifo_swapped_in_before_the_read_times_out_and_the_run_goes_on(tmp_path):
    """check-4 finding 1: the account swaps known_hosts for a FIFO after the collector's checks. The read as the
    account ends after 5 s (+1 s KILL) with 'read timed out'; the files after it are read, the run ends with #END."""
    import time

    _need_setpriv_and_timeout()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    ak = _write_key_line(home / ".ssh" / "authorized_keys", "ak@x")
    (home / ".ssh" / "known_hosts").write_text("h ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6jZpFBdpQjQ6yJ8bTt5jW4m5dQ1lDzW3gVq1r2s3t4\n")
    pub = _write_key_line(home / ".ssh" / "zz.pub", "zz@x")
    t0 = time.monotonic()
    out, _ = _run_collector_as_root(tmp_path, home, fifo_glob="*/known_hosts")
    took = time.monotonic() - t0
    kh = home / ".ssh" / "known_hosts"
    assert f"#X {kh}\tread timed out" in out.splitlines()
    assert "|" + ak in out and "|" + pub in out and "\n#END " in out
    assert 4.5 < took < 20, took
    c = records.parse(out)
    assert c.complete and (str(kh), "read timed out") in build(c).unreadable


def test_account_with_many_blocking_files_is_given_up_after_two_timeouts(tmp_path):
    """One account cannot hold the run for long: after two timeouts the rest of its ~/.ssh is skipped
    ('time budget exceeded'); the next account is read in full."""
    import time

    _need_setpriv_and_timeout()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    for i in range(6):
        (home / ".ssh" / f"known_hosts{i}").write_text("x\n")
    other = tmp_path / "other"
    (other / ".ssh").mkdir(parents=True)
    ak = _write_key_line(other / ".ssh" / "authorized_keys", "other@x")
    t0 = time.monotonic()
    out, _ = _run_collector_as_root(tmp_path, home, extra_users=f"echo 'zoe:x:4243:4243::{other}:/bin/sh'\n",
                                    fifo_glob="*/known_hosts?")
    took = time.monotonic() - t0
    lines = out.splitlines()
    assert sum(ln.endswith("\tread timed out") for ln in lines) == 2, [x for x in lines if x.startswith("#X")]
    assert f"#X {home}/.ssh\ttime budget exceeded" in lines
    assert "|" + ak in out and "\n#END " in out
    assert took < 20, took


def test_flood_stops_at_the_account_budget_and_later_accounts_are_complete(tmp_path):
    """check-4 finding 2: 40 .pub files of 1 MB in one account. The collector stops that account at its 4 MiB
    budget ('output budget exceeded'); an account later in passwd is complete and the output stays far below
    the transport's 32 MiB."""
    _need_setpriv_and_timeout()
    home = tmp_path / "flood"
    (home / ".ssh").mkdir(parents=True)
    junk = ("ssh-ed25519 " + "A" * 186 + " flood\n") * 5000        # 1,000,000 bytes, 5000 lines
    for i in range(40):
        (home / ".ssh" / f"f{i:02d}.pub").write_text(junk)
    victim = tmp_path / "victim"
    (victim / ".ssh").mkdir(parents=True)
    ak = _write_key_line(victim / ".ssh" / "authorized_keys", "VICTIMBACKDOOR")
    out, _ = _run_collector_as_root(tmp_path, home, extra_users=f"echo 'zvictim:x:4244:4244::{victim}:/bin/sh'\n")
    assert len(out.encode()) < 6 * 1024 * 1024, len(out)
    assert f"#X {home}/.ssh\toutput budget exceeded" in out.splitlines()
    assert "|" + ak in out and "\n#END " in out
    d = build(records.parse(out))
    assert [a.username for a in d.authorized if "VICTIMBACKDOOR" in a.entry.raw] == ["zvictim"]
