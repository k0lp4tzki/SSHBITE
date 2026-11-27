"""Collector record parser on real lab output, truncated and garbage input; host fact building."""

import random

from sshbite.parse import records
from sshbite.parse.host import build

from .conftest import FIX


def test_real_root_output_a1():
    c = records.parse((FIX / "collect_a1_root.txt").read_text())
    assert c.complete and c.version == "1" and c.garbage == 0
    assert c.sections == ["META", "HOSTKEYS", "SSHD", "ACCOUNTS", "SHADOW", "USERS", "SYSTEM", "END"]
    d = build(c)
    assert d.hostname == "a1" and "172.30.1.11" in d.ips
    assert {k.alg for k in d.host_keys} == {"ssh-ed25519", "ecdsa-sha2-nistp256"}
    assert d.preferred_host_key().alg == "ssh-ed25519"
    assert d.accounts["root"].uid == 0 and d.accounts["deploy"].login_shell
    assert d.accounts["sshbite"].pw_state == "locked"
    auth = {(a.username, a.entry.key.comment) for a in d.authorized}
    assert ("root", "fleet-deploy") in auth and ("deploy", "ops@jump") in auth
    pk = {p.path: p for p in d.private_keys}["/home/deploy/.ssh/id_rsa"]
    assert pk.encrypted == "no" and pk.mode == 0o644 and pk.bits == 2048 and pk.owner == "deploy"
    kh = [k for k in d.known_hosts if k.username == "deploy"]
    assert [k.entry.hashed for k in kh] == [True, True, False]
    assert [e.entry.host_pattern for e in d.ssh_configs if e.username == "deploy"] == ["a3"]
    assert {e.file for e in d.ssh_configs if e.username == ""} == {"/etc/ssh/ssh_config"}
    assert any(s.source == "sshd-T" for s in d.sshd)


def test_real_unprivileged_output_b5():
    c = records.parse((FIX / "collect_b5_unprivileged.txt").read_text())
    assert c.complete and "SHADOW" not in c.sections
    assert ("/root/.ssh", "unreadable") in c.skipped and ("/home/carol/.ssh", "unreadable") in c.skipped
    d = build(c)
    assert not d.shadow_available and d.accounts["carol"].pw_state == "unknown"
    assert not [s for s in d.sshd if s.source == "sshd-T"]
    assert [s.value for s in d.sshd if s.name == "passwordauthentication"][0] == "no"   # parsed config


def test_audit_key_is_ignored():
    text = (FIX / "collect_a1_root.txt").read_text()
    c = records.parse(text)
    fps = {a.entry.key.fp for a in build(c).authorized}
    some = next(iter(fps))
    assert some not in {a.entry.key.fp for a in build(c, audit_fp=some).authorized}


def test_truncated_output():
    text = (FIX / "collect_a1_root.txt").read_text()
    cut = text[: len(text) // 2]
    c = records.parse(cut, truncated=True)
    assert not c.complete and c.truncated
    build(c)  # must not raise


def test_garbage_does_not_crash():
    rng = random.Random(1)
    base = (FIX / "collect_a1_root.txt").read_text()
    for _ in range(200):
        chars = list(base)
        for _ in range(50):
            i = rng.randrange(len(chars))
            chars[i] = rng.choice(["\t", "\n", "#", "|", "x", "\x00", "#F ", "#K a\tz\t"])
        c = records.parse("".join(chars))
        build(c)
    c = records.parse("#F only\n|line\n#K\n#V\n#X\n#END notanumber\n" + "\x00" * 100 + "\n|" + "y" * 100000)
    assert c.garbage >= 1 and len(max(c.cmds.get("", [""]) + [""], key=len)) <= 16384
    assert records.parse_mode("-rw-r--r--") == 0o644 and records.parse_mode("600") == 0o600
    assert records.parse_mode("garbage") is None


def test_unknown_values_and_skip_reasons_pass_through():
    """Spec 7.4 assumption: #V setpriv and new #X reasons reach Collected unchanged."""
    from sshbite.parse import records

    c = records.parse("#SSHBITE 1 x\n#S META\n#V setpriv\tno\n#S USERS\n#V user\talice\n"
                      "#X /home/alice/.ssh\tnot read: setpriv missing\n"
                      "#X /home/alice/.ssh/authorized_keys2\tunreadable by account\n#END 2\n")
    assert c.value("setpriv") == "no"
    assert c.skipped == [("/home/alice/.ssh", "not read: setpriv missing"),
                         ("/home/alice/.ssh/authorized_keys2", "unreadable by account")]
    assert c.users == ["alice"] and c.garbage == 0
