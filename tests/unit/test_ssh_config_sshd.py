from sshbite.parse import ssh_config as sc
from sshbite.parse import sshd

from .conftest import FIX


def test_ssh_config_blocks():
    text = ("User global\nHost a1\n    HostName 172.30.1.11\n    User deploy\n    Port 2222\n"
            "    IdentityFile ~/.ssh/id_a\n    IdentityFile ~/.ssh/id_b\nHost b1 b2\n  user admin\n"
            "Host db\n  HostName=172.30.2.12\n  ProxyJump ops@172.30.1.11:22,[10.0.0.1]:2200\n"
            "Match host x exec \"true\"\n  HostName y\nInclude config.d/*\nHost *\n  ForwardAgent yes\n")
    entries, includes = sc.parse(text, "/home/u/.ssh/config")
    by = {e.host_pattern: e for e in entries}
    assert entries[0].user == "global" and entries[0].line_no == 0 and entries[0].host_pattern == "*"
    a1 = by["a1"]
    assert (a1.hostname, a1.hostname_line, a1.user, a1.port, a1.line_no) == ("172.30.1.11", 3, "deploy", 2222, 2)
    assert a1.identity_files == ["~/.ssh/id_a", "~/.ssh/id_b"]
    assert by["b1 b2"].user == "admin"
    db = by["db"]
    assert db.hostname == "172.30.2.12" and db.proxyjump_line == 12
    assert sc.proxyjump_hops(db.proxyjump) == [("172.30.1.11", 22), ("10.0.0.1", 2200)]
    assert any(e.is_match for e in entries)
    assert includes == [(15, "config.d/*")]
    assert sc.has_wildcard("web-*") and not sc.has_wildcard("a1")


def test_sshd_t_fixture():
    st = sshd.parse_sshd_t((FIX / "sshd_T_a2.txt").read_text().splitlines())
    assert sshd.effective(st, "permitrootlogin") == "yes"
    assert sshd.effective(st, "passwordauthentication") == "no"
    assert sshd.effective(st, "authorizedkeysfile") == ".ssh/authorized_keys .ssh/authorized_keys2"
    assert sshd.effective(st, "pubkeyauthentication") == "yes"


def test_sshd_config_include_and_match():
    files = {
        "/etc/ssh/sshd_config": ["Include /etc/ssh/sshd_config.d/*.conf", "PermitRootLogin no",
                                 "PasswordAuthentication yes", "AllowUsers alice bob@10.0.0.1",
                                 "Match User backup", "  ForceCommand /bin/false", "  PasswordAuthentication no",
                                 "Match Address 10.0.0.0/8", "  PermitRootLogin yes"],
        "/etc/ssh/sshd_config.d/lab.conf": ["PermitRootLogin prohibit-password", "PasswordAuthentication no"],
    }
    st = sshd.parse_config(files)
    # first obtained value wins; the include comes first
    assert sshd.effective(st, "permitrootlogin") == "prohibit-password"
    assert sshd.effective(st, "passwordauthentication") == "no"
    matches = [s for s in st if s.name == "match"]
    assert len(matches) == 2 and "ForceCommand" in matches[0].value and matches[0].line == 5
    assert sshd.effective_multi(st, "allowusers") == ["alice", "bob@10.0.0.1"]
    assert sshd.effective([], "passwordauthentication") == "yes"  # OpenSSH default
