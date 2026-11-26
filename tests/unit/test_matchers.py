from pathlib import Path

import pytest

from sshbite.config import scope_match
from sshbite.errors import ConfigError
from sshbite.seeds import parse_host_port, read_ansible, read_hosts_file


def test_scope_match():
    assert scope_match(["172.30.1.0/24"], ["x"], ["172.30.1.9"])
    assert not scope_match(["172.30.1.0/24"], ["172.30.1.9"], ["10.0.0.1"])
    assert scope_match(["web-*"], ["WEB-01.corp"], [])
    assert scope_match(["172.30.2.14/32"], [], ["172.30.2.14"])
    assert not scope_match(["172.30.2.14/32"], [], ["172.30.2.15"])
    assert scope_match(["10.*"], [], ["10.1.2.3"])
    assert scope_match(["fd00::/8"], [], ["fd00::1"])


def test_hosts_file(tmp_path: Path):
    p = tmp_path / "hosts"
    p.write_text("# seeds\nweb1\nweb2:2222  # comment\n[fd00::1]:22\n\n")
    s = read_hosts_file(str(p), 22)
    assert [(x.value, x.port) for x in s] == [("web1", 22), ("web2", 2222), ("fd00::1", 22)]
    p.write_text("bad host name\n")
    with pytest.raises(ConfigError, match=":1:"):
        read_hosts_file(str(p), 22)
    assert parse_host_port("h:99999", 22) is None


def test_ansible_ini(tmp_path: Path):
    p = tmp_path / "inv.ini"
    p.write_text("ungrouped1\n[web]\nweb[01:03].corp ansible_port=2222\n[db]\ndb1 ansible_host=10.0.0.5\n"
                 "web01.corp\n[all:vars]\nx=1\n[prod:children]\nweb\n")
    s = {x.value: x for x in read_ansible(str(p), 22)}
    assert set(s) == {"ungrouped1", "web01.corp", "web02.corp", "web03.corp", "10.0.0.5"}
    assert s["web01.corp"].port == 2222 and s["web01.corp"].groups == ["web", "db"]
    assert s["10.0.0.5"].groups == ["db"] and s["ungrouped1"].groups == ["ungrouped"]


def test_ansible_yaml(tmp_path: Path):
    p = tmp_path / "inv.yaml"
    p.write_text("all:\n  hosts:\n    lone:\n  children:\n    web:\n      hosts:\n        w1:\n          ansible_host: 10.1.0.1\n"
                 "    db:\n      children:\n        pg:\n          hosts:\n            p1: {ansible_port: 2200}\n")
    s = {x.value: x for x in read_ansible(str(p), 22)}
    assert s["10.1.0.1"].groups == ["web"] and s["p1"].groups == ["pg"] and s["p1"].port == 2200
    assert s["lone"].groups == ["ungrouped"]
