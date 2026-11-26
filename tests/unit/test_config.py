"""Config loading and validation with all error paths (spec 3.2, 8.1)."""

import os

import pytest
import yaml

from sshbite.config import EXAMPLE_CONFIG, check_files, load_config, parse_config_text, resolve_config_path
from sshbite.errors import ConfigError

from .conftest import FIX

PIN = " ".join((FIX / "keys" / "ed25519.pub").read_text().split()[:2])


def _base(**over):
    d = {"entry": {"host": "jump.example", "host_keys": [PIN]}}
    for k, v in over.items():
        d[k] = v
    return yaml.safe_dump(d)


def test_example_config_has_all_defaults_and_needs_a_real_pin():
    with pytest.raises(ConfigError) as ei:
        parse_config_text(EXAMPLE_CONFIG)
    assert "entry.host_keys[0]: not an OpenSSH public key line" in str(ei.value)
    data = yaml.safe_load(EXAMPLE_CONFIG)
    data["entry"]["host_keys"] = [PIN]
    cfg = parse_config_text(yaml.safe_dump(data))
    assert cfg.limits.concurrency == 20 and cfg.limits.host_timeout == 30 and cfg.crawl.max_depth == 10
    assert cfg.crawl.max_hosts == 1000 and cfg.rules.many_hosts_threshold == 10 and cfg.web.port == 8722
    assert cfg.grouping.tags[0].name == "dmz"


@pytest.mark.parametrize("over,msg", [
    ({"crawl": {"include": ["10.0.0.0/8", "web-*", "not a glob!"]}}, "crawl.include[2]: not a CIDR or glob"),
    ({"crawl": {"exclude": ["10.0.0.0/33"]}}, "crawl.exclude[0]: not a CIDR or glob"),
    ({"bogus": 1}, "bogus: unknown key"),
    ({"crawl": {"max_depth": -1}}, "crawl.max_depth:"),
    ({"hostkeys": {"mode": "strict"}}, "hostkeys: known_hosts_file is required when mode is strict"),
    ({"hostkeys": {"mode": "maybe"}}, "hostkeys.mode:"),
    ({"privilege": {"mode": "su"}}, "privilege.mode:"),
    ({"seeds": {"cidrs": ["10.0.0.0/8"]}}, "seeds.cidrs: 16777216 addresses in total, at most 65536"),
    ({"rules": {"strength": {"weak": ["ssh-rsa>>2048"]}}}, "rules.strength.weak[0]:"),
    ({"limits": {"concurrency": 0}}, "limits.concurrency:"),
])
def test_error_paths_name_their_path(over, msg):
    with pytest.raises(ConfigError) as ei:
        parse_config_text(_base(**over), "/etc/sshbite/sshbite.yaml")
    assert msg in str(ei.value), str(ei.value)


def test_missing_entry_and_bad_yaml():
    with pytest.raises(ConfigError, match="entry: required"):
        parse_config_text("database: /tmp/x.db\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        parse_config_text("entry: [\n")
    with pytest.raises(ConfigError, match="mapping"):
        parse_config_text("- a\n")


def test_path_resolution(tmp_path, monkeypatch):
    monkeypatch.delenv("SSHBITE_CONFIG", raising=False)
    assert resolve_config_path(None) == "/etc/sshbite/sshbite.yaml"
    monkeypatch.setenv("SSHBITE_CONFIG", "/x.yaml")
    assert resolve_config_path(None) == "/x.yaml" and resolve_config_path("/y.yaml") == "/y.yaml"
    p = tmp_path / "c.yaml"
    p.write_text(_base(database="data/s.db", audit={"key_file": "k"}))
    cfg = load_config(str(p))
    assert cfg.database == str(tmp_path / "data" / "s.db") and cfg.audit.key_file == str(tmp_path / "k")
    with pytest.raises(ConfigError, match="config file not found"):
        load_config(str(tmp_path / "missing.yaml"))


def test_file_checks(tmp_path):
    import asyncssh

    key = tmp_path / "audit"
    key.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    os.chmod(key, 0o644)
    p = tmp_path / "c.yaml"
    p.write_text(_base(database=str(tmp_path / "db" / "s.db"), audit={"key_file": str(key)}))
    os.chmod(p, 0o644)
    cfg = load_config(str(p))
    res = check_files(cfg)
    assert any(str(key) in e and "0644" in e and "must be 0600" in e for e in res.errors), res.errors
    assert any("group- or world-readable" in w for w in res.warnings)
    os.chmod(key, 0o600)
    os.chmod(p, 0o600)
    assert check_files(load_config(str(p))).errors == []
    p.write_text(_base(database=str(tmp_path / "s.db"), audit={"key_file": str(key)}, entry={"host": "j"}))
    assert any("entry.host_keys: missing" in e for e in check_files(load_config(str(p))).errors)
    p.write_text(_base(audit={"key_file": str(tmp_path / "nokey")}))
    assert any("file not found" in e for e in check_files(load_config(str(p))).errors)


# ---------------------------------------------------------------- privilege.mode installed (spec 3)

PATH_RULE = ("must be an absolute path of letters, digits, '.', '_', '-' and '/' "
             "(no '.' or '..' segments, at most 200 characters)")


def test_installed_mode_literal_and_default_path():
    cfg = parse_config_text(_base(privilege={"mode": "installed"}))
    assert cfg.privilege.mode == "installed"
    assert cfg.privilege.collector_path == "/usr/local/libexec/sshbite/sshbite-collect"
    assert cfg.privilege.resolve_path == "/usr/local/libexec/sshbite/sshbite-resolve"
    assert cfg.privilege.gate_path == "/usr/local/libexec/sshbite/sshbite-gate"
    assert parse_config_text(_base()).privilege.mode == "sudo"          # the default stays sudo
    with pytest.raises(ConfigError) as ei:
        parse_config_text(_base(privilege={"mode": "root"}), "/etc/sshbite/sshbite.yaml")
    assert str(ei.value) == ("/etc/sshbite/sshbite.yaml: privilege.mode: "
                             "Input should be 'sudo', 'sudo-login', 'none' or 'installed'")


def test_installed_valid_custom_path():
    cfg = parse_config_text(_base(privilege={"mode": "installed", "collector_path": "/opt/sec-tools_1/bin/sb.collect"}))
    assert cfg.privilege.gate_path == "/opt/sec-tools_1/bin/sshbite-gate"
    parse_config_text(_base(privilege={"mode": "installed", "collector_path": "/" + "a" * 199}))   # 200 chars


@pytest.mark.parametrize("path", ["usr/local/libexec/sshbite/sshbite-collect", "/usr/local/../bin/sh",
                                  "/usr/local/libexec/ssh bite/sshbite-collect", "/usr/bin/x;id",
                                  "/" + "a" * 200, "/a/./b"])
def test_installed_invalid_paths(path):
    with pytest.raises(ConfigError) as ei:
        parse_config_text(_base(privilege={"mode": "installed", "collector_path": path}), "/etc/sshbite/sshbite.yaml")
    assert str(ei.value) == f"/etc/sshbite/sshbite.yaml: privilege.collector_path: {PATH_RULE}"


def test_installed_password_scope_is_an_error():
    with pytest.raises(ConfigError) as ei:
        parse_config_text(_base(privilege={"mode": "installed", "password_scope": ["10.0.0.0/8"]}),
                          "/etc/sshbite/sshbite.yaml")
    assert str(ei.value) == ("/etc/sshbite/sshbite.yaml: privilege.password_scope: not used with privilege.mode "
                             "installed (no sudo password is ever sent) - remove it")
    # an empty list is fine, and other modes keep their scope
    assert parse_config_text(_base(privilege={"mode": "installed", "password_scope": []})).privilege.mode == "installed"
    assert parse_config_text(_base(privilege={"mode": "sudo", "password_scope": ["10.0.0.0/8"]}))


def test_installed_collector_path_warning_for_other_modes(tmp_path):
    from click.testing import CliRunner

    from sshbite.cli import main
    from sshbite.config import privilege_warnings

    cfg = parse_config_text(_base(privilege={"mode": "sudo", "collector_path": "/opt/c"}))
    assert privilege_warnings(cfg) == ["privilege.collector_path: ignored unless privilege.mode is installed"]
    assert privilege_warnings(parse_config_text(_base(privilege={"mode": "installed", "collector_path": "/opt/c"}))) == []
    assert privilege_warnings(parse_config_text(_base(privilege={"mode": "sudo"}))) == []
    # in `config validate`: a warning on stderr, not an error
    key = tmp_path / "k"
    import asyncssh
    key.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    key.chmod(0o600)
    p = tmp_path / "c.yaml"
    p.write_text(_base(privilege={"mode": "sudo", "collector_path": "/opt/c"}, audit={"key_file": str(key)},
                       database=str(tmp_path / "x.db")))
    p.chmod(0o600)
    r = CliRunner().invoke(main, ["-c", str(p), "config", "validate"])
    assert r.exit_code == 0, r.output
    assert "warning: privilege.collector_path: ignored unless privilege.mode is installed" in r.stderr
