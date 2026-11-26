"""Optional extra seeds at depth 0 (spec 3.2): hosts file, CIDRs, static Ansible inventories."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .errors import ConfigError

_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


@dataclass
class Seed:
    value: str            # name or address
    port: int
    source: str           # hosts_file | cidr | ansible:<file>
    probe: bool = False   # CIDR addresses are TCP-probed first
    groups: list[str] = field(default_factory=list)


def parse_host_port(token: str, default_port: int) -> tuple[str, int] | None:
    token = token.strip()
    m = re.match(r"^\[([^\]]+)\](?::(\d{1,5}))?$", token)
    if m:
        return m.group(1), int(m.group(2) or default_port)
    if token.count(":") == 1:
        h, p = token.split(":")
        if not p.isdigit() or not (0 < int(p) < 65536):
            return None
        token, port = h, int(p)
    else:
        port = default_port
    if not _HOST_RE.match(token):
        return None
    return token, port


def read_hosts_file(path: str, default_port: int) -> list[Seed]:
    out = []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ConfigError(f"seeds.hosts_file: {path}: {exc.strerror}") from None
    for no, line in enumerate(text.splitlines(), start=1):
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        hp = parse_host_port(s, default_port)
        if hp is None:
            raise ConfigError(f"seeds.hosts_file: {path}:{no}: not 'host' or 'host:port': {s[:80]}")
        out.append(Seed(hp[0], hp[1], "hosts_file"))
    return out


def cidr_addresses(cidrs: list[str]) -> list[str]:
    out = []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        out.extend(str(a) for a in hosts)
    return out


def _ansible_ini(text: str, path: str, default_port: int) -> list[Seed]:
    seeds: dict[str, Seed] = {}
    group = "ungrouped"
    children_section = False
    vars_section = False
    for no, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(";", 1)[0] if raw.lstrip().startswith(";") else raw
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            name = m.group(1)
            children_section = name.endswith(":children")
            vars_section = name.endswith(":vars")
            group = name.split(":", 1)[0]
            continue
        if children_section or vars_section:
            continue
        parts = line.split()
        host = parts[0]
        hvars = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
        if "[" in host and ":" in host and re.search(r"\[\d+:\d+\]", host):
            # range pattern web[01:10].example
            m2 = re.search(r"\[(\d+):(\d+)\]", host)
            a, b = m2.group(1), m2.group(2)
            width = len(a)
            names = [host[:m2.start()] + str(i).zfill(width) + host[m2.end():] for i in range(int(a), int(b) + 1)]
        else:
            names = [host]
        for name in names:
            addr = hvars.get("ansible_host", name)
            port = int(hvars["ansible_port"]) if hvars.get("ansible_port", "").isdigit() else default_port
            hp = parse_host_port(addr, port)
            if hp is None:
                raise ConfigError(f"seeds.ansible_inventories: {path}:{no}: bad host {addr[:80]}")
            s = seeds.setdefault(name, Seed(hp[0], hp[1], f"ansible:{Path(path).name}"))
            if group not in s.groups:
                s.groups.append(group)
    return list(seeds.values())


def _ansible_yaml(data, path: str, default_port: int) -> list[Seed]:
    seeds: dict[str, Seed] = {}

    def walk(name: str, node, depth: int = 0):
        if depth > 20 or not isinstance(node, dict):
            return
        hosts = node.get("hosts") or {}
        if isinstance(hosts, dict):
            for h, hv in hosts.items():
                hv = hv if isinstance(hv, dict) else {}
                addr = str(hv.get("ansible_host", h))
                port = hv.get("ansible_port", default_port)
                port = int(port) if str(port).isdigit() else default_port
                hp = parse_host_port(addr, port)
                if hp is None:
                    raise ConfigError(f"seeds.ansible_inventories: {path}: bad host {addr[:80]}")
                s = seeds.setdefault(str(h), Seed(hp[0], hp[1], f"ansible:{Path(path).name}"))
                if name not in s.groups and name != "all":
                    s.groups.append(name)
        children = node.get("children") or {}
        if isinstance(children, dict):
            for cname, cnode in children.items():
                walk(str(cname), cnode or {}, depth + 1)

    if isinstance(data, dict):
        for gname, gnode in data.items():
            walk(str(gname), gnode or {})
    for s in seeds.values():
        if not s.groups:
            s.groups.append("ungrouped")
    return list(seeds.values())


def read_ansible(path: str, default_port: int) -> list[Seed]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ConfigError(f"seeds.ansible_inventories: {path}: {exc.strerror}") from None
    if path.endswith((".yml", ".yaml")) or text.lstrip().startswith(("all:", "---")):
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigError(f"seeds.ansible_inventories: {path}: not valid YAML: {exc}") from None
        return _ansible_yaml(data, path, default_port)
    return _ansible_ini(text, path, default_port)


def load_seeds(cfg) -> list[Seed]:
    port = cfg.crawl.ssh_port
    seeds: list[Seed] = []
    if cfg.seeds.hosts_file:
        seeds.extend(read_hosts_file(cfg.seeds.hosts_file, port))
    for inv in cfg.seeds.ansible_inventories:
        seeds.extend(read_ansible(inv, port))
    for addr in cidr_addresses(cfg.seeds.cidrs):
        seeds.append(Seed(addr, port, "cidr", probe=True))
    return seeds
