"""Configuration: loading, schema validation, file checks (spec 3.2, 8.1)."""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .errors import ConfigError

DEFAULT_CONFIG_PATH = "/etc/sshbite/sshbite.yaml"

EXAMPLE_CONFIG = """\
database: /var/lib/sshbite/sshbite.db
entry:
  host: jump01.corp.example     # as reachable from the SSHBITE machine
  port: 22
  host_keys: ["ssh-ed25519 AAAAC3Nza..."]   # required; any match = verified
audit:
  user: sshbite
  key_file: /etc/sshbite/audit_ed25519      # must be 0600
  key_passphrase_env: null
privilege:
  mode: sudo        # sudo: sudo -n /bin/sh -s | sudo-login: sudo -n -i /bin/sh -s | none
  password_scope: []  # CIDRs / hostname globs that may receive the sudo password; empty = every host
crawl:
  max_depth: 10
  max_hosts: 1000
  include: []       # CIDRs / hostname globs; empty = no restriction
  exclude: []       # always wins
  chain_fallback: true
  hash_probe_include_cidrs: true
  hash_probe_max_addresses: 4096
  ssh_port: 22
seeds:              # optional extra seeds, depth 0
  hosts_file: null              # host or host:port per line, '#' comments
  cidrs: []                     # every address probed via the entry; total <= 65536
  ansible_inventories: []       # static INI or YAML
hostkeys:
  mode: tofu                    # tofu | strict
  known_hosts_file: null        # required if strict
limits:
  concurrency: 20
  host_timeout: 30              # whole host: connect + auth + sudo probe + collect
  connect_timeout: 10           # per hop
  entry_connections: 4          # tunnels multiplexed over these
  max_output_mb: 32
rules:
  strength:                     # first match wins
    good:     [ssh-ed25519, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com]
    ok:       [ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, "ssh-rsa>=3072"]
    weak:     ["ssh-rsa>=2048"]
    critical: ["ssh-rsa<2048", ssh-dss]
  many_hosts_threshold: 10
  ignore_audit_key: true
grouping:
  tags: [{name: dmz, match: ["10.1.0.0/16", "web-*"]}]   # first match wins, else "untagged"
web:
  bind: 127.0.0.1
  port: 8722
  session_hours: 8
  secure_cookie: false          # true behind a TLS reverse proxy (always true with --tls-cert)
  trusted_proxies: []           # proxy IPs/CIDRs whose X-Forwarded-For names the client
"""

_GLOB_RE = re.compile(r"^[A-Za-z0-9.*?\[\]!_:-]{1,253}$")
_RULE_RE = re.compile(r"^([A-Za-z0-9@._-]+)(?:(>=|<=|>|<|==)(\d{1,6}))?$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")


def _scope_item(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("not a CIDR or glob")
    value = value.strip()
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError("not a CIDR or glob") from None
        return value
    if not _GLOB_RE.match(value):
        raise ValueError("not a CIDR or glob")
    return value


ScopeItem = Annotated[str, AfterValidator(_scope_item)]


def _pin(value: str) -> str:
    from .parse.keys import parse_public_key_line

    if not isinstance(value, str) or parse_public_key_line(value) is None:
        raise ValueError("not an OpenSSH public key line ('<alg> <base64> [comment]', e.g. from ssh-keyscan)")
    return value.strip()


PinItem = Annotated[str, AfterValidator(_pin)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EntryCfg(_Strict):
    host: str
    port: int = Field(22, ge=1, le=65535)
    host_keys: list[PinItem] = Field(default_factory=list)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        if not _HOSTNAME_RE.match(v):
            raise ValueError("not a host name or address")
        return v



class AuditCfg(_Strict):
    user: str = "sshbite"
    key_file: str = "/etc/sshbite/audit_ed25519"
    key_passphrase_env: str | None = None


class PrivilegeCfg(_Strict):
    mode: Literal["sudo", "sudo-login", "none"] = "sudo"
    # hosts (CIDRs / name globs) that may receive the sudo password; empty = every host
    password_scope: list[ScopeItem] = Field(default_factory=list)

    @field_validator("password_scope", mode="before")
    @classmethod
    def _none_list(cls, v: Any) -> Any:
        return [] if v is None else v


class CrawlCfg(_Strict):
    max_depth: int = Field(10, ge=0, le=100)
    max_hosts: int = Field(1000, ge=1, le=100000)
    include: list[ScopeItem] = Field(default_factory=list)
    exclude: list[ScopeItem] = Field(default_factory=list)
    chain_fallback: bool = True
    hash_probe_include_cidrs: bool = True
    hash_probe_max_addresses: int = Field(4096, ge=0, le=1 << 20)
    ssh_port: int = Field(22, ge=1, le=65535)

    @field_validator("include", "exclude", mode="before")
    @classmethod
    def _none_list(cls, v: Any) -> Any:
        return [] if v is None else v


class SeedsCfg(_Strict):
    hosts_file: str | None = None
    cidrs: list[ScopeItem] = Field(default_factory=list)
    ansible_inventories: list[str] = Field(default_factory=list)

    @field_validator("cidrs")
    @classmethod
    def _cidrs(cls, v: list[str]) -> list[str]:
        total = 0
        for i, c in enumerate(v):
            if "/" not in c:
                raise ValueError(f"item {i} is not a CIDR")
            total += ipaddress.ip_network(c, strict=False).num_addresses
        if total > 65536:
            raise ValueError(f"{total} addresses in total, at most 65536 allowed")
        return v


class HostkeysCfg(_Strict):
    mode: Literal["tofu", "strict"] = "tofu"
    known_hosts_file: str | None = None

    @model_validator(mode="after")
    def _strict(self) -> "HostkeysCfg":
        if self.mode == "strict" and not self.known_hosts_file:
            raise ValueError("known_hosts_file is required when mode is strict")
        return self


class LimitsCfg(_Strict):
    concurrency: int = Field(20, ge=1, le=500)
    host_timeout: float = Field(30, gt=0, le=3600)
    connect_timeout: float = Field(10, gt=0, le=600)
    entry_connections: int = Field(4, ge=1, le=32)
    max_output_mb: int = Field(32, ge=1, le=1024)


def _rule(v: str) -> str:
    if not isinstance(v, str) or not _RULE_RE.match(v.strip()):
        raise ValueError("not an algorithm or '<alg><op><bits>' rule")
    return v.strip()


RuleItem = Annotated[str, AfterValidator(_rule)]


class StrengthCfg(_Strict):
    good: list[RuleItem] = Field(
        default_factory=lambda: ["ssh-ed25519", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"]
    )
    ok: list[RuleItem] = Field(
        default_factory=lambda: ["ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa>=3072"]
    )
    weak: list[RuleItem] = Field(default_factory=lambda: ["ssh-rsa>=2048"])
    critical: list[RuleItem] = Field(default_factory=lambda: ["ssh-rsa<2048", "ssh-dss"])


class RulesCfg(_Strict):
    strength: StrengthCfg = Field(default_factory=StrengthCfg)
    many_hosts_threshold: int = Field(10, ge=2)
    ignore_audit_key: bool = True


class TagCfg(_Strict):
    name: str = Field(min_length=1, max_length=64)
    match: list[ScopeItem]


class GroupingCfg(_Strict):
    tags: list[TagCfg] = Field(default_factory=list)


def _proxy_item(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("not an IP address or CIDR")
    try:
        ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValueError("not an IP address or CIDR") from None
    return value.strip()


ProxyItem = Annotated[str, AfterValidator(_proxy_item)]


class WebCfg(_Strict):
    bind: str = "127.0.0.1"
    port: int = Field(8722, ge=1, le=65535)
    session_hours: float = Field(8, gt=0, le=24 * 30)
    # TLS ends at a reverse proxy: mark the session cookie Secure (always on with --tls-cert)
    secure_cookie: bool = False
    # peers whose X-Forwarded-For (last hop) is used as the client address for the per-IP login limit
    trusted_proxies: list[ProxyItem] = Field(default_factory=list)

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def _none_list(cls, v: Any) -> Any:
        return [] if v is None else v


class Config(_Strict):
    database: str = "/var/lib/sshbite/sshbite.db"
    entry: EntryCfg
    audit: AuditCfg = Field(default_factory=AuditCfg)
    privilege: PrivilegeCfg = Field(default_factory=PrivilegeCfg)
    crawl: CrawlCfg = Field(default_factory=CrawlCfg)
    seeds: SeedsCfg = Field(default_factory=SeedsCfg)
    hostkeys: HostkeysCfg = Field(default_factory=HostkeysCfg)
    limits: LimitsCfg = Field(default_factory=LimitsCfg)
    rules: RulesCfg = Field(default_factory=RulesCfg)
    grouping: GroupingCfg = Field(default_factory=GroupingCfg)
    web: WebCfg = Field(default_factory=WebCfg)

    # set by load_config, not part of the YAML
    path: str | None = Field(default=None, exclude=True)
    raw_sha256: str | None = Field(default=None, exclude=True)

    @model_validator(mode="before")
    @classmethod
    def _no_internal(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for k in ("path", "raw_sha256"):
                if k in data:
                    raise ValueError(f"unknown key '{k}'")
        return data


def format_loc(loc: tuple[Any, ...]) -> str:
    out = ""
    for part in loc:
        if isinstance(part, int):
            out += f"[{part}]"
        elif part in ("function-after", "function-before") or str(part).startswith("function-"):
            continue
        else:
            out += ("." if out else "") + str(part)
    return out or "(root)"


def format_validation_error(err: ValidationError) -> list[str]:
    lines = []
    for e in err.errors():
        loc = format_loc(tuple(e.get("loc", ())))
        msg = e.get("msg", "invalid")
        msg = re.sub(r"^(Value error|Assertion failed), ", "", msg)
        if e.get("type") == "extra_forbidden":
            msg = "unknown key"
        elif e.get("type") == "missing":
            msg = "required"
        lines.append(f"{loc}: {msg}")
    return lines


def resolve_config_path(cli_path: str | None) -> str:
    return cli_path or os.environ.get("SSHBITE_CONFIG") or DEFAULT_CONFIG_PATH


def _abs(base: Path, p: str | None) -> str | None:
    if p is None:
        return None
    pp = Path(os.path.expanduser(p))
    return str(pp if pp.is_absolute() else (base / pp))


def parse_config_text(text: str, path: str = "<string>") -> Config:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark else ""
        raise ConfigError(f"{path}: not valid YAML{where}: {getattr(exc, 'problem', exc)}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: the config must be a YAML mapping")
    try:
        cfg = Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError("\n".join(f"{path}: {line}" for line in format_validation_error(exc))) from None
    base = Path(path).resolve().parent if path != "<string>" else Path.cwd()
    cfg.database = _abs(base, cfg.database) or cfg.database
    cfg.audit.key_file = _abs(base, cfg.audit.key_file) or cfg.audit.key_file
    cfg.seeds.hosts_file = _abs(base, cfg.seeds.hosts_file)
    cfg.seeds.ansible_inventories = [_abs(base, p) or p for p in cfg.seeds.ansible_inventories]
    cfg.hostkeys.known_hosts_file = _abs(base, cfg.hostkeys.known_hosts_file)
    return cfg


def load_config(cli_path: str | None = None) -> Config:
    import hashlib

    path = resolve_config_path(cli_path)
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path} (create one with `sshbite init-config > {path}`)") from None
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror}") from None
    cfg = parse_config_text(raw.decode("utf-8", errors="replace"), path)
    cfg.path = str(Path(path).resolve())
    cfg.raw_sha256 = hashlib.sha256(raw).hexdigest()
    return cfg


@dataclass
class CheckResult:
    errors: list[str]
    warnings: list[str]


def _group_world_readable(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & (stat.S_IRGRP | stat.S_IROTH))
    except OSError:
        return False


def check_audit_key_file(cfg: Config) -> str | None:
    """Return an error message when the audit key is missing or not mode 0600."""
    p = cfg.audit.key_file
    try:
        st = os.stat(p)
    except FileNotFoundError:
        return f"audit.key_file: {p}: file not found"
    except OSError as exc:
        return f"audit.key_file: {p}: {exc.strerror}"
    if not stat.S_ISREG(st.st_mode):
        return f"audit.key_file: {p}: not a regular file"
    mode = stat.S_IMODE(st.st_mode)
    if mode != 0o600:
        return f"audit.key_file: {p}: mode is {mode:04o}, must be 0600 (chmod 600 {p})"
    if not os.access(p, os.R_OK):
        return f"audit.key_file: {p}: not readable by this user"
    return None


CRAWL_UNRESTRICTED_WARNING = (
    "crawl.include is empty: crawl targets and ports are taken from target data (known_hosts, ~/.ssh/config, "
    "from=) without restriction; set crawl.include to the networks and host names you mean to scan")


def scope_warnings(cfg: Config) -> list[str]:
    """Warnings about the crawl scope, printed by `config validate` and `scan` (the default stays unrestricted)."""
    return [] if cfg.crawl.include else [CRAWL_UNRESTRICTED_WARNING]


def check_files(cfg: Config) -> CheckResult:
    """File permission and seed checks of `config validate` (spec 8.1)."""
    errors: list[str] = []
    warnings: list[str] = []
    err = check_audit_key_file(cfg)
    if err:
        errors.append(err)
    else:
        try:
            load_audit_key(cfg)
        except ConfigError as exc:
            errors.append(str(exc))
    if cfg.path and _group_world_readable(cfg.path):
        warnings.append(f"config file {cfg.path} is group- or world-readable (chmod 600 recommended)")
    if os.path.exists(cfg.database) and _group_world_readable(cfg.database):
        warnings.append(f"database {cfg.database} is group- or world-readable (chmod 600 recommended)")
    if not cfg.entry.host_keys:
        errors.append("entry.host_keys: missing - pin the entry host key (scan aborts without it)")
    if cfg.seeds.hosts_file and not os.path.isfile(cfg.seeds.hosts_file):
        errors.append(f"seeds.hosts_file: {cfg.seeds.hosts_file}: file not found")
    for i, inv in enumerate(cfg.seeds.ansible_inventories):
        if not os.path.isfile(inv):
            errors.append(f"seeds.ansible_inventories[{i}]: {inv}: file not found")
    if cfg.hostkeys.mode == "strict" and cfg.hostkeys.known_hosts_file and not os.path.isfile(cfg.hostkeys.known_hosts_file):
        errors.append(f"hostkeys.known_hosts_file: {cfg.hostkeys.known_hosts_file}: file not found")
    if not errors:
        try:
            from .seeds import load_seeds

            load_seeds(cfg)
        except ConfigError as exc:
            errors.append(str(exc))
    return CheckResult(errors, warnings)


def key_passphrase(cfg: Config) -> str | None:
    env = cfg.audit.key_passphrase_env
    if not env:
        return None
    val = os.environ.get(env)
    if val is None:
        raise ConfigError(f"audit.key_passphrase_env: environment variable {env} is not set")
    return val


def load_audit_key(cfg: Config):
    """Load the audit private key (asyncssh SSHKey). Never logs the passphrase."""
    import asyncssh

    try:
        return asyncssh.read_private_key(cfg.audit.key_file, key_passphrase(cfg))
    except (asyncssh.KeyImportError, asyncssh.KeyEncryptionError) as exc:
        raise ConfigError(f"audit.key_file: {cfg.audit.key_file}: cannot load key ({exc})") from None
    except OSError as exc:
        raise ConfigError(f"audit.key_file: {cfg.audit.key_file}: {exc.strerror}") from None


def scope_match(patterns: list[str], names: list[str], ips: list[str]) -> bool:
    """True if any name (fnmatch, case-insensitive) or IP (CIDR) matches any pattern."""
    for pat in patterns:
        if "/" in pat:
            net = ipaddress.ip_network(pat, strict=False)
            for ip in ips:
                try:
                    if ipaddress.ip_address(ip) in net:
                        return True
                except ValueError:
                    continue
        else:
            p = pat.lower()
            for n in list(names) + list(ips):
                if fnmatch.fnmatchcase(n.lower(), p):
                    return True
    return False
