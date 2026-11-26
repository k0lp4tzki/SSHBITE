"""Key blobs of every algorithm (incl. certificates, DSA, RSA-1024) against stored `ssh-keygen -lf` output."""

import re

import pytest

from sshbite.config import StrengthCfg
from sshbite.parse.keys import classify_strength, parse_public_key_line

from .conftest import FIX

ALG = {"ED25519": "ssh-ed25519", "RSA": "ssh-rsa", "DSA": "ssh-dss", "ED25519-SK": "sk-ssh-ed25519@openssh.com",
       "ECDSA-SK": "sk-ecdsa-sha2-nistp256@openssh.com"}


def _expected():
    for line in (FIX / "keys" / "keygen_lf.txt").read_text().splitlines():
        name, out = line.split("\t")
        m = re.match(r"^(\d+) (SHA256:\S+) .*\(([A-Z0-9-]+)\)$", out)
        yield name, int(m.group(1)), m.group(2), m.group(3)


@pytest.mark.parametrize("name,bits,fp,typ", list(_expected()))
def test_matches_ssh_keygen(name, bits, fp, typ):
    k = parse_public_key_line((FIX / "keys" / name).read_text())
    assert k is not None
    assert k.fp == fp
    assert k.bits == bits
    is_cert = typ.endswith("-CERT")
    assert k.info.is_cert == is_cert
    base = typ[:-5] if is_cert else typ
    if base == "ECDSA":
        assert k.alg == f"ecdsa-sha2-nistp{bits}"
    else:
        assert k.alg == ALG[base]


def test_rejects_garbage():
    assert parse_public_key_line("") is None
    assert parse_public_key_line("ssh-ed25519") is None
    assert parse_public_key_line("ssh-ed25519 !!!notbase64") is None
    assert parse_public_key_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA") is None  # truncated
    # algorithm in the line does not match the blob
    line = (FIX / "keys" / "ed25519.pub").read_text().split()
    assert parse_public_key_line(f"ssh-rsa {line[1]}") is None


@pytest.mark.parametrize("alg,bits,cls", [
    ("ssh-ed25519", 256, "good"), ("sk-ssh-ed25519@openssh.com", 256, "good"),
    ("ecdsa-sha2-nistp256", 256, "ok"), ("ssh-rsa", 4096, "ok"), ("ssh-rsa", 3072, "ok"),
    ("ssh-rsa", 2048, "weak"), ("ssh-rsa", 1024, "critical"), ("ssh-dss", 1024, "critical"),
    ("ssh-ed448", 456, "unknown"),
])
def test_strength(alg, bits, cls):
    assert classify_strength(alg, bits, StrengthCfg()) == cls


def test_strength_rules_are_configurable():
    rules = {"good": ["ssh-ed25519"], "ok": ["ssh-rsa>=2048"], "weak": [], "critical": ["ssh-rsa<2048", "ssh-dss"]}
    assert classify_strength("ssh-rsa", 2048, rules) == "ok"
