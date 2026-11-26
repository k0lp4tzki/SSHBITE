from sshbite.parse import known_hosts as kh

from .conftest import FIX

KEY = " ".join((FIX / "keys" / "ed25519.pub").read_text().split()[:2])


def test_markers_patterns_negation_ports():
    text = (f"@cert-authority *.example.com {KEY}\n@revoked bad.example {KEY}\n"
            f"a,b.example,!c.example,[d.example]:2222,10.0.0.1 {KEY}\n# c\n\n@bogus x {KEY}\nshort\n")
    es = kh.parse(text)
    assert [e.marker for e in es[:3]] == ["cert-authority", "revoked", None]
    assert es[2].patterns == ["a", "b.example", "!c.example", "[d.example]:2222", "10.0.0.1"]
    assert es[3].error and es[4].error
    plain = [p for p in es[2].patterns if kh.is_plain_pattern(p)]
    assert plain == ["a", "b.example", "[d.example]:2222", "10.0.0.1"]
    assert kh.split_host_port("[d.example]:2222") == ("d.example", 2222)
    assert kh.split_host_port("a") == ("a", 22)
    assert kh.entry_matches_host(es[2], ["a"])
    assert not kh.entry_matches_host(es[2], ["c.example", "a"])  # negation wins
    assert kh.entry_matches_host(es[2], ["d.example"], 2222)
    assert not kh.entry_matches_host(es[2], ["d.example"], 22)


def test_hashed_against_ssh_keygen_H():
    plain = kh.parse((FIX / "known_hosts_plain").read_text())
    hashed = kh.parse((FIX / "known_hosts_hashed").read_text())
    assert all(e.hashed for e in hashed) and len(hashed) == len(plain) == 3
    names = ["host1.example.com", "172.30.1.12", "[gw.example.com]:2222"]
    for e, name in zip(hashed, names):
        assert kh.hash_matches(e, name)
        assert not kh.hash_matches(e, name + "x")
    assert kh.hash_matches(hashed[2], kh.hash_candidate("gw.example.com", 2222))
    assert hashed[0].key.fp == plain[0].key.fp


def test_hash_host_roundtrip():
    line = kh.hash_host("oldsrv.corp.example", b"\x01" * 20) + " " + KEY
    e = kh.parse_line(line, 1)
    assert kh.hash_matches(e, "oldsrv.corp.example")
