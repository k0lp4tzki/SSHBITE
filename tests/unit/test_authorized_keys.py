from sshbite.parse import authorized_keys as ak

from .conftest import FIX

KEY = (FIX / "keys" / "ed25519.pub").read_text().strip()


def test_plain_and_comment():
    e = ak.parse_line(KEY, 1)
    assert e.key is not None and e.options == [] and e.key.comment == "fixture-ed25519"
    assert ak.parse_line("# comment", 2) is None and ak.parse_line("   ", 3) is None


def test_options_with_quotes_and_escapes():
    line = ('from="10.0.0.0/8,!10.0.0.5,host-*.example",command="echo \\"hi, there\\"; logger x",'
            'no-pty,no-port-forwarding,permitopen="db:5432",environment="A=b c",'
            'expiry-time="20991231",principals="ops,dev",restrict ' + KEY)
    e = ak.parse_line(line, 7)
    assert e.error is None and e.key is not None
    assert e.from_patterns == ["10.0.0.0/8", "!10.0.0.5", "host-*.example"]
    assert e.command == 'echo "hi, there"; logger x'
    assert e.has("no-pty") and e.has("no-port-forwarding") and e.restrict
    assert e.opt("permitopen") == "db:5432" and e.opt("environment") == "A=b c"
    assert e.expiry_time == "20991231" and e.principals == "ops,dev"
    assert not e.cert_authority


def test_cert_authority():
    e = ak.parse_line('cert-authority,principals="ops" ' + KEY, 1)
    assert e.cert_authority and e.principals == "ops"


def test_malformed_lines():
    assert ak.parse_line('command="unterminated ' + KEY, 1).error
    assert ak.parse_line("from=unquoted " + KEY, 1).error
    assert ak.parse_line("no-pty", 1).error
    assert ak.parse_line("ssh-ed25519 AAAA", 1).error == "invalid key"
    assert ak.parse_line("x" * 20000, 1).raw.__len__() <= 16 * 1024


def test_from_matcher():
    pats = ["172.30.2.0/24", "!172.30.2.99", "*.corp", "jump?"]
    assert ak.from_matches(pats, [], ["172.30.2.5"])
    assert not ak.from_matches(pats, [], ["172.30.2.99"])
    assert ak.from_matches(pats, ["web.corp"], ["10.9.9.9"])
    assert ak.from_matches(pats, ["jump1"], [])
    assert not ak.from_matches(pats, ["jump12"], ["10.0.0.1"])
    assert not ak.from_matches(["10.0.0.0/8"], ["a3"], ["172.30.1.13"])
    assert ak.from_matches(["172.30.2.5"], [], ["172.30.1.5", "172.30.2.5"])
    # negation alone never allows
    assert not ak.from_matches(["!10.0.0.1"], [], ["10.0.0.2"])


def test_literal_from_targets():
    assert ak.literal_from_targets(["10.0.0.0/8", "!x", "a*", "b?", "host1", "172.30.2.5"]) == ["host1", "172.30.2.5"]
