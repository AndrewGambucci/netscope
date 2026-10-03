import subprocess

import pytest

from netscope import firewall


@pytest.mark.parametrize("ip", ["10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1",
                                "::1", "fe80::1", "0.0.0.0", "not-an-ip", "", "8.8.8.8; calc", None])
def test_non_public_or_invalid_ips_are_refused(ip):
    with pytest.raises(firewall.BlockError):
        firewall.normalize_public_ip(ip)


def test_public_ip_is_normalised():
    assert firewall.normalize_public_ip("185.60.218.35") == "185.60.218.35"
    assert firewall.normalize_public_ip("2606:4700:4700:0:0:0:0:1111") == "2606:4700:4700::1111"


def test_rule_name_uses_prefix():
    assert firewall.rule_name("1.2.3.4") == "NetScope-block-1.2.3.4"


@pytest.fixture
def fake_netsh(monkeypatch):
    rules, calls = set(), []
    monkeypatch.setattr(firewall, "supported", lambda: True)

    def netsh(*args):
        calls.append(args)
        if args[0] == "show" and args[1] == "rule" and args[2].startswith("name=all"):
            out = "".join(f"Rule Name: {n}\n----\n" for n in sorted(rules))
            return subprocess.CompletedProcess(args, 0, out, "")
        if args[0] == "show":
            return subprocess.CompletedProcess(args, 0 if args[2][5:] in rules else 1, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def elevated(*args):
        calls.append(("elevated", *args))
        name = next(a for a in args if a.startswith("name="))[5:]
        (rules.add if args[0] == "add" else rules.discard)(name)

    monkeypatch.setattr(firewall, "_netsh", netsh)
    monkeypatch.setattr(firewall, "_netsh_elevated", elevated)
    return rules, calls


def test_block_adds_inbound_block_rule_for_that_ip(fake_netsh):
    rules, calls = fake_netsh
    assert firewall.block("185.60.218.35") == "185.60.218.35"
    assert "NetScope-block-185.60.218.35" in rules
    added = next(c for c in calls if c[0] == "elevated")
    assert {"dir=in", "action=block", "remoteip=185.60.218.35"} <= set(added)


def test_block_twice_does_not_add_twice(fake_netsh):
    _, calls = fake_netsh
    firewall.block("185.60.218.35")
    firewall.block("185.60.218.35")
    assert sum(c[0] == "elevated" for c in calls) == 1


def test_block_refuses_private_ip_without_touching_firewall(fake_netsh):
    _, calls = fake_netsh
    with pytest.raises(firewall.BlockError):
        firewall.block("192.168.1.10")
    assert calls == []


def test_unblock_and_list_only_cover_netscope_rules(fake_netsh):
    rules, _ = fake_netsh
    rules.add("Some other rule")
    firewall.block("185.60.218.35")
    firewall.block("45.9.20.1")
    assert firewall.list_blocked() == ["185.60.218.35", "45.9.20.1"]
    firewall.unblock("185.60.218.35")
    assert firewall.list_blocked() == ["45.9.20.1"]
    assert "Some other rule" in rules


def test_unsupported_platform_refuses(monkeypatch):
    monkeypatch.setattr(firewall, "supported", lambda: False)
    with pytest.raises(firewall.BlockError):
        firewall.block("185.60.218.35")
    assert firewall.list_blocked() == []
