"""Block / unblock a malicious source IP with an inbound Windows Firewall rule.

Safety rules, enforced here and in the server:
  - only public (globally routable) addresses can be blocked, never private, loopback or multicast ones
  - the IP is parsed with `ipaddress` and re-serialised, so the only characters that reach netsh are
    hex digits, dots and colons; commands run as an argv list, never through a shell string
  - every rule NetScope creates is named RULE_PREFIX + ip, so it only ever lists or deletes its own rules
Only Windows is supported so far.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
import sys

from netscope import privilege
from netscope.logs import log

RULE_PREFIX = "NetScope-block-"
NETSH = ["netsh", "advfirewall", "firewall"]
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class BlockError(Exception):
    """A block/unblock that was refused or failed; the message is safe to show the user."""


def supported() -> bool:
    return sys.platform == "win32"


def rule_name(ip: str) -> str:
    return RULE_PREFIX + ip


def normalize_public_ip(ip: object) -> str:
    """The canonical text of a public IP, or BlockError. This is the gate that protects the user's own network."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        raise BlockError("That is not a valid IP address.") from None
    if not addr.is_global or addr.is_multicast:
        raise BlockError("Only public internet addresses can be blocked.")
    return str(addr)


def _netsh(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([*NETSH, *args], capture_output=True, text=True, timeout=30,
                          creationflags=_NO_WINDOW)


def _netsh_elevated(*args: str) -> None:
    """Run netsh as administrator (a UAC prompt unless we already are one) and wait for it."""
    if privilege.is_admin():
        result = _netsh(*args)
        if result.returncode != 0:
            raise BlockError(result.stdout.strip() or result.stderr.strip() or "netsh failed.")
        return
    # Every argument here is built from a validated IP and fixed words: no spaces, no quotes.
    arg_list = " ".join([*NETSH[1:], *args])
    script = f"Start-Process -FilePath netsh -ArgumentList '{arg_list}' -Verb RunAs -Wait -WindowStyle Hidden"
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, text=True, timeout=180, creationflags=_NO_WINDOW)
    if result.returncode != 0:
        raise BlockError("Administrator permission was not granted, so nothing was blocked.")


def is_blocked(ip: str) -> bool:
    return _netsh("show", "rule", f"name={rule_name(ip)}").returncode == 0


def block(ip: object) -> str:
    """Add the inbound block rule for a public IP. Returns the canonical IP."""
    if not supported():
        raise BlockError("Blocking is only available on Windows for now.")
    ip = normalize_public_ip(ip)
    if is_blocked(ip):
        return ip
    _netsh_elevated("add", "rule", f"name={rule_name(ip)}", "dir=in", "action=block",
                    f"remoteip={ip}", "enable=yes", "profile=any")
    if not is_blocked(ip):
        raise BlockError("The firewall rule was not created.")
    log.info("blocked %s", ip)
    return ip


def unblock(ip: object) -> str:
    """Remove NetScope's block rule for an IP. Returns the canonical IP."""
    if not supported():
        raise BlockError("Blocking is only available on Windows for now.")
    ip = normalize_public_ip(ip)
    if not is_blocked(ip):
        return ip
    _netsh_elevated("delete", "rule", f"name={rule_name(ip)}")
    if is_blocked(ip):
        raise BlockError("The firewall rule was not removed.")
    log.info("unblocked %s", ip)
    return ip


def list_blocked() -> list[str]:
    """IPs that have a NetScope block rule right now (reads the firewall; needs no elevation)."""
    if not supported():
        return []
    try:
        out = _netsh("show", "rule", "name=all", "dir=in").stdout
    except (OSError, subprocess.SubprocessError):
        return []
    ips = []
    for name in re.findall(r"^Rule Name:\s*(.+?)\s*$", out, re.MULTILINE):
        if name.startswith(RULE_PREFIX):
            try:
                ips.append(str(ipaddress.ip_address(name[len(RULE_PREFIX):])))
            except ValueError:
                continue
    return sorted(set(ips))
