"""Decides whether an indicator is worth sending to a threat-intel
provider.

Reserved and non-routable values (RFC 2606 names like .invalid/.example,
RFC 5737 documentation IPs, private/loopback ranges) can never appear in a
reputation database. Querying them wastes rate-limited quota and comes back
as a confusing "HTTP 400" the analyst then has to interpret, so they are
short-circuited with an explanation instead.
"""
from __future__ import annotations

import ipaddress

RESERVED_TLDS = {"invalid", "example", "test", "localhost", "local", "internal", "home", "lan"}


def _host_of(value: str) -> str:
    host = value.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].split("?", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):                       # bracketed IPv6
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:                     # host:port
        host = host.split(":", 1)[0]
    return host.strip().rstrip(".").lower()


def _ip_reason(host: str) -> str | None:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    # Documentation ranges are checked first: ipaddress reports RFC 5737
    # blocks as `is_private`, which would otherwise mislabel them.
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"):
        if addr.version == ipaddress.ip_network(net).version and addr in ipaddress.ip_network(net):
            return "RFC 5737 documentation address - reserved for examples, never routed"
    if addr.is_loopback:
        return "loopback address - not present in public reputation data"
    if addr.is_link_local:
        return "link-local address - not present in public reputation data"
    if addr.is_private:
        return "private/internal address - not present in public reputation data"
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return "reserved address range - not present in public reputation data"
    return None


def skip_reason(finding_type: str, value: str) -> str | None:
    """Return why this indicator cannot be queried at all, or None to query.

    Deliberately narrow: only values that providers actually reject. IP
    addresses in reserved ranges are still queried, because VirusTotal and
    AbuseIPDB do answer for them - suppressing those lookups would throw
    away real results. Those get an advisory note instead.
    """
    if finding_type == "hash_partial":
        return "truncated hash - providers need the full digest to match"

    if finding_type in ("domain", "url", "email"):
        host = _host_of(value)
        if host and "." in host and host.rsplit(".", 1)[-1] in RESERVED_TLDS:
            return "reserved/non-routable domain suffix - providers reject this as unqueryable"
        if host and "." not in host:
            return "not a fully-qualified host - nothing to look up"
    return None


def advisory(finding_type: str, value: str) -> str | None:
    """Extra context worth showing next to real provider results - e.g. an
    address that is reserved and so will never have a meaningful
    reputation, even though the lookup itself succeeds."""
    if finding_type in ("ip", "ip_port"):
        return _ip_reason(_host_of(value))
    return None
