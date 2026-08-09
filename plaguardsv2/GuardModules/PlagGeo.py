"""Where an address actually is, and who runs it.

A reputation verdict says whether an IP is known bad; geolocation says
whether traffic to it makes any sense at all - an admin share reaching a
host two continents away is worth a question even when no provider has ever
heard of it. Modelled on HolmesGeo (github.com/jon-brandy/HolmesGeo), which
enriches extracted addresses with geographic, network and DNS detail.

Two sources, in order of preference:

  1. A local MaxMind GeoLite2 database, if one is configured. Fully offline -
     the address never leaves the machine.
  2. ipinfo.io, if a token is configured. One request per address, cached.

Reverse DNS is done with the standard library and is independent of both.
With nothing configured the enrichment is simply skipped, exactly like a
threat-intel provider with no key.
"""
from __future__ import annotations

import ipaddress
import socket

from . import PlagConfig
from .PlagProviders.base import explain_http, safe_json_request

# What the tabular export and the report show per address.
FIELDS = [
    "ip", "category", "city", "latitude", "longitude", "country",
    "country_code", "continent", "asn", "organization", "network",
    "reverse_dns",
]

_IPINFO_URL = "https://ipinfo.io"
REVERSE_DNS_TIMEOUT = 3.0


_DOCUMENTATION_NETS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")


def category(value: str) -> str:
    """Whether an address is even worth locating."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    # Checked first: ipaddress reports the RFC 5737 documentation blocks as
    # `is_private`, which would otherwise mislabel them as internal.
    for net in _DOCUMENTATION_NETS:
        network = ipaddress.ip_network(net)
        if addr.version == network.version and addr in network:
            return "documentation"
    # Order matters: `is_private` is also true for loopback, link-local and
    # multicast, so the specific cases have to be asked about first.
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    if addr.is_reserved or not addr.is_global:
        return "reserved"
    return "public"


def reverse_dns(value: str) -> str:
    """The PTR record for an address, or "" if it has none."""
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(REVERSE_DNS_TIMEOUT)
        return socket.gethostbyaddr(value)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(previous)


def _from_maxmind(value: str, db_path: str) -> dict | None:
    """Look the address up in a local GeoLite2 database.

    Optional: geoip2 is only imported if a database is actually configured,
    so the package stays installable without it.
    """
    try:
        import geoip2.database
    except ImportError:
        return None

    try:
        with geoip2.database.Reader(db_path) as reader:
            record = reader.city(value)
    except Exception:
        return None

    return {
        "city": record.city.name or "",
        "latitude": record.location.latitude,
        "longitude": record.location.longitude,
        "country": record.country.name or "",
        "country_code": record.country.iso_code or "",
        "continent": record.continent.name or "",
        "asn": "",
        "organization": record.traits.autonomous_system_organization or "",
        "network": str(record.traits.network or ""),
        "source": "MaxMind GeoLite2 (local)",
    }


def _from_ipinfo(value: str, token: str) -> dict | None:
    status, body, err = safe_json_request(
        "GET", f"{_IPINFO_URL}/{value}/json",
        headers={"Authorization": f"Bearer {token}"},
    )
    if err or status != 200 or body is None:
        return {"error": err or explain_http("ipinfo", status)}

    # "AS13335 Cloudflare, Inc." -> ("AS13335", "Cloudflare, Inc.")
    org = body.get("org") or ""
    asn, _, organization = org.partition(" ")
    if not asn.upper().startswith("AS"):
        asn, organization = "", org

    latitude = longitude = None
    if body.get("loc"):
        parts = body["loc"].split(",")
        if len(parts) == 2:
            try:
                latitude, longitude = float(parts[0]), float(parts[1])
            except ValueError:
                pass

    return {
        "city": body.get("city") or "",
        "latitude": latitude,
        "longitude": longitude,
        "country": body.get("country") or "",
        "country_code": body.get("country") or "",
        "continent": "",
        "asn": asn,
        "organization": organization,
        "network": "",
        "source": "ipinfo.io",
    }


def locate(value: str, conn=None) -> dict:
    """Everything we can say about one address.

    Always returns the full field set so callers - the report, the CSV
    export - never have to special-case a missing key.
    """
    result = {name: "" for name in FIELDS}
    result["ip"] = value
    result["category"] = category(value)
    result["source"] = ""
    result["note"] = ""

    if result["category"] == "invalid":
        result["note"] = "not an IP address"
        return result
    if result["category"] != "public":
        # A private or reserved address has no public location to find.
        result["note"] = f"{result['category']} address - no public geolocation"
        return result

    result["reverse_dns"] = reverse_dns(value)

    db_path = PlagConfig.get_geoip_db_path(conn)
    if db_path:
        found = _from_maxmind(value, db_path)
        if found:
            result.update(found)
            return result
        result["note"] = "GeoLite2 database configured but unreadable"

    token = PlagConfig.get_api_key(conn, "ipinfo") if conn is not None else ""
    if token:
        found = _from_ipinfo(value, token)
        if found and "error" in found:
            result["note"] = found["error"]
        elif found:
            result.update(found)
        return result

    if not result["note"]:
        result["note"] = "no geolocation source configured"
    return result


def enrich(findings: list, conn=None) -> dict:
    """Locate every address among the findings, once each.

    Returns `{ip: record}`. Addresses that cannot be located still get a
    record, so the export shows the reason rather than an empty row.
    """
    seen: dict[str, dict] = {}
    for finding in findings:
        if getattr(finding, "type", None) not in ("ip", "ip_port"):
            continue
        value = str(getattr(finding, "value", "")).rsplit(":", 1)[0] \
            if getattr(finding, "type", "") == "ip_port" else str(getattr(finding, "value", ""))
        if value and value not in seen:
            seen[value] = locate(value, conn)
    return seen
