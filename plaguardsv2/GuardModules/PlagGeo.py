"""Where an address actually is, and who runs it.

A reputation verdict says whether an IP is known bad; geolocation says
whether traffic to it makes any sense at all - an admin share reaching a
host two continents away is worth a question even when no provider has ever
heard of it. Modelled on HolmesGeo (github.com/jon-brandy/HolmesGeo), which
enriches extracted addresses with geographic, network and DNS detail.

Two sources, in order of preference:

  1. A local MaxMind GeoLite2 database, if one is configured. Fully offline -
     the address never leaves the machine. City and Country give place and
     network; ASN gives the operator. All three can be pointed at together -
     see `_resolve_databases` - and are merged into one record.
  2. ipinfo.io, if a token is configured. One request per address, cached.

Reverse DNS is done with the standard library and is independent of both.
With nothing configured the enrichment is simply skipped, exactly like a
threat-intel provider with no key.
"""
from __future__ import annotations

import ipaddress
import socket
import tarfile
from pathlib import Path

from . import PlagConfig, PlagGrep
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


_ARCHIVE_SUFFIXES = (".tar.gz", ".tgz")
_KIND_HINTS = ("asn", "city", "country")  # checked in this order; no name matches two


def _classify(filename: str) -> str | None:
    """Which of ASN / City / Country a GeoLite2 file is, from its name."""
    lowered = filename.lower()
    for kind in _KIND_HINTS:
        if kind in lowered:
            return kind
    return None


def _extract_archive(archive: Path, cache_dir: Path) -> Path:
    """Unpack a MaxMind `.tar.gz` download once, reusing it on later calls.

    MaxMind's own downloads arrive as an archive, not a bare `.mmdb`, so this
    lets Settings simply be pointed at the folder those downloads land in.
    """
    stem = archive.name
    for suffix in _ARCHIVE_SUFFIXES:
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    dest = cache_dir / stem
    if dest.is_dir() and any(dest.rglob("*.mmdb")):
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive) as tar:
            tar.extractall(dest, filter="data")
    except Exception:
        pass  # left empty; the caller's glob simply finds nothing
    return dest


def _pick(mmdbs: list[Path], kind: str) -> str | None:
    """The database matching `kind` if the name says so, else whatever's
    there - a folder or archive pointed at for one specific kind normally
    holds exactly one database anyway."""
    for mmdb in mmdbs:
        if _classify(mmdb.name) == kind:
            return str(mmdb)
    return str(mmdbs[0]) if mmdbs else None


def _resolve_one(path: str, kind: str, cache_dir: Path | None = None) -> str | None:
    """The `.mmdb` file for one GeoLite2 database - `kind` is 'city',
    'country' or 'asn', matching the Settings field `path` came from.

    `path` may be a bare `.mmdb` file (used as-is, trusting the field it was
    entered in), MaxMind's `.tar.gz` download, or a folder holding either.
    """
    if not path:
        return None
    root = Path(path)
    if not root.exists():
        return None

    if cache_dir is None:
        cache_dir = Path("data") / "geolite2_cache"

    if root.is_file():
        if root.name.lower().endswith(_ARCHIVE_SUFFIXES):
            return _pick(sorted(_extract_archive(root, cache_dir).rglob("*.mmdb")), kind)
        return str(root)

    mmdbs = sorted(root.rglob("*.mmdb"))
    if not mmdbs:
        for suffix in _ARCHIVE_SUFFIXES:
            for archive in sorted(root.rglob(f"*{suffix}")):
                mmdbs += sorted(_extract_archive(archive, cache_dir).rglob("*.mmdb"))
    return _pick(mmdbs, kind)


def _maxmind_reader(db_path: str, method: str, value: str):
    """Open one database, run one lookup, and always close it again."""
    try:
        import geoip2.database
    except ImportError:
        return None
    try:
        with geoip2.database.Reader(db_path) as reader:
            return getattr(reader, method)(value)
    except Exception:
        return None


def _from_maxmind_city(value: str, db_path: str) -> dict | None:
    record = _maxmind_reader(db_path, "city", value)
    if record is None:
        return None
    return {
        "city": record.city.name or "",
        "latitude": record.location.latitude,
        "longitude": record.location.longitude,
        "country": record.country.name or "",
        "country_code": record.country.iso_code or "",
        "continent": record.continent.name or "",
        "network": str(record.traits.network or ""),
    }


def _from_maxmind_country(value: str, db_path: str) -> dict | None:
    record = _maxmind_reader(db_path, "country", value)
    if record is None:
        return None
    return {
        "country": record.country.name or "",
        "country_code": record.country.iso_code or "",
        "continent": record.continent.name or "",
        "network": str(record.traits.network or ""),
    }


def _from_maxmind_asn(value: str, db_path: str) -> dict | None:
    record = _maxmind_reader(db_path, "asn", value)
    if record is None:
        return None
    number = record.autonomous_system_number
    return {
        "asn": f"AS{number}" if number else "",
        "organization": record.autonomous_system_organization or "",
        "network": str(record.network or ""),
    }


def _from_maxmind(value: str, dbs: dict[str, str]) -> dict | None:
    """Merge whichever of City / Country / ASN are configured.

    City wins over Country when both are present - it is a strict superset -
    but ASN is always consulted on top of either, since it is kept current
    independently and is the only source for the operator name.
    """
    result: dict = {}
    sources = []

    place = None
    if dbs.get("city"):
        place = _from_maxmind_city(value, dbs["city"])
        if place is not None:
            sources.append("City")
    if place is None and dbs.get("country"):
        place = _from_maxmind_country(value, dbs["country"])
        if place is not None:
            sources.append("Country")
    if place:
        result.update(place)

    if dbs.get("asn"):
        asn_info = _from_maxmind_asn(value, dbs["asn"])
        if asn_info is not None:
            sources.append("ASN")
            result["asn"] = asn_info["asn"]
            result["organization"] = asn_info["organization"]
            if not result.get("network"):
                result["network"] = asn_info["network"]

    if not sources:
        return None
    result["source"] = "MaxMind GeoLite2 (local: " + " + ".join(sources) + ")"
    return result


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

    configured = PlagConfig.get_geoip_db_paths(conn)
    if any(configured.values()):
        dbs = {
            kind: _resolve_one(path, kind)
            for kind, path in configured.items() if path
        }
        dbs = {kind: db for kind, db in dbs.items() if db}
        found = _from_maxmind(value, dbs) if dbs else None
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


def describe(record: dict | None) -> list[dict]:
    """A `locate()` record as label/value rows for display - the PDF report
    and the Quick IOC Lookup page both turn one of these into the same
    layout, so the formatting lives here rather than in either caller.

    Only the fields that actually came back are included, in a fixed
    reading order. A record with nothing locatable (private, reserved, no
    source configured) collapses to a single row explaining why.
    """
    if not record:
        return []
    if record.get("note"):
        return [{"label": "Note", "value": record["note"]}]

    rows = []
    if record.get("city"):
        rows.append({"label": "City", "value": record["city"]})
    if record.get("country"):
        code = f" ({record['country_code']})" if record.get("country_code") else ""
        rows.append({"label": "Country", "value": record["country"] + code})
    if record.get("continent"):
        rows.append({"label": "Continent", "value": record["continent"]})
    if record.get("latitude") is not None and record.get("longitude") is not None:
        rows.append({"label": "Coordinates",
                     "value": f"{record['latitude']}, {record['longitude']}"})
    if record.get("organization"):
        asn = f" ({record['asn']})" if record.get("asn") else ""
        rows.append({"label": "Operator", "value": record["organization"] + asn})
    elif record.get("asn"):
        rows.append({"label": "ASN", "value": record["asn"]})
    if record.get("network"):
        rows.append({"label": "Network", "value": PlagGrep.defang_text(record["network"])})
    if record.get("reverse_dns"):
        rows.append({"label": "Reverse DNS", "value": PlagGrep.defang_text(record["reverse_dns"])})
    if record.get("source"):
        rows.append({"label": "Source", "value": record["source"]})
    return rows
