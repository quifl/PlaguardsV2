"""Deep links into each threat-intel provider's own page for an indicator.

A verdict on its own rarely settles anything - the analyst wants the
provider's detail view: who else reported it, when, and what for. These
build that URL so a result row can be followed straight through.

The links point at the *provider*, never at the indicator itself, and the
value is URL-encoded into the path or query - so following one can never
resolve or fetch the thing under investigation.
"""
from __future__ import annotations

from urllib.parse import quote, quote_plus

# The IOC types PlagGrep produces that map onto a provider lookup at all.
_HASH_TYPES = {"hash", "md5", "sha1", "sha256", "hash_partial"}
_HOST_TYPES = {"domain", "hostname"}


def _kind(ioc_type: str) -> str:
    """Collapse our finding types onto the four a provider distinguishes."""
    if ioc_type in _HASH_TYPES:
        return "hash"
    if ioc_type in _HOST_TYPES:
        return "domain"
    if ioc_type in ("ip", "ip_port"):
        return "ip"
    if ioc_type == "url":
        return "url"
    if ioc_type == "signature":
        return "signature"
    return ""


def _bare_ip(value: str) -> str:
    """`198.51.100.42:4444` -> `198.51.100.42`; providers index the host."""
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def _virustotal(kind: str, value: str) -> str | None:
    if kind == "signature":
        # VirusTotal has no signature page; a search is the closest thing.
        return f"https://www.virustotal.com/gui/search/{quote(value, safe='')}"
    if kind == "ip":
        return f"https://www.virustotal.com/gui/ip-address/{quote(_bare_ip(value), safe='')}"
    if kind == "domain":
        return f"https://www.virustotal.com/gui/domain/{quote(value, safe='')}"
    if kind == "hash":
        return f"https://www.virustotal.com/gui/file/{quote(value, safe='')}"
    if kind == "url":
        return f"https://www.virustotal.com/gui/search/{quote(value, safe='')}"
    return None


def _abusech(kind: str, value: str) -> str | None:
    if kind == "signature":
        return f"https://bazaar.abuse.ch/browse/signature/{quote(value, safe='')}/"
    if kind == "hash":
        return f"https://bazaar.abuse.ch/browse.php?search={quote_plus(value)}"
    if kind == "url":
        return f"https://urlhaus.abuse.ch/browse.php?search={quote_plus(value)}"
    # ThreatFox indexes IPs and domains alongside everything else.
    return f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote_plus(_bare_ip(value))}"


def _otx(kind: str, value: str) -> str | None:
    section = {"ip": "ip", "domain": "domain", "hash": "file", "url": "url"}.get(kind)
    if not section:
        return None
    target = _bare_ip(value) if kind == "ip" else value
    return f"https://otx.alienvault.com/indicator/{section}/{quote(target, safe='')}"


def reference_url(provider_id: str, ioc_type: str, value: str) -> str | None:
    """The provider's page for this indicator, or None if it doesn't have one.

    A provider that only indexes IPs gets no link for a domain, rather than a
    link to a page that will just say "not found".
    """
    if not value:
        return None
    kind = _kind(ioc_type or "")
    if not kind:
        return None

    if provider_id == "virustotal":
        return _virustotal(kind, value)
    if provider_id == "abusech":
        return _abusech(kind, value)
    if provider_id == "otx":
        return _otx(kind, value)
    if provider_id == "abuseipdb" and kind == "ip":
        return f"https://www.abuseipdb.com/check/{quote(_bare_ip(value), safe='')}"
    if provider_id == "shodan" and kind == "ip":
        return f"https://www.shodan.io/host/{quote(_bare_ip(value), safe='')}"
    if provider_id == "greynoise" and kind == "ip":
        return f"https://viz.greynoise.io/ip/{quote(_bare_ip(value), safe='')}"
    if provider_id == "pulsedive" and kind != "signature":
        return f"https://pulsedive.com/indicator/?ioc={quote_plus(_bare_ip(value))}"
    return None
