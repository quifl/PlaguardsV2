"""Regex + signature based IOC extraction for blue-team triage.

Pure pattern matching over text - no network calls, no execution. Everything
found here is a *candidate* for the analyst to triage, not a confirmed
threat.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .PlagRules import SIGNATURES

COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "us", "uk", "de", "fr",
    "ru", "cn", "jp", "kr", "in", "br", "au", "ca", "nl", "se", "no", "fi",
    "dk", "pl", "es", "it", "ch", "at", "be", "cz", "gr", "pt", "ro", "hu",
    "tr", "ua", "za", "mx", "ar", "cl", "id", "my", "sg", "ph", "vn", "th",
    "nz", "ie", "il", "sa", "ae", "eg", "ng", "ke", "pk", "bd", "xyz", "top",
    "club", "online", "site", "shop", "app", "dev", "cloud", "icu", "vip",
    "pw", "tk", "ml", "ga", "cf", "gq", "cc", "tv", "me", "link", "live",
    "world", "win", "name", "mobi", "asia", "gov", "edu",
    "mil", "int", "store", "tech", "space", "website", "fun", "host",
    "press", "email", "download", "stream", "party", "science", "work",
    "monster", "rest", "sbs", "lol",
    # RFC 2606 / RFC 6761 reserved names. They never resolve, so they show up
    # constantly in safe samples and write-ups - worth surfacing rather than
    # silently dropping.
    "invalid", "example", "test", "localhost", "local", "internal",
}

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>)\]}]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

# An IP with an explicit port is more actionable than the bare IP, so it is
# surfaced as its own finding type.
_IP_PORT_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)):(\d{1,5})\b"
)
# Either a full browser-style UA string, or a bare product token such as
# "EVILBOT/1.0". The lookbehind keeps it from matching version fragments
# inside a URL path.
_USER_AGENT_RE = re.compile(
    # Browser-style UA. Stops at a quote/newline/pipe/semicolon, and also
    # before the next "KEY=" field so it doesn't swallow the rest of a
    # summary line such as "UA=... MUTEX=... PORT=...".
    r"Mozilla/\d\.\d(?:(?!\s+[A-Za-z][A-Za-z0-9_]*=)[^\"'\n|;]){0,200}"
    # Or a bare product token like "EVILBOT/1.0". The lookbehind keeps it
    # from matching a version fragment inside a URL path.
    r"|(?<![\w/.])[A-Za-z][A-Za-z0-9._-]{2,40}/\d+(?:\.\d+)+"
)
_REGISTRY_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)[\\/][^\s\"'\n,;)]{3,200}"
)
_MUTEX_RE = re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_.\-{}]{3,100}")
# A truncated hash (a prefix pasted into a rule or note) is still worth
# flagging - it just can't be looked up directly.
_HASH_PARTIAL_RE = re.compile(r"\b[a-fA-F0-9]{16,31}\b|\b[a-fA-F0-9]{33,39}\b|\b[a-fA-F0-9]{41,63}\b")

_REFANG_RULES = [
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.IGNORECASE), "@"),
]

_COMPILED_SIGNATURES = [
    {**s, "regex": re.compile(s["pattern"], re.IGNORECASE)} for s in SIGNATURES
]


@dataclass
class Finding:
    type: str
    value: str
    context: str = ""
    mitre: list[str] = field(default_factory=list)
    severity: str = "info"
    description: str = ""
    defanged: bool = False
    intel: dict = field(default_factory=dict)


def refang(text: str) -> str:
    for pattern, repl in _REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


# Types whose values are network-reachable and so should be neutralised
# before they end up in a shareable document.
_DEFANGABLE = {"ip", "ip_port", "domain", "url", "email"}


def defang(value: str, ioc_type: str | None = None) -> str:
    """Neutralise an indicator so it can't be clicked or copy-pasted into a
    browser straight out of a report: 1.2.3.4 -> 1[.]2[.]3[.]4,
    http:// -> hxxp://, user@host -> user[@]host."""
    if not value:
        return value
    if ioc_type is not None and ioc_type not in _DEFANGABLE:
        return value
    out = re.sub(r"^http(s?)(?=://)", r"hxxp\1", value, flags=re.IGNORECASE)
    out = out.replace(".", "[.]")
    out = out.replace("@", "[@]")
    return out


def defang_text(text: str) -> str:
    """Defang only the indicator spans inside a block of free text, leaving
    ordinary prose untouched. Used for resolved variable values, which are
    usually whole sentences with IOCs embedded in them."""
    if not text:
        return text

    spans: list[tuple[int, int, str]] = []
    taken: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < e and end > s for s, e in taken)

    # Longest/most specific patterns first so a URL isn't split into a bare
    # domain, and an IP:port isn't reduced to just the IP.
    for pattern, kind in ((_URL_RE, "url"), (_EMAIL_RE, "email"),
                          (_IP_PORT_RE, "ip_port"), (_IPV4_RE, "ip"),
                          (_DOMAIN_RE, "domain")):
        for m in pattern.finditer(text):
            value = m.group(0)
            if kind == "domain" and not _valid_domain(value):
                continue
            if overlaps(m.start(), m.end()):
                continue
            taken.append((m.start(), m.end()))
            spans.append((m.start(), m.end(), defang(value, kind)))

    if not spans:
        return text

    out = []
    cursor = 0
    for start, end, replacement in sorted(spans):
        out.append(text[cursor:start])
        out.append(replacement)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def _context(text: str, start: int, end: int, radius: int = 40) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = text[lo:hi].replace("\n", " ").strip()
    return snippet


def _valid_domain(match: str) -> bool:
    tld = match.rsplit(".", 1)[-1].lower()
    return tld in COMMON_TLDS


def classify_value(value: str) -> str | None:
    """Classify a single, standalone IOC value (for the Quick IOC Lookup
    tool) - full-match only, no signature scanning."""
    value = refang((value or "").strip())
    if not value:
        return None
    if _IPV4_RE.fullmatch(value):
        return "ip"
    if _URL_RE.fullmatch(value):
        return "url"
    if _SHA256_RE.fullmatch(value):
        return "hash_sha256"
    if _SHA1_RE.fullmatch(value):
        return "hash_sha1"
    if _MD5_RE.fullmatch(value):
        return "hash_md5"
    if _DOMAIN_RE.fullmatch(value) and _valid_domain(value):
        return "domain"
    return None


# What the lookup form offers, and the finding type each maps onto. "hash"
# resolves to a specific digest by length; "signature" is a malware family
# name (AgentTesla, Formbook, ...) rather than an indicator that can be
# recognised by shape, which is exactly why it needs choosing by hand.
LOOKUP_TYPES = [
    ("auto", "Detect automatically"),
    ("ip", "IP address"),
    ("domain", "Domain"),
    ("url", "URL"),
    ("hash", "File hash (MD5 / SHA-1 / SHA-256)"),
    ("signature", "Malware signature / family"),
]

_HASH_BY_LENGTH = {32: "hash_md5", 40: "hash_sha1", 64: "hash_sha256"}


def resolve_lookup_type(value: str, requested: str = "auto") -> tuple[str | None, str]:
    """Work out which finding type to look a value up as.

    Returns `(finding_type, note)`. `note` is non-empty when the request could
    not be honoured, so the caller can say why rather than silently checking
    something else.
    """
    cleaned = refang((value or "").strip())
    if not cleaned:
        return None, "Enter a value to look up."

    if requested in ("", "auto"):
        detected = classify_value(cleaned)
        if detected:
            return detected, ""
        return None, ("That doesn't look like an IP, domain, URL or hash. "
                      "Pick a type from the list if you meant a malware signature.")

    if requested == "signature":
        return "signature", ""

    if requested == "hash":
        digest = _HASH_BY_LENGTH.get(len(cleaned))
        if digest and cleaned.isalnum():
            return digest, ""
        return None, ("A hash has to be 32, 40 or 64 hex characters "
                      "(MD5, SHA-1 or SHA-256).")

    if requested in ("ip", "domain", "url"):
        detected = classify_value(cleaned)
        if detected == requested:
            return requested, ""
        # Honour the explicit choice, but say the value doesn't look like one.
        return requested, f"This doesn't look like a {requested}; checking it as one anyway."

    return None, "Unknown lookup type."


def scan(original: str, deobfuscated: str, resolved: str = "") -> list[Finding]:
    """Scan the original and deobfuscated text, plus (optionally) the block
    of statically resolved variable values produced by PlagTrace - that is
    where IOCs assembled from concatenation/encoding finally become
    visible."""
    findings: dict[tuple[str, str], Finding] = {}

    def add(f: Finding):
        key = (f.type, f.value.lower())
        if key not in findings:
            findings[key] = f

    # Resolved values first: the same indicator found there and in the raw
    # text is kept from there, where it is already whole.
    sources = [deobfuscated, original]
    if resolved:
        sources.insert(0, resolved)

    for raw_text in sources:
        text = refang(raw_text)
        was_defanged = text != raw_text

        for m in _IP_PORT_RE.finditer(text):
            add(Finding("ip_port", m.group(0), _context(text, m.start(), m.end()),
                         severity="low", defanged=was_defanged,
                         description="An IP address with an explicit port - a likely C2 endpoint."))

        for m in _IPV4_RE.finditer(text):
            add(Finding("ip", m.group(0), _context(text, m.start(), m.end()),
                         defanged=was_defanged))

        for m in _USER_AGENT_RE.finditer(text):
            add(Finding("user_agent", m.group(0).strip(), _context(text, m.start(), m.end()),
                         severity="low",
                         description="A hardcoded User-Agent string, often used to fingerprint the implant's traffic."))

        for m in _REGISTRY_RE.finditer(text):
            add(Finding("registry_key", m.group(0), _context(text, m.start(), m.end()),
                         severity="medium", mitre=["T1547.001"],
                         description="A registry path referenced by the script - Run keys are a common persistence point."))

        for m in _MUTEX_RE.finditer(text):
            add(Finding("mutex", m.group(0), _context(text, m.start(), m.end()),
                         severity="low", mitre=["T1027"],
                         description="A named mutex/kernel object, frequently used as an infection marker."))

        for m in _URL_RE.finditer(text):
            add(Finding("url", m.group(0).rstrip(".,;)"), _context(text, m.start(), m.end()),
                         defanged=was_defanged))

        for m in _DOMAIN_RE.finditer(text):
            val = m.group(0)
            if _IPV4_RE.fullmatch(val):
                continue
            if not _valid_domain(val):
                continue
            add(Finding("domain", val, _context(text, m.start(), m.end()), defanged=was_defanged))

        for m in _EMAIL_RE.finditer(text):
            add(Finding("email", m.group(0), _context(text, m.start(), m.end()), defanged=was_defanged))

        for m in _SHA256_RE.finditer(text):
            add(Finding("hash_sha256", m.group(0), _context(text, m.start(), m.end())))
        for m in _SHA1_RE.finditer(text):
            if _SHA256_RE.match(text, m.start()):
                continue
            add(Finding("hash_sha1", m.group(0), _context(text, m.start(), m.end())))
        for m in _MD5_RE.finditer(text):
            if _SHA1_RE.match(text, m.start()) or _SHA256_RE.match(text, m.start()):
                continue
            add(Finding("hash_md5", m.group(0), _context(text, m.start(), m.end())))

        for m in _HASH_PARTIAL_RE.finditer(text):
            add(Finding("hash_partial", m.group(0), _context(text, m.start(), m.end()),
                         severity="low",
                         description="A truncated hash prefix - not directly resolvable against "
                                     "threat-intel sources, but useful for correlation."))

        for sig in _COMPILED_SIGNATURES:
            for m in sig["regex"].finditer(raw_text):
                add(Finding(
                    type="signature",
                    value=sig["name"],
                    context=_context(raw_text, m.start(), m.end()),
                    mitre=sig["mitre"],
                    severity=sig["severity"],
                    description=sig["description"],
                ))

    return sorted(
        _drop_prefix_duplicates(list(findings.values())),
        key=lambda f: (_severity_rank(f.severity), f.type, f.value.lower()),
        reverse=True,
    )


def _drop_prefix_duplicates(found: list[Finding]) -> list[Finding]:
    """A partially-resolved value and its fully-resolved counterpart both
    match - e.g. `"EVIL"+"BOT/1.0"` yields a stray `BOT/1.0` alongside the
    folded `Mozilla/5.0 (Windows NT 10.0) EVILBOT/1.0`. Drop any value that
    is contained within another finding of the same type, so the analyst
    sees the complete indicator once."""
    collapsible = {"user_agent", "registry_key", "mutex"}
    keep = []
    for f in found:
        if f.type not in collapsible:
            keep.append(f)
            continue
        superseded = any(
            other is not f
            and other.type == f.type
            and other.value != f.value
            and f.value in other.value
            for other in found
        )
        if not superseded:
            keep.append(f)
    return keep


def _severity_rank(severity: str) -> int:
    return {"high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)
