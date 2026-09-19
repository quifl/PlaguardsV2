"""Regex + signature based IOC extraction for blue-team triage.

Pure pattern matching over text - no network calls, no execution. Everything
found here is a *candidate* for the analyst to triage, not a confirmed
threat.
"""
from __future__ import annotations

import base64
import bisect
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field

from . import PlagEncode
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
# The label repetition is bounded rather than open-ended: every pattern in
# this module runs over attacker-supplied text, and an unbounded `+` over a
# label group turns a long dotted run with no valid TLD ("a.a.a.a..." x N)
# into quadratic backtracking - measured at 8s for 16k labels before the
# bound, linear after. 16 labels is far past any real FQDN.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,16}[a-zA-Z]{2,24}\b"
)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>)\]}]+", re.IGNORECASE)
# Same treatment: the old host part was `[A-Za-z0-9.-]+\.`, whose dot is in
# both halves, so a dotted run with no TLD backtracked over every dot. Each
# label class here excludes the dot, which makes the split unambiguous.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}\b"
)
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

# --- IPv6 -----------------------------------------------------------------
# Matched loosely, then validated with the standard library. A hand-written
# hextet grammar either misses a legal `::` elision or accepts something that
# merely looks like one, and a wrong address here becomes a false indicator
# in an analyst-facing report - so the grammar is delegated to `ipaddress`.
#
# The lookbehind refuses a match glued to a word character or a `]`, which is
# what keeps PowerShell's static-member syntax out: `[Convert]::FromBase64String`
# and `$x::Add` would otherwise offer `::Add` as a perfectly legal address.
# The lookahead demands two colons up front so a bare IPv4 or a clock time
# never even becomes a candidate.
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z:.\]])"
    r"(?=[0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}:)"
    r"[0-9A-Fa-f:]{2,45}"
    r"(?:\.\d{1,3}){0,3}"
    r"(?![0-9A-Za-z:.])"
)
# `[2001:db8::1]:443` - the bracket form is the only unambiguous way to write
# an IPv6 endpoint, since a bare trailing `:443` is just another hextet.
_IPV6_PORT_RE = re.compile(
    r"\[([0-9A-Fa-f:]{2,45}(?:\.\d{1,3}){0,3})\]:(\d{1,5})(?!\d)"
)

# --- Cryptocurrency wallets ----------------------------------------------
# Base58 deliberately omits 0/O/I/l so the alphabet itself is a filter, but
# structure alone is not enough for the short legacy form - see
# `_base58check_ok`, which is what actually keeps precision high.
_BTC_BASE58_RE = re.compile(r"(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])")
# bech32/bech32m: lowercase only, and the charset drops 1/b/i/o.
_BTC_BECH32_RE = re.compile(r"(?<![A-Za-z0-9])bc1[ac-hj-np-z02-9]{11,71}(?![A-Za-z0-9])")
# The `0x` prefix is required. A bare 40-hex run is indistinguishable from a
# SHA-1 digest, and claiming one is a wallet would invent an indicator; with
# the prefix there is no overlap at all, because `_SHA1_RE`'s leading \b
# cannot fall between the `x` and the first hex digit.
_ETH_RE = re.compile(r"(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])")
# Monero: 95 chars standard/subaddress, 106 with an integrated payment id.
_XMR_RE = re.compile(
    r"(?<![A-Za-z0-9])[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}"
    r"(?:[1-9A-HJ-NP-Za-km-z]{11})?(?![A-Za-z0-9])"
)

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: i for i, char in enumerate(_BASE58_ALPHABET)}
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)

# --- Filesystem paths -----------------------------------------------------
# One root alternation shared by the quoted and unquoted forms: a drive
# letter, a UNC host, an expanded %VAR%, or PowerShell's $env: accessor. The
# single-letter drive branch is what stops `HKLM:\SOFTWARE\...` matching,
# since the lookbehind sees the preceding `M`.
_PATH_ROOT = (
    r"(?:[A-Za-z]:\\"
    r"|\\\\[A-Za-z0-9][A-Za-z0-9._-]{0,62}\\"
    r"|%[A-Za-z_][A-Za-z0-9_()]{0,30}%\\"
    r"|\$[Ee][Nn][Vv]:[A-Za-z_][A-Za-z0-9_]{0,30}\\)"
)
_PATH_SEGMENT = r"[^\\/:*?\"<>|\r\n\s]"
# Unquoted: whitespace ends the path. Allowing spaces here would swallow the
# prose after it ("copy to C:\Temp\x.exe then run"), and a path with words
# glued on is a wrong value, not a partial one.
_WINDOWS_PATH_RE = re.compile(
    rf"(?<![A-Za-z0-9._\\]){_PATH_ROOT}"
    rf"(?:{_PATH_SEGMENT}{{1,120}}\\){{0,24}}{_PATH_SEGMENT}{{1,120}}"
)
# Quoted: the quotes delimit it, so "C:\Program Files\..." survives intact.
_QUOTED_PATH_RE = re.compile(
    rf"['\"]({_PATH_ROOT}[^'\"*?<>|\r\n]{{1,240}})['\"]"
)
_PATH_TRAILING_JUNK = ".,;:)]}'\"`"

# --- Named persistence artefacts -----------------------------------------
# The persistence *command* is already a signature rule; this pulls out the
# NAME, which is what an incident responder actually sweeps an estate for.
# Quoted forms are listed first so the quotes are consumed rather than
# becoming part of the name.
_ARTEFACT_NAME = r"(?:\"([^\"\r\n]{1,120})\"|'([^'\r\n]{1,120})'|([^\s'\"\r\n]{1,120}))"
_SCHEDULED_TASK_RE = re.compile(
    rf"(?:/tn[:=\s]|\B-TaskName\b)\s*{_ARTEFACT_NAME}", re.IGNORECASE
)
_SERVICE_NAME_RE = re.compile(
    rf"(?:\bNew-Service\b[^\r\n]{{0,80}}?\B-Name\b|\bsc(?:\.exe)?\s+create)\s*{_ARTEFACT_NAME}",
    re.IGNORECASE,
)

# --- Residual Base64 ------------------------------------------------------
# Long enough that ordinary identifiers, GUIDs and digests cannot reach it.
MIN_RESIDUAL_B64_LEN = 64
# Above this many same-type findings the prefix collapse is skipped - see
# `_drop_prefix_duplicates`.
_COLLAPSE_LIMIT = 400
_B64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{64,}={0,2}(?![A-Za-z0-9+/=])")

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


def _valid_ipv6(candidate: str) -> bool:
    """Is this candidate really an IPv6 address worth reporting?

    Two rejections beyond the grammar, both aimed at text that parses as an
    address by accident:

    * the unspecified address `::` - a batch file's comment marker, so every
      `:: download the file` line would otherwise become an indicator;
    * a lone alphabetic hextet after an elision (`::dead`, `::Add`), which is
      far more likely to be a word than an address. A candidate earns its
      place with a digit somewhere, or with two or more hextets.
    """
    try:
        address = ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    if address.is_unspecified:
        return False
    hextets = [part for part in candidate.split(":") if part]
    return len(hextets) >= 2 or any(char.isdigit() for char in candidate)


def _base58check_ok(value: str) -> bool:
    """Verify the four-byte double-SHA-256 checksum on a legacy/P2SH address.

    Structure alone is weak here: `[13]` plus 25-34 base58 characters is a
    shape a random token can hit. The checksum makes a false positive a
    1-in-4-billion event, which is the difference between an indicator an
    analyst can trust and one they have to re-derive by hand.
    """
    total = 0
    for char in value:
        index = _BASE58_INDEX.get(char)
        if index is None:
            return False
        total = total * 58 + index
    body = total.to_bytes((total.bit_length() + 7) // 8, "big")
    # Leading '1's encode leading zero bytes, which the integer has dropped.
    body = b"\x00" * (len(value) - len(value.lstrip("1"))) + body
    if len(body) != 25:
        return False
    return hashlib.sha256(hashlib.sha256(body[:21]).digest()).digest()[:4] == body[21:]


def _bech32_polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            checksum ^= _BECH32_GENERATOR[i] if (top >> i) & 1 else 0
    return checksum


def _bech32_ok(address: str) -> bool:
    """BIP-173/BIP-350 checksum for a `bc1...` address.

    Both constants are accepted: 1 is bech32 (witness v0) and 0x2bc830a3 is
    bech32m (v1+, i.e. taproot). Rejecting either would silently drop a whole
    class of real wallet.
    """
    hrp, separator, data = address.rpartition("1")
    if not hrp or not separator or len(data) < 6:
        return False
    try:
        values = [_BECH32_CHARSET.index(char) for char in data]
    except ValueError:
        return False
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    return _bech32_polymod(expanded + values) in (1, 0x2BC830A3)


def _artefact_name(match: re.Match) -> str | None:
    """The task/service name out of a `/tn`-style match, or None.

    None covers the cases where reporting anything would be a guess: the
    parser latched onto the next switch instead of a value, or the name is
    still an unresolved expression (`$taskName`, `$(...)`). An unresolved
    name in the report is a fabricated artefact to hunt for, which is worse
    than saying nothing.
    """
    name = next((group for group in match.groups() if group), "").strip()
    if not name or len(name) > 120:
        return None
    if name[0] in "-/":
        return None
    if "$" in name or "`" in name or "(" in name:
        return None
    if not any(char.isalnum() for char in name):
        return None
    return name


# Types whose values are network-reachable and so should be neutralised
# before they end up in a shareable document.
_DEFANGABLE = {"ip", "ip_port", "ipv6_port", "domain", "url", "email"}

# Types whose separator is the colon rather than the dot. Bracketing dots
# does nothing to an IPv6 address, so those need the `[:]` form that
# `_REFANG_RULES` already knows how to undo.
_COLON_DEFANGABLE = {"ip", "ipv6_port"}


def defang(value: str, ioc_type: str | None = None) -> str:
    """Neutralise an indicator so it can't be clicked or copy-pasted into a
    browser straight out of a report: 1.2.3.4 -> 1[.]2[.]3[.]4,
    http:// -> hxxp://, user@host -> user[@]host,
    2001:db8::1 -> 2001[:]db8[:][:]1."""
    if not value:
        return value
    if ioc_type is not None and ioc_type not in _DEFANGABLE:
        return value
    # `ip_port` and `url` are excluded by type rather than by shape: their
    # colons are structural (port separator, scheme) and bracketing those
    # would corrupt the value. With no type given, only a value that really
    # parses as IPv6 takes this branch.
    if value.count(":") >= 2 and (
        ioc_type in _COLON_DEFANGABLE
        or (ioc_type is None and _valid_ipv6(value))
    ):
        return value.replace(":", "[:]").replace(".", "[.]")
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
    taken = _Spans()

    # Longest/most specific patterns first so a URL isn't split into a bare
    # domain, an IP:port isn't reduced to just the IP, and an IPv4-mapped
    # IPv6 address isn't reduced to the embedded v4 half.
    for pattern, kind in ((_URL_RE, "url"), (_EMAIL_RE, "email"),
                          (_IPV6_PORT_RE, "ipv6_port"),
                          (_IP_PORT_RE, "ip_port"),
                          (_IPV6_CANDIDATE_RE, "ipv6"), (_IPV4_RE, "ip"),
                          (_DOMAIN_RE, "domain")):
        for m in pattern.finditer(text):
            value = m.group(0)
            if kind == "domain" and not _valid_domain(value):
                continue
            if kind == "ipv6" and not _valid_ipv6(value):
                continue
            if kind == "ipv6_port" and not _valid_ipv6(m.group(1)):
                continue
            if taken.overlaps(m.start(), m.end()):
                continue
            # Bare IPv6 is reported (and defanged) as the plain `ip` type.
            taken.claim(m.start(), m.end())
            spans.append((m.start(), m.end(),
                          defang(value, "ip" if kind == "ipv6" else kind)))

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


class _Spans:
    """A set of disjoint claimed ranges with an O(log n) overlap test.

    Comparing each new match against every claimed range is quadratic in the
    number of indicators, which on a machine-generated script is the same
    denial of service as a backtracking regex - just in Python rather than in
    the regex engine. Measured on a 1.2MB adversarial document: 84s of the
    89s scan was one such linear scan.
    """

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []

    def overlaps(self, start: int, end: int) -> bool:
        before = bisect.bisect_right(self._starts, start) - 1
        if before >= 0 and start < self._ends[before]:
            return True
        after = bisect.bisect_left(self._starts, start)
        return after < len(self._starts) and end > self._starts[after]

    def claim(self, start: int, end: int) -> None:
        at = bisect.bisect_left(self._starts, start)
        self._starts.insert(at, start)
        self._ends.insert(at, end)


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
    # IPv6 shares the `ip` type so it reaches geolocation, provider lookups
    # and the reserved-range advisory through the paths that already exist.
    if _IPV6_CANDIDATE_RE.fullmatch(value) and _valid_ipv6(value):
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


def _wallet_candidates(text: str) -> list[tuple[str, str, tuple[int, int]]]:
    """Every wallet address in `text` as (value, currency, span).

    BTC forms carry a checksum and are made to prove it; XMR and ETH have no
    checksum reachable from the standard library, so they lean on a length
    and alphabet narrow enough that an accidental match is implausible.
    """
    found: list[tuple[str, str, tuple[int, int]]] = []
    for m in _BTC_BASE58_RE.finditer(text):
        if _base58check_ok(m.group(0)):
            found.append((m.group(0), "Bitcoin", (m.start(), m.end())))
    for m in _BTC_BECH32_RE.finditer(text):
        if _bech32_ok(m.group(0)):
            found.append((m.group(0), "Bitcoin", (m.start(), m.end())))
    for m in _ETH_RE.finditer(text):
        found.append((m.group(0), "Ethereum", (m.start(), m.end())))
    for m in _XMR_RE.finditer(text):
        found.append((m.group(0), "Monero", (m.start(), m.end())))
    return found


def _path_candidates(text: str) -> list[tuple[str, str, tuple[int, int]]]:
    """Every filesystem path in `text` as (value, type, span).

    The quoted form is collected first and its span claimed, so a quoted
    "C:\\Program Files\\App\\x.exe" is not also reported truncated at the
    space by the unquoted pattern.
    """
    found: list[tuple[str, str, tuple[int, int]]] = []
    claimed = _Spans()

    def record(value: str, start: int, end: int) -> None:
        value = value.rstrip(_PATH_TRAILING_JUNK)
        if len(value) < 4 or "\\" not in value.lstrip("\\"):
            return
        found.append((value, "unc_path" if value.startswith("\\\\") else "file_path",
                      (start, end)))

    for m in _QUOTED_PATH_RE.finditer(text):
        claimed.claim(m.start(1), m.end(1))
        record(m.group(1), m.start(1), m.end(1))

    for m in _WINDOWS_PATH_RE.finditer(text):
        if claimed.overlaps(m.start(), m.end()):
            continue
        record(m.group(0), m.start(), m.end())
    return found


def _b64_plaintexts(blob: str) -> list[str]:
    """Every plausible plaintext behind a Base64 run.

    Both codecs are tried and both results kept: a UTF-16LE payload decodes
    "successfully" as UTF-8 too, because the interleaved NUL bytes are legal
    UTF-8, so stopping at the first success would compare the wrong string.

    Used only to decide whether a run was *already* resolved elsewhere in the
    same analysis, never to produce an indicator - a failure here just means
    the blob stays reported as residual, which is the safe direction.
    """
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
    except Exception:
        return []
    out = []
    for codec in ("utf-8", "utf-16-le"):
        try:
            decoded = raw.decode(codec)
        except (UnicodeDecodeError, ValueError):
            continue
        # PlagEncode's own bar for "would a human read this as text", so the
        # report and the decoders agree on what counts as decoded.
        if decoded.strip() and PlagEncode.looks_like_text(decoded.encode("utf-8", "replace")):
            out.append(decoded.strip())
    return out


def _residual_b64_findings(texts: list[str], claimed: set[str]) -> list[Finding]:
    """Base64 runs that made it through the whole pipeline intact.

    A surviving blob is not an indicator in itself - it is a marker of where
    static analysis stopped, which is exactly the thing an analyst needs to
    know before trusting the rest of the report. Only the *deobfuscated* and
    *resolved* text is searched: a blob the pipeline decoded is gone from
    both by construction, so it cannot be reported here.
    """
    found: list[Finding] = []
    seen: set[str] = set()
    haystack = "\n".join(texts)

    for text in texts:
        url_spans = _Spans()
        for m in _URL_RE.finditer(text):
            url_spans.claim(m.start(), m.end())
        for m in _B64_BLOB_RE.finditer(text):
            blob = m.group(0)
            core = blob.rstrip("=")
            if blob in seen or blob in claimed:
                continue
            if len(core) < MIN_RESIDUAL_B64_LEN or len(blob) % 4 != 0:
                continue
            # An all-hex run is a digest, and the hash extractors own it.
            if re.fullmatch(r"[a-fA-F0-9]+", core):
                continue
            # Real Base64 mixes character classes; a single-class run that
            # long is an identifier, a key name or a URL path segment.
            classes = sum((any(c.islower() for c in core), any(c.isupper() for c in core),
                           any(c.isdigit() for c in core)))
            if classes < 2:
                continue
            if url_spans.overlaps(m.start(), m.end()):
                continue
            if any(plain in haystack for plain in _b64_plaintexts(blob)):
                continue  # already decoded elsewhere in this run
            seen.add(blob)
            shown = blob if len(blob) <= 96 else blob[:96] + "..."
            found.append(Finding(
                "base64_blob", shown, _context(text, m.start(), m.end()),
                severity="info", mitre=["T1027.010", "T1140"],
                description=f"A {len(blob)}-character Base64 run survived deobfuscation and "
                            f"could not be decoded statically - static analysis stops here, "
                            f"so treat the rest of the report as incomplete for this branch."
                            + (" Value truncated for display." if len(blob) > 96 else ""),
            ))
    return found


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

        for m in _IPV6_PORT_RE.finditer(text):
            if not _valid_ipv6(m.group(1)) or not 0 < int(m.group(2)) <= 65535:
                continue
            # The endpoint deliberately does NOT reuse `ip_port`: every
            # consumer of that type recovers the host with rsplit(":", 1),
            # which on a bracketed address yields "[2001:db8::1]" and then an
            # "invalid address" row in the geolocation table. The bare address
            # is added alongside so geolocation still gets something it can
            # resolve.
            add(Finding("ipv6_port", m.group(0), _context(text, m.start(), m.end()),
                         severity="low", defanged=was_defanged,
                         description="An IPv6 address with an explicit port - a likely C2 endpoint."))
            add(Finding("ip", m.group(1), _context(text, m.start(), m.end()),
                         defanged=was_defanged))

        for m in _IPV6_CANDIDATE_RE.finditer(text):
            if not _valid_ipv6(m.group(0)):
                continue
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

        for value, currency, span in _wallet_candidates(text):
            add(Finding("crypto_wallet", value, _context(text, *span),
                         severity="high", mitre=["T1657"],
                         description=f"A {currency} wallet address - a ransom or stealer "
                                     f"payout destination, and a pivot across campaigns."))

        for value, kind, span in _path_candidates(text):
            if kind == "unc_path":
                add(Finding("unc_path", value, _context(text, *span),
                             severity="medium", mitre=["T1021.002"],
                             description="A UNC share path - lateral movement or exfiltration "
                                         "to a remote host over SMB."))
            else:
                add(Finding("file_path", value, _context(text, *span),
                             severity="low",
                             description="A filesystem path referenced by the script - a staging, "
                                         "drop or output location worth sweeping for."))

        for m in _SCHEDULED_TASK_RE.finditer(text):
            name = _artefact_name(m)
            if name:
                add(Finding("scheduled_task", name, _context(text, m.start(), m.end()),
                             severity="medium", mitre=["T1053.005"],
                             description="The name of a scheduled task the script creates or "
                                         "touches - hunt for it by name across the estate."))

        for m in _SERVICE_NAME_RE.finditer(text):
            name = _artefact_name(m)
            if name:
                add(Finding("service_name", name, _context(text, m.start(), m.end()),
                             severity="medium", mitre=["T1543.003"],
                             description="The name of a Windows service the script creates - "
                                         "hunt for it by name across the estate."))

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

    # Run once, and only over what came *out* of the pipeline: a blob that was
    # decoded no longer appears there, which is what keeps this from firing on
    # successfully-resolved Base64. Wallet values are excluded because a
    # 95-character Monero address is also a legal Base64 run.
    residual_sources = [t for t in (deobfuscated, resolved) if t]
    wallet_values = {f.value for f in findings.values() if f.type == "crypto_wallet"}
    for blob_finding in _residual_b64_findings(residual_sources, wallet_values):
        add(blob_finding)

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
    collapsible = {"user_agent", "registry_key", "mutex", "file_path", "unc_path"}
    peers: dict[str, list[str]] = {}
    for f in found:
        if f.type in collapsible:
            peers.setdefault(f.type, []).append(f.value)

    keep = []
    for f in found:
        if f.type not in collapsible:
            keep.append(f)
            continue
        same_type = peers[f.type]
        # The containment test is quadratic in the number of same-type
        # findings. Below the cap that is a handful of comparisons; above it,
        # a generated script with thousands of paths would stall the scan, and
        # showing a few redundant prefixes is the cheaper failure.
        if len(same_type) <= _COLLAPSE_LIMIT and any(
            other != f.value and f.value in other for other in same_type
        ):
            continue
        keep.append(f)
    return keep


def _severity_rank(severity: str) -> int:
    return {"high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)
