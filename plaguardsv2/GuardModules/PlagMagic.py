"""CyberChef-style Magic: find the recipe that turns an encoded run into text.

Works like CyberChef's Magic operation: try every decoder whose input pattern
matches, recurse on the output, and keep the best recipe that ends in readable
text. Each step is a real CyberChef operation with its real arguments, so a
recipe found here opens in CyberChef and reproduces the same output.

Decoding only; nothing here executes anything.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import functools
import html
import json
import lzma
import quopri
import re
import zlib
from dataclasses import dataclass
from urllib.parse import quote, unquote_to_bytes

MAX_DEPTH = 4
MAX_NODES = 300
MIN_INPUT_LEN = 16
MAX_INPUT_LEN = 200_000
# Decompression is capped so a small bomb cannot inflate into memory.
MAX_OUTPUT_LEN = 1_000_000
MAX_XOR_LEN = 8_192
# Above this a CyberChef link carries the recipe only, not the input.
MAX_LINK_INPUT = 200_000


@dataclass(frozen=True)
class Step:
    op: str
    args: tuple = ()

    def config(self) -> dict:
        return {"op": self.op, "args": list(self.args)}


@dataclass(frozen=True)
class MagicResult:
    steps: tuple[Step, ...]
    output: str
    score: float

    @property
    def label(self) -> str:
        """CyberChef's operation names, as the recipe is rebuilt there."""
        return " > ".join(_step_label(s) for s in self.steps)

    @property
    def short_label(self) -> str:
        """For "decoded from ..." phrasing: "Hex > Base64 > Gunzip"."""
        return " > ".join(_step_label(s).removeprefix("From ") for s in self.steps)

    def recipe(self) -> list[dict]:
        return [s.config() for s in self.steps]


def _step_label(step: Step) -> str:
    if step.op == "XOR":
        return f"XOR key 0x{step.args[0]['string']}"
    if step.op == "Decode text":
        return "Decode UTF-16LE"
    return step.op


# Byte classification

_PRINTABLE = bytes(range(32, 127)) + b"\t\n\r"
_LETTERS = re.compile(rb"[A-Za-z]")


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return 1 - len(data.translate(None, _PRINTABLE)) / len(data)


def _as_text(data: bytes) -> str | None:
    """The data as a string when a person would read it as text, else None."""
    if not data or b"\x00" in data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _printable_ratio(data) >= 0.95:
        return text
    # UTF-8 letters outside ASCII are text too, as long as the control bytes are rare.
    controls = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r")
    return text if controls / len(text) < 0.02 and text.isprintable() else None


# Cribs: what a decoded stage of a script usually contains.
_CRIB_RE = re.compile(
    r"https?://|\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|\b[a-z0-9-]{2,63}\.(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|invalid|example|local)\b"
    r"|\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|js|hta|scr|lnk|zip)\b"
    r"|\b(?:powershell|invoke-\w+|iex|new-object|start-process|downloadstring|downloadfile"
    r"|webclient|frombase64string|wscript|cscript|createobject|mshta|rundll32|regsvr32"
    r"|certutil|bitsadmin|schtasks|cmd\.exe|function|return|echo|eval|document\.|window\."
    r"|set-content|get-content|add-type|write-host|param|foreach|reg add|curl|wget)\b"
    r"|\$[a-z_][a-z0-9_]*\s*=",
    re.IGNORECASE,
)
_WORD_RE = re.compile(r"[A-Za-z]{2,}")
# Word shapes people write: lower, Capitalised, short ACRONYM, or camelCase with a vowel.
_ORDINARY_WORD_RE = re.compile(
    r"(?=[A-Za-z]*[aeiouyAEIOUY])(?:[a-z]+|[A-Z][a-z]+|[A-Z]{2,5}|[a-z]+(?:[A-Z][a-z]+)+)"
)
_COMMON_LETTERS = set("etaoinshrdlu")


def _cribs(text: str) -> int:
    return len(set(m.group(0).lower() for m in _CRIB_RE.finditer(text)))


def _wordiness(text: str) -> float:
    """Share of the text made of ordinary words, separated by spaces.

    An encoded run is one long token, and decoded garbage has the wrong word
    shapes and letter mix, so both score near zero.
    """
    if not text or " " not in text.strip():
        return 0.0
    words = [w for w in _WORD_RE.findall(text)
             if len(w) <= 14 and _ORDINARY_WORD_RE.fullmatch(w)]
    if len({w.lower() for w in words}) < 3:
        return 0.0
    letters = "".join(words).lower()
    if sum(ch in _COMMON_LETTERS for ch in letters) / len(letters) < 0.55:
        return 0.0
    return len(letters) / max(1, len(text.replace(" ", "")))


def readable(text: str) -> bool:
    """Would an analyst read this as a decoded stage rather than more encoding?"""
    return _cribs(text) >= 1 or _wordiness(text) >= 0.55



def _score(text: str, steps: int) -> float:
    return 3 * min(_cribs(text), 6) + 4 * _wordiness(text) - 0.5 * steps


# Decoders. Each yields (step, output bytes) for every way it applies.

_B64_RE = re.compile(rb"^[A-Za-z0-9+/]+={0,2}$")
_B64URL_RE = re.compile(rb"^[A-Za-z0-9_-]+={0,2}$")
_B32_RE = re.compile(rb"^(?:[A-Z2-7]+|[a-z2-7]+)={0,6}$")
_B58_RE = re.compile(rb"^[1-9A-HJ-NP-Za-km-z]{20,}$")
_B85_RE = re.compile(rb"^(?:<~)?[!-uz]{15,}(?:~>)?$")
_HEX_RE = re.compile(
    rb"^(?:(?:0x|\\x)?[0-9A-Fa-f]{2}(?:[ ,;:\n]|, ?)?)+$"
)
_BIN_RE = re.compile(rb"^[01]{8}(?:[ ,;:]?[01]{8}){3,}$")
_WS_RE = re.compile(rb"\s+")
_DELIMS = ((b" ", "Space"), (b",", "Comma"), (b";", "Semi-colon"),
           (b":", "Colon"), (b"\n", "Line feed"))
_URL_ESC_RE = re.compile(rb"%[0-9A-Fa-f]{2}")
_ENTITY_RE = re.compile(rb"&(?:#\d{2,7}|#x[0-9A-Fa-f]{2,6}|[A-Za-z]{2,8});")
_ESCAPE_RE = re.compile(rb"\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|[0-7]{3})")
_QP_RE = re.compile(rb"=[0-9A-F]{2}")
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _padded(data: bytes, block: int) -> bytes:
    data = data.rstrip(b"=")
    return data + b"=" * (-len(data) % block)


def _from_base64(data: bytes):
    compact = _WS_RE.sub(b"", data)
    if len(compact) < 8:
        return
    if _B64_RE.match(compact):
        try:
            yield (Step("From Base64", ("A-Za-z0-9+/=", True, False)),
                   base64.b64decode(_padded(compact, 4), validate=True))
        except (binascii.Error, ValueError):
            pass
    elif _B64URL_RE.match(compact):
        try:
            yield (Step("From Base64", ("A-Za-z0-9-_", True, False)),
                   base64.urlsafe_b64decode(_padded(compact, 4)))
        except (binascii.Error, ValueError):
            pass


def _from_base32(data: bytes):
    compact = _WS_RE.sub(b"", data)
    if len(compact) < 16 or not _B32_RE.match(compact):
        return
    try:
        yield (Step("From Base32", ("A-Z2-7=", True)),
               base64.b32decode(_padded(compact, 8), casefold=True))
    except (binascii.Error, ValueError):
        pass


def _from_base58(data: bytes):
    if not _B58_RE.match(data) or len(data) > 4096:
        return
    number = 0
    for ch in data:
        number = number * 58 + _B58_ALPHABET.index(ch)
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    lead = len(data) - len(data.lstrip(b"1"))
    yield (Step("From Base58", (_B58_ALPHABET.decode(), True)), b"\x00" * lead + body)


def _from_base85(data: bytes):
    compact = _WS_RE.sub(b"", data)
    # A run inside the Base64 alphabet is left to the Base64 decoder.
    if not _B85_RE.match(compact) or _B64URL_RE.match(compact) or _B64_RE.match(compact):
        return
    try:
        yield (Step("From Base85", ("!-u", True, "z")),
               base64.a85decode(compact, adobe=compact.startswith(b"<~")))
    except (binascii.Error, ValueError):
        pass


def _from_hex(data: bytes):
    stripped = data.strip()
    if len(stripped) < 8 or not _HEX_RE.match(stripped):
        return
    digits = re.sub(rb"0x|\\x|[^0-9A-Fa-f]", b"", stripped)
    if len(digits) % 2:
        return
    yield Step("From Hex", ("Auto",)), bytes.fromhex(digits.decode())


def _delimited(data: bytes, token: bytes):
    """Split on the one delimiter the run uses, or None if it uses several."""
    stripped = data.strip()
    for raw, name in _DELIMS:
        parts = [p.strip() for p in stripped.split(raw)]
        if len(parts) >= 4 and all(re.fullmatch(token, p) for p in parts):
            return name, parts
    return None


def _from_decimal(data: bytes):
    found = _delimited(data, rb"\d{1,7}")
    if not found:
        return
    name, parts = found
    codes = [int(p) for p in parts]
    if all(c <= 255 for c in codes):
        yield Step("From Decimal", (name, False)), bytes(codes)
    elif all(c <= 0x10FFFF for c in codes):
        try:
            text = "".join(chr(c) for c in codes)
            yield Step("From Charcode", (name, 10)), text.encode("utf-8")
        except (ValueError, UnicodeEncodeError):
            pass


def _from_octal(data: bytes):
    # Three digits each, as escaped octal is written. The decimal reading is
    # tried too, and the scorer keeps whichever spells text.
    found = _delimited(data, rb"[0-3][0-7]{2}")
    if not found:
        return
    name, parts = found
    yield Step("From Octal", (name,)), bytes(int(p, 8) for p in parts)


def _from_binary(data: bytes):
    stripped = data.strip()
    if not _BIN_RE.match(stripped):
        return
    bits = re.sub(rb"[^01]", b"", stripped)
    if len(bits) % 8:
        return
    sep = next((name for raw, name in _DELIMS if raw in stripped), "None")
    yield (Step("From Binary", (sep, 8)),
           bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)))


def _url_decode(data: bytes):
    if len(_URL_ESC_RE.findall(data)) >= 3:
        yield Step("URL Decode", (False,)), unquote_to_bytes(data)


def _from_html_entity(data: bytes):
    if len(_ENTITY_RE.findall(data)) >= 3:
        text = data.decode("utf-8", "replace")
        yield Step("From HTML Entity", ()), html.unescape(text).encode("utf-8", "replace")


def _unescape_string(data: bytes):
    if len(_ESCAPE_RE.findall(data)) < 3:
        return

    def swap(m: re.Match) -> bytes:
        tok = m.group(0)[1:]
        if tok[:1] == b"x":
            return bytes([int(tok[1:], 16)])
        if tok[:1] == b"u":
            return chr(int(tok[1:], 16)).encode("utf-8")
        return bytes([int(tok, 8) & 0xFF])

    yield Step("Unescape string", ()), _ESCAPE_RE.sub(swap, data)


def _from_quoted_printable(data: bytes):
    if len(_QP_RE.findall(data)) >= 3 and not _B64_RE.match(_WS_RE.sub(b"", data)):
        yield Step("From Quoted Printable", ()), quopri.decodestring(data)


def _bounded(decompressor, data: bytes) -> bytes | None:
    try:
        out = decompressor.decompress(data, MAX_OUTPUT_LEN)
    except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
        return None
    return out or None


def _decompress(data: bytes):
    if data[:3] == b"\x1f\x8b\x08":
        out = _bounded(zlib.decompressobj(16 + zlib.MAX_WBITS), data)
        if out:
            yield Step("Gunzip", ()), out
    elif data[:1] == b"\x78" and data[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda"):
        out = _bounded(zlib.decompressobj(zlib.MAX_WBITS), data)
        if out:
            yield Step("Zlib Inflate", (0, 0, "Adaptive", False, False)), out
    elif data[:3] == b"BZh":
        out = _bounded(bz2.BZ2Decompressor(), data)
        if out:
            yield Step("Bzip2 Decompress", (False,)), out
    elif data[:3] == b"\x5d\x00\x00":
        out = _bounded(lzma.LZMADecompressor(format=lzma.FORMAT_ALONE), data)
        if out:
            yield Step("LZMA Decompress", ()), out
    elif _printable_ratio(data) < 0.85:
        # Raw deflate has no header, so it is only tried on data that is not already text.
        obj = zlib.decompressobj(-zlib.MAX_WBITS)
        out = _bounded(obj, data)
        if out and obj.eof:
            yield Step("Raw Inflate", (0, 0, "Adaptive", False, False)), out


def _utf16le(data: bytes):
    if len(data) < 8 or len(data) % 2:
        return
    odd = data[1::2]
    if odd.count(0) / len(odd) < 0.6:
        return
    try:
        text = data.decode("utf-16-le")
    except UnicodeDecodeError:
        return
    yield Step("Decode text", ("UTF-16LE (1200)",)), text.encode("utf-8")


_XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]


def _xor_single_byte(data: bytes):
    # Never on the raw input: XOR is tried only on bytes another decoder produced.
    # A small key often leaves text printable, so "already readable" is the stop, not "printable".
    if len(data) < 12 or len(data) > MAX_XOR_LEN or readable(data.decode("latin-1")):
        return
    best = None
    for key in range(1, 256):
        out = data.translate(_XOR_TABLES[key])
        if _printable_ratio(out) < 0.97:
            continue
        text = out.decode("latin-1")
        rank = _cribs(text) * 3 + _wordiness(text)
        if rank and (best is None or rank > best[0]):
            best = (rank, key, out)
    if best:
        _, key, out = best
        text = out.decode("latin-1")
        # 255 keys give chance many tries, so the bar is higher than for a decoder.
        # One crib is enough only beside real words in fully printable output;
        # a bare dotted number turns up in XOR'd binary by chance.
        strong = _cribs(text) >= 2 or _wordiness(text) >= 0.6 or (
            _cribs(text) >= 1 and len(out) >= 16 and _printable_ratio(out) == 1.0
            and len(_ORDINARY_WORD_RE.findall(text)) >= 2)
        if not strong and not _B64_RE.match(out):
            return
        yield Step("XOR", ({"option": "Hex", "string": f"{key:02x}"}, "Standard", False)), out


def _reverse(data: bytes):
    # Reversed Base64 shows itself by leading padding; anything else needs cribs to gain.
    stripped = data.strip()
    if stripped.startswith(b"=") or (
        _letters_only_token(stripped) and _cribs(stripped[::-1].decode("latin-1"))
        > _cribs(stripped.decode("latin-1"))
    ):
        yield Step("Reverse", ("Character",)), stripped[::-1]


def _letters_only_token(data: bytes) -> bool:
    return len(data) >= MIN_INPUT_LEN and not _WS_RE.search(data) and bool(_LETTERS.search(data))


_ROT13 = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_ROT47 = bytes.maketrans(bytes(range(33, 127)), bytes(33 + (b - 33 + 47) % 94 for b in range(33, 127)))


def _rotations(data: bytes):
    """ROT13 and ROT47 change letters, not encodings, so they must reveal cribs to count."""
    if _printable_ratio(data) < 0.95 or not _LETTERS.search(data):
        return
    # Digits survive ROT13, so an IP can be a crib on both sides; only the gain counts.
    before = _cribs(data.decode("latin-1"))
    for step, table in ((Step("ROT13", (True, True, False, 13)), _ROT13),
                        (Step("ROT47", (47,)), _ROT47)):
        out = data.translate(table)
        if _cribs(out.decode("latin-1")) - before >= 2:
            yield step, out


_DECODERS = (
    _decompress, _utf16le, _from_base64, _from_base32, _from_hex, _from_binary,
    _from_decimal, _from_octal, _from_base85, _from_base58, _url_decode,
    _from_html_entity, _unescape_string, _from_quoted_printable, _reverse,
    _rotations, _xor_single_byte,
)
_NO_REPEAT = {"Reverse", "ROT13", "ROT47", "XOR"}


def _expand(data: bytes, steps: tuple[Step, ...]):
    last = steps[-1].op if steps else None
    for decoder in _DECODERS:
        if decoder is _xor_single_byte and not steps:
            continue
        try:
            for step, out in decoder(data):
                if step.op in _NO_REPEAT and step.op == last:
                    continue
                if out and out != data and len(out) <= MAX_OUTPUT_LEN:
                    yield step, out
        except (ValueError, OverflowError, MemoryError, UnicodeError):
            continue


@functools.lru_cache(maxsize=2048)
def magic(value: str) -> MagicResult | None:
    """The best recipe that turns `value` into readable text, or None.

    Breadth-first, so a shorter recipe is found before a longer one, and the
    input itself must not already read as text.
    """
    value = (value or "").strip()
    if not MIN_INPUT_LEN <= len(value) <= MAX_INPUT_LEN:
        return None
    # A separator rule (`-----`, `=====`) fits the Base64url alphabet but encodes nothing.
    if not re.search(r"[A-Za-z0-9]", value):
        return None
    start = value.encode("utf-8", "replace")
    # Readable input can still be encoded (`http%3A%2F%2F...`), so it is searched,
    # but a recipe must clearly beat what the input already says.
    floor = _score(value, 0) + 1 if readable(value) else float("-inf")

    best: MagicResult | None = None
    frontier = [(start, ())]
    seen = {start}
    nodes = 0
    for _depth in range(MAX_DEPTH):
        nxt = []
        for data, steps in frontier:
            for step, out in _expand(data, steps):
                nodes += 1
                if out in seen:
                    continue
                seen.add(out)
                path = steps + (step,)
                text = _as_text(out)
                if text is not None and readable(text) and text.strip() != value:
                    result = MagicResult(path, text, _score(text, len(path)))
                    if result.score > floor and (best is None or result.score > best.score):
                        best = result
                nxt.append((out, path))
                if nodes >= MAX_NODES:
                    return best
        frontier = nxt
        if not frontier:
            break
    return best


# Candidate runs inside a script

_QUOTED_RE = re.compile(r"'([^'\n]{%d,})'|\"([^\"\n]{%d,})\"" % (MIN_INPUT_LEN, MIN_INPUT_LEN))
_BARE_RUN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])")
_LIST_TOKEN_RE = re.compile(r"(?:0x|\\x)?[0-9A-Fa-f]{1,8}[,;:]?")
MAX_CANDIDATES = 200


def candidates(text: str) -> list[str]:
    """Runs in a script worth handing to `magic`: quoted literals, long bare
    tokens in an encoding alphabet, and lines that are nothing but data."""
    found: list[str] = []
    seen: set[str] = set()

    def add(run: str) -> None:
        run = run.strip()
        if len(run) >= MIN_INPUT_LEN and run not in seen and len(found) < MAX_CANDIDATES:
            seen.add(run)
            found.append(run)

    for m in _QUOTED_RE.finditer(text):
        add(m.group(1) or m.group(2))
    for m in _BARE_RUN_RE.finditer(text):
        add(m.group(0))
    # A line that is one token, or a list of numbers, is data rather than code.
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        tokens = stripped.split()
        if len(tokens) == 1 or all(_LIST_TOKEN_RE.fullmatch(t) for t in tokens):
            add(stripped)
    return found


def survey(text: str) -> list[tuple[str, MagicResult | None]]:
    """Every encoded-looking run in `text`, paired with the recipe that opens it.

    A run with no recipe is kept only when it looks encoded, so ordinary
    strings do not crowd out the ones that still need an analyst.
    """
    out = []
    for run in candidates(text):
        result = magic(run)
        if result is not None or _looks_encoded(run):
            out.append((run, result))
    return out


_DIGEST_HEX_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})


def _looks_encoded(run: str) -> bool:
    compact = re.sub(r"\s+", "", run)
    if len(compact) < 40 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return False
    # A digest or a 0x wallet address is an indicator in its own right, not a stage.
    if re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", compact) and (
            len(compact) in _DIGEST_HEX_LENGTHS or compact[:2].lower() == "0x"):
        return False
    classes = sum((any(c.islower() for c in compact), any(c.isupper() for c in compact),
                   any(c.isdigit() for c in compact)))
    return classes >= 2


# CyberChef links

MAGIC_RECIPE = [{"op": "Magic", "args": [MAX_DEPTH, True, False, ""]}]


def chef_fragment(data: str, recipe: list[dict] | None = None) -> str:
    """The `#recipe=...&input=...` fragment CyberChef reads on load.

    A fragment never reaches a server, and CyberChef splits parameters on
    `&` and `=` before decoding, so both parts are fully percent-encoded.
    """
    recipe_json = json.dumps(recipe or MAGIC_RECIPE, separators=(",", ":"))
    fragment = "recipe=" + quote(recipe_json, safe="")
    raw = (data or "").encode("utf-8")
    if raw and len(raw) <= MAX_LINK_INPUT:
        fragment += "&input=" + quote(base64.b64encode(raw).decode(), safe="")
    return fragment
