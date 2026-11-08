"""Shared decoding helpers for the non-PowerShell script folders.

Hex/unicode escapes, `unescape("%41")`, `atob("...")` and bare Base64
literals all turn up in .js and .vbs droppers, and the checks around them -
is this really text? is it a compressed stage? - are the same either way.

Decoding only; nothing here executes anything.
"""
from __future__ import annotations

import base64
import gzip
import re
import zlib
from urllib.parse import unquote

from . import PlagMagic

MIN_B64_LEN = 20
_PRINTABLE = set(range(32, 127)) | {9, 10, 13}

_ESCAPE_RE = re.compile(
    r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|([0-7]{1,3}))"
)


def decode_script(raw: bytes) -> str:
    """Text for a submitted file, honouring its byte-order mark.

    PowerShell writes UTF-16LE with a BOM by default, and a UTF-16 script read
    as UTF-8 is a NUL between every character - unreadable to every pass. A
    UTF-16 file without a BOM is recognised by its NULs falling on one side.
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace")
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        codec = "utf-32-le" if raw[0] == 0xFF else "utf-32-be"
        return raw[4:].decode(codec, errors="replace")
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace")
    if len(raw) >= 4 and len(raw) % 2 == 0:
        sample = raw[:4096]
        odd = sample[1::2].count(0) / (len(sample) // 2)
        even = sample[0::2].count(0) / (len(sample) // 2)
        if odd > 0.4 and even < 0.05:
            return raw.decode("utf-16-le", errors="replace")
        if even > 0.4 and odd < 0.05:
            return raw.decode("utf-16-be", errors="replace")
    return raw.decode("utf-8", errors="replace")


def looks_like_text(raw: bytes) -> bool:
    """Would a human read this as text? Guards against 'decoding' a blob that
    merely happens to be valid Base64."""
    if not raw:
        return False
    printable = sum(1 for b in raw if b in _PRINTABLE)
    return printable / len(raw) >= 0.85


# A decompression bomb is a few kilobytes that inflate to gigabytes. Output is
# measured with a bounded probe before the real decompression runs.
MAX_INFLATE_BYTES = 64 * 1024 * 1024


def inflated_size_ok(raw: bytes, wbits: int, cap: int = MAX_INFLATE_BYTES) -> bool:
    """Would decompressing `raw` stay within `cap` bytes? Gzip members are
    walked one by one, since gzip.decompress inflates every one of them."""
    data = raw
    total = 0
    while data:
        d = zlib.decompressobj(wbits)
        try:
            total += len(d.decompress(data, cap + 1 - total))
        except zlib.error:
            return True   # not a valid stream: the real call fails the same way
        if total > cap or (d.unconsumed_tail and not d.eof):
            return False
        data = d.unused_data if wbits > zlib.MAX_WBITS and d.eof else b""
        if data[:2] != b"\x1f\x8b":
            break
    return True


def bounded_decompress(raw: bytes, max_output: int, max_ratio: int | None = None) -> tuple[bytes | None, str]:
    """(output, "") for a gzip, zlib or raw-deflate stream within both bounds;
    (None, reason) for a stream that is not one, or that would exceed them."""
    candidates = [31] if raw[:2] == b"\x1f\x8b" else [zlib.MAX_WBITS, -zlib.MAX_WBITS]
    for wbits in candidates:
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(raw, max_output + 1)
        except zlib.error:
            continue
        if len(out) > max_output or (d.unconsumed_tail and not d.eof):
            return None, f"inflates past {max_output} bytes"
        if not d.eof:
            continue
        if max_ratio and len(out) > max_ratio * max(1, len(raw)):
            return None, f"inflation ratio above {max_ratio}"
        return out, ""
    return None, "not a compressed stream"


def maybe_decompress(raw: bytes) -> bytes:
    """Unwrap a gzip or zlib/deflate stage, leaving anything else alone."""
    if raw[:2] == b"\x1f\x8b":
        if not inflated_size_ok(raw, 31):
            return raw
        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        if not inflated_size_ok(raw, wbits):
            return raw
        try:
            return zlib.decompress(raw, wbits)
        except Exception:
            continue
    return raw


def decode_base64(candidate: str) -> str | None:
    """Decoded text for a Base64 string, or None if it isn't one."""
    candidate = (candidate or "").strip()
    if len(candidate) < MIN_B64_LEN:
        return None
    try:
        raw = maybe_decompress(base64.b64decode(candidate, validate=True))
    except Exception:
        return None
    if not looks_like_text(raw):
        return None
    return raw.decode("utf-8", errors="replace")


def decode_escapes(text: str) -> str:
    """Hex, unicode and octal escapes become the characters they name."""
    def swap(match: re.Match) -> str:
        hex2, hex4, octal = match.groups()
        try:
            code = int(hex2 or hex4, 16) if (hex2 or hex4) else int(octal, 8)
        except (TypeError, ValueError):
            return match.group(0)
        return chr(code) if 0 <= code <= 0x10FFFF else match.group(0)

    return _ESCAPE_RE.sub(swap, text)


_CODE_LIST_RE = re.compile(r"^\s*(?:0x[0-9A-Fa-f]{1,2}|\d{1,3})(?:\s*[,;\s]\s*(?:0x[0-9A-Fa-f]{1,2}|\d{1,3})){3,}\s*$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/\s]+={0,2}$")


def decode_char_codes(value: str) -> str | None:
    """`91,73,78,...` -> the text those code points spell.

    Needs at least four codes: two or three numbers separated by commas are
    far more likely to be a version string or an octet than a payload.
    """
    if not _CODE_LIST_RE.match(value or ""):
        return None
    codes = []
    for token in re.split(r"[,;\s]+", value.strip()):
        if not token:
            continue
        try:
            codes.append(int(token, 16) if token[:2].lower() == "0x" else int(token))
        except ValueError:
            return None
    if not codes or any(not 0 <= c <= 0x10FFFF for c in codes):
        return None
    text = "".join(chr(c) for c in codes)
    return text if looks_like_text(text.encode("utf-8", "replace")) else None


def decode_payload(value: str) -> tuple[str, str] | None:
    """Is this resolved value *itself* still encoded?

    Returns `(how, plaintext)` for a character-code list, a Base64 blob, or
    any single token PlagMagic finds a recipe for, so a variable holding one
    stage of a peel shows what it contains instead of a wall of digits. None
    when it is already plain, or when decoding produces something unreadable.
    """
    value = (value or "").strip()
    if not value or len(value) > 200_000:
        return None

    text = decode_char_codes(value)
    if text and text != value:
        return "character codes", text

    b64_text = None
    if _B64_RE.match(value):
        b64_text = decode_base64(value)
        if b64_text == value:
            b64_text = None
        # Printable is not readable: XOR'd bytes pass the printable bar too.
        if b64_text and PlagMagic.readable(b64_text):
            return "base64", b64_text

    # One token, or a Base64 blob, goes to the recipe search; code with spaces does not.
    if b64_text or not re.search(r"\s", value):
        result = PlagMagic.magic(value)
        if result is not None:
            return result.short_label, result.output.strip()
    return ("base64", b64_text) if b64_text else None


def decode_percent(text: str) -> str | None:
    """`%41%42` -> `AB`, as `unescape`/`decodeURIComponent` would."""
    if "%" not in text:
        return None
    try:
        decoded = unquote(text)
    except Exception:
        return None
    return decoded if decoded != text else None
