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

MIN_B64_LEN = 20
_PRINTABLE = set(range(32, 127)) | {9, 10, 13}

_ESCAPE_RE = re.compile(
    r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|([0-7]{1,3}))"
)


def looks_like_text(raw: bytes) -> bool:
    """Would a human read this as text? Guards against 'decoding' a blob that
    merely happens to be valid Base64."""
    if not raw:
        return False
    printable = sum(1 for b in raw if b in _PRINTABLE)
    return printable / len(raw) >= 0.85


def maybe_decompress(raw: bytes) -> bytes:
    """Unwrap a gzip or zlib/deflate stage, leaving anything else alone."""
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
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

    Returns `(how, plaintext)` for a value that is a character-code list or a
    Base64 blob, so a variable holding one stage of a peel can show what it
    actually contains instead of a wall of digits. None when it is already
    plain, or when decoding produces something unreadable.
    """
    value = (value or "").strip()
    if not value or len(value) > 200_000:
        return None

    text = decode_char_codes(value)
    if text and text != value:
        return "character codes", text

    if _B64_RE.match(value):
        text = decode_base64(value)
        if text and text != value:
            return "base64", text
    return None


def decode_percent(text: str) -> str | None:
    """`%41%42` -> `AB`, as `unescape`/`decodeURIComponent` would."""
    if "%" not in text:
        return None
    try:
        decoded = unquote(text)
    except Exception:
        return None
    return decoded if decoded != text else None
