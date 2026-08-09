"""Recovers the payload from a byte-array loader.

The shape is standard: a Base64 blob decoded to bytes, XOR-ed against a short
repeating key in a `for` loop, then handed to a decompression stream and read
back as text. No single expression resolves it - the work happens across four
statements and a loop - so it needs recognising as a whole.

Everything is arithmetic on a byte list. Nothing is executed, no stream is
opened, and a shape that does not match is left untouched.
"""
from __future__ import annotations

import re

from . import PlagEncode

MAX_PAYLOAD = 2_000_000

_BYTE_ARRAY_RE = re.compile(
    r"\$(?P<name>\w+)\s*=\s*\[byte\[\]\]\s*\(\s*(?P<bytes>[\d\s,]+?)\s*\)",
    re.IGNORECASE,
)

_FROM_B64_RE = re.compile(
    r"\$(?P<name>\w+)\s*=\s*\[(?:System\.)?Convert\]::FromBase64String\("
    r"\s*['\"](?P<b64>[A-Za-z0-9+/=\s]+)['\"]\s*\)",
    re.IGNORECASE,
)

# $x[$i] = $b[$i] -bxor $K[$i % $K.Length]
_XOR_LOOP_RE = re.compile(
    r"\$(?P<dst>\w+)\s*\[\s*\$\w+\s*\]\s*=\s*"
    r"\$(?P<src>\w+)\s*\[\s*\$\w+\s*\]\s*-bxor\s*"
    r"\$(?P<key>\w+)\s*\[\s*\$\w+\s*%\s*\$(?P=key)\.Length\s*\]",
    re.IGNORECASE,
)

_DECOMPRESS_RE = re.compile(r"(Gzip|Deflate)Stream", re.IGNORECASE)

_MARKER = "# [recovered payload:"


def _byte_arrays(text: str) -> dict[str, bytes]:
    """Every byte array the script builds, by variable name."""
    found: dict[str, bytes] = {}

    for match in _BYTE_ARRAY_RE.finditer(text):
        try:
            values = [int(tok) for tok in match.group("bytes").split(",") if tok.strip()]
        except ValueError:
            continue
        if values and all(0 <= v <= 255 for v in values):
            found[match.group("name").lower()] = bytes(values)

    for match in _FROM_B64_RE.finditer(text):
        blob = re.sub(r"\s+", "", match.group("b64"))
        try:
            import base64
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except Exception:
            continue
        if raw and len(raw) <= MAX_PAYLOAD:
            found[match.group("name").lower()] = raw

    return found


def recover_xor_loop(text: str):
    """Undo `dst[i] = src[i] -bxor key[i % key.Length]` and any decompression.

    The recovered text is appended as a comment rather than replacing the
    loader, so the script still reads as what was submitted.
    """
    loop = _XOR_LOOP_RE.search(text)
    if loop is None:
        return text, False, ""
    # The loader stays in the script, so without this the pass would match
    # again on every round and append the payload once per iteration.
    if _MARKER in text:
        return text, False, ""

    arrays = _byte_arrays(text)
    src = arrays.get(loop.group("src").lower())
    key = arrays.get(loop.group("key").lower())
    if not src or not key:
        return text, False, ""

    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(src))

    # The loader almost always compresses before encrypting; inflate if the
    # script says so, or if the bytes announce themselves.
    if _DECOMPRESS_RE.search(text) or plain[:2] in (b"\x1f\x8b", b"\x78\x9c", b"\x78\x01"):
        plain = PlagEncode.maybe_decompress(plain)

    if not PlagEncode.looks_like_text(plain):
        return text, False, ""

    decoded = plain.decode("utf-8", errors="replace").strip()
    if not decoded:
        return text, False, ""

    lines = [f"{_MARKER} {loop.group('src')} XOR {loop.group('key')}]"]
    lines += [f"# {line}" for line in decoded.split("\n")]
    return text + "\n" + "\n".join(lines), True, f"{len(decoded)} character(s)"
