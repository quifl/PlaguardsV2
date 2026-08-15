"""Recovers the payload from a byte-array loader.

The shape is standard: a Base64 blob decoded to bytes, combined byte-by-byte
with a short repeating key in a `for` loop, then handed to a decompression
stream and read back as text. No single expression resolves it - the work
happens across several statements and a loop - so it has to be recognised as
a whole.

This does not match one hard-coded shape. It builds a small symbol table of
the script's byte arrays and integers, finds the assignment inside the loop
body, and *evaluates* whatever index expression the key is subscripted with.
So the names, the length variable, the key size and the arithmetic can all
differ from any sample seen before.

Everything is arithmetic on a byte list. Nothing is executed, no stream is
opened, and a shape that does not reduce is left untouched.
"""
from __future__ import annotations

import base64
import re

from . import PlagArith, PlagEncode

MAX_PAYLOAD = 4_000_000
MARKER = "# [recovered payload"

# $name = [byte[]](90,55,193,158)   /   [byte[]]@(90,55,...)
_BYTE_LITERAL_RE = re.compile(
    r"\$(?P<name>\w+)\s*=\s*\[byte\[\]\]\s*@?\(\s*(?P<bytes>[\d\sxXA-Fa-f,]+?)\s*\)",
    re.IGNORECASE,
)

# $name = [Convert]::FromBase64String("....")
_FROM_B64_RE = re.compile(
    r"\$(?P<name>\w+)\s*=\s*(?:\[byte\[\]\]\s*)?"
    r"\[(?:System\.)?Convert\]::FromBase64String\(\s*['\"](?P<b64>[A-Za-z0-9+/=\s]+)['\"]\s*\)",
    re.IGNORECASE,
)

# $name = <integer>            /  $name = $other.Length  /  $name = $other.Count
_INT_ASSIGN_RE = re.compile(r"\$(?P<name>\w+)\s*=\s*(?P<value>\d{1,9})\s*(?:[;\n]|$)")
_LEN_ASSIGN_RE = re.compile(
    r"\$(?P<name>\w+)\s*=\s*\$(?P<of>\w+)\s*\.\s*(?:Length|Count)\b", re.IGNORECASE
)

# $dst[$i] = $src[$i] <op> $key[<expr>]
_COMBINE_RE = re.compile(
    r"\$(?P<dst>\w+)\s*\[\s*\$(?P<idx>\w+)\s*\]\s*=\s*"
    r"\$(?P<src>\w+)\s*\[\s*\$(?P=idx)\s*\]\s*"
    r"(?P<op>-bxor|-band|-bor|\+|-)\s*"
    r"\$(?P<key>\w+)\s*\[\s*(?P<keyidx>[^\]]{1,120})\s*\]",
    re.IGNORECASE,
)

_DECOMPRESS_RE = re.compile(r"(Gzip|Deflate)Stream", re.IGNORECASE)

_OPS = {
    "-bxor": lambda a, b: a ^ b,
    "-band": lambda a, b: a & b,
    "-bor": lambda a, b: a | b,
    "+": lambda a, b: a + b,
    "-": lambda a, b: a - b,
}


def _symbols(text: str) -> tuple[dict[str, bytes], dict[str, int]]:
    """The script's byte arrays and integer variables, by lower-cased name."""
    arrays: dict[str, bytes] = {}
    integers: dict[str, int] = {}

    for match in _BYTE_LITERAL_RE.finditer(text):
        values = []
        for token in match.group("bytes").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                values.append(int(token, 16) if token[:2].lower() == "0x" else int(token))
            except ValueError:
                values = []
                break
        if values and all(0 <= v <= 255 for v in values):
            arrays[match.group("name").lower()] = bytes(values)

    for match in _FROM_B64_RE.finditer(text):
        blob = re.sub(r"\s+", "", match.group("b64"))
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except Exception:
            continue
        if raw and len(raw) <= MAX_PAYLOAD:
            arrays[match.group("name").lower()] = raw

    for match in _INT_ASSIGN_RE.finditer(text):
        integers[match.group("name").lower()] = int(match.group("value"))

    # `$kLen = $rollKey.Length` - resolved after the arrays are known.
    for match in _LEN_ASSIGN_RE.finditer(text):
        source = arrays.get(match.group("of").lower())
        if source is not None:
            integers[match.group("name").lower()] = len(source)

    return arrays, integers


_DOLLAR_LEN_RE = re.compile(r"\$(\w+)\s*\.\s*(?:Length|Count)\b", re.IGNORECASE)
_DOLLAR_RE = re.compile(r"\$(\w+)")


def _index_function(expression: str, arrays: dict, integers: dict, index_name: str):
    """Turn `$n % $kLen` into a callable of the loop index.

    Returns `f(i) -> int | None`. Handles a length read inline
    (`$key.Length`), a length held in a variable, or a bare number - the
    three ways the same loop gets written.
    """
    bindings: dict[str, int] = {}

    # `$key.Length` -> a plain name bound to that array's length.
    def bind_length(match: re.Match) -> str:
        name = match.group(1).lower()
        if name in arrays:
            key = f"len_{name}"
            bindings[key] = len(arrays[name])
            return key
        if name in integers:
            return str(integers[name])
        return "__unknown__"

    text = _DOLLAR_LEN_RE.sub(bind_length, expression)

    def bind_name(match: re.Match) -> str:
        name = match.group(1).lower()
        if name == index_name.lower():
            return "idx"
        if name in integers:
            return str(integers[name])
        if name in arrays:
            return "__unknown__"
        return "__unknown__"

    text = _DOLLAR_RE.sub(bind_name, text)
    if "__unknown__" in text:
        return None

    evaluate = PlagArith.compile_expression(text)
    if evaluate is None:
        return None

    def at(i: int):
        return evaluate({**bindings, "idx": i})

    return at


def recover_xor_loop(text: str):
    """Undo a byte-wise loop over an encoded array, and any decompression.

    The recovered text is appended as a comment rather than replacing the
    loader, so the script still reads as what was submitted.
    """
    if MARKER in text:
        # The loader stays in the script; without this the pass would match
        # again on every round and append its output once per iteration.
        return text, False, ""

    combine = _COMBINE_RE.search(text)
    if combine is None:
        return text, False, ""

    arrays, integers = _symbols(text)
    src = arrays.get(combine.group("src").lower())
    key = arrays.get(combine.group("key").lower())
    if not src or not key:
        return text, False, ""

    key_at = _index_function(combine.group("keyidx"), arrays, integers,
                             combine.group("idx"))
    if key_at is None:
        return text, False, ""

    operation = _OPS[combine.group("op").lower()]
    out = bytearray()
    for i, value in enumerate(src):
        position = key_at(i)
        if position is None or not 0 <= position < len(key):
            return text, False, ""
        out.append(operation(value, key[position]) & 0xFF)
    plain = bytes(out)

    # The loader almost always compresses before encoding; inflate if the
    # script says so, or if the bytes announce themselves.
    if _DECOMPRESS_RE.search(text) or plain[:2] in (b"\x1f\x8b", b"\x78\x9c", b"\x78\x01"):
        plain = PlagEncode.maybe_decompress(plain)

    if not PlagEncode.looks_like_text(plain):
        return text, False, ""

    decoded = plain.decode("utf-8", errors="replace").strip()
    if not decoded:
        return text, False, ""

    lines = [f"{MARKER}: {combine.group('src')} {combine.group('op')} "
             f"{combine.group('key')}]"]
    lines += [f"# {line}" for line in decoded.split("\n")]
    return text + "\n" + "\n".join(lines), True, f"{len(decoded)} character(s)"
