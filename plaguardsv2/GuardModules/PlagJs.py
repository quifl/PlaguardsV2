"""JScript / JavaScript literal folding.

The .js half of a dropper corpus is usually `String.fromCharCode` for the
characters, `+` to rejoin them, and a `split`/`reverse`/`join` dance over a
backwards literal. All three reduce statically.

Text rewriting only. Nothing here executes, and no JavaScript engine is
involved.
"""
from __future__ import annotations

import re

from . import PlagArith, PlagEncode

_DQ = r'"(?:[^"\\]|\\.)*"'
_SQ = r"'(?:[^'\\]|\\.)*'"
_LITERAL = f"(?:{_DQ}|{_SQ})"

# Arithmetic per argument too: fromCharCode(0x6d, 108+1, 97*1).
_FROM_CHAR_CODE_RE = re.compile(
    r"\bString\s*\.\s*fromCharCode\s*\(\s*([0-9A-Fa-fxX\s,+\-*/^()]{1,4000}?)\s*\)",
    re.IGNORECASE,
)

_CONCAT_RE = re.compile(rf"({_LITERAL})\s*\+\s*({_LITERAL})")

# "abc".split("").reverse().join("")
_REVERSE_CHAIN_RE = re.compile(
    rf"({_LITERAL})\s*\.\s*split\s*\(\s*(?:\"\"|'')\s*\)"
    r"\s*\.\s*reverse\s*\(\s*\)"
    r"\s*\.\s*join\s*\(\s*(?:\"\"|'')\s*\)",
    re.IGNORECASE,
)

# "a-b-c".split("-").join("")
_SPLIT_JOIN_RE = re.compile(
    rf"({_LITERAL})\s*\.\s*split\s*\(\s*({_LITERAL})\s*\)"
    rf"\s*\.\s*join\s*\(\s*({_LITERAL})\s*\)",
    re.IGNORECASE,
)

_REPLACE_RE = re.compile(
    rf"({_LITERAL})\s*\.\s*replace\s*\(\s*({_LITERAL})\s*,\s*({_LITERAL})\s*\)",
    re.IGNORECASE,
)

# "abcdef".substring(2, 5) / .substr(2, 3) / .slice(2, 5) / .charAt(2)
_SLICE_RE = re.compile(
    r"({literal})\s*\.\s*(substring|substr|slice|charAt)\s*\(\s*"
    r"(-?\d{{1,6}})\s*(?:,\s*(-?\d{{1,6}})\s*)?\)".format(literal=_LITERAL),
    re.IGNORECASE,
)

_CASE_TRIM_RE = re.compile(
    rf"({_LITERAL})\s*\.\s*(toUpperCase|toLowerCase|trim)\s*\(\s*\)",
    re.IGNORECASE,
)

_CASE_TRIM_OPS = {"touppercase": str.upper, "tolowercase": str.lower, "trim": str.strip}

_ATOB_RE = re.compile(rf"\batob\s*\(\s*({_LITERAL})\s*\)", re.IGNORECASE)

_UNESCAPE_RE = re.compile(
    rf"\b(?:unescape|decodeURI|decodeURIComponent)\s*\(\s*({_LITERAL})\s*\)",
    re.IGNORECASE,
)

# var x = "literal";  /  x = 'literal'
_ASSIGN_RE = re.compile(
    rf"^(\s*(?:var|let|const)?\s*)([A-Za-z_$][\w$]*)(\s*=\s*)({_LITERAL})(\s*;?\s*)$"
)
# A bare name, not a property access or another declaration.
_USE_RE = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)(?![\w$]*\s*=[^=])(?![\w$])")

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}


def looks_like_script(text: str) -> bool:
    """Cheap sniff so the passes stay off files that are not JScript."""
    markers = ("var ", "function ", "wscript.echo", "fromcharcode", "=>", "console.log")
    lowered = text.lower()
    return sum(1 for m in markers if m in lowered) >= 2


def _unquote(literal: str) -> str:
    body = literal[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            out.append(_ESCAPES.get(body[i + 1], body[i + 1]))
            i += 2
            continue
        out.append(body[i])
        i += 1
    return "".join(out)


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return '"' + escaped + '"'


def resolve_char_codes(text: str):
    """`String.fromCharCode(72,105)` -> `"Hi"`."""
    hits = 0

    def swap(match: re.Match) -> str:
        nonlocal hits
        chars = []
        for token in match.group(1).split(","):
            token = token.strip()
            if not token:
                continue
            char = PlagArith.to_char(token)
            if char is None:
                # One argument we cannot fold means the whole call stays, so a
                # partly-decoded string is never presented as the answer.
                return match.group(0)
            chars.append(char)
        if not chars:
            return match.group(0)
        hits += 1
        return _quote("".join(chars))

    result = _FROM_CHAR_CODE_RE.sub(swap, text)
    return result, hits > 0, f"{hits} sequence(s)" if hits else ""


def fold_concatenation(text: str):
    """`"a" + "b"` -> `"ab"`, repeatedly."""
    hits = 0
    for _ in range(200):
        new, count = _CONCAT_RE.subn(
            lambda m: _quote(_unquote(m.group(1)) + _unquote(m.group(2))), text
        )
        if not count:
            break
        text, hits = new, hits + count
    return text, hits > 0, f"{hits} pair(s)" if hits else ""


def fold_string_methods(text: str):
    """Fold reverse / split-join / replace chains over literal receivers."""
    hits = 0

    def reverse(match: re.Match) -> str:
        nonlocal hits
        hits += 1
        return _quote(_unquote(match.group(1))[::-1])

    def split_join(match: re.Match) -> str:
        nonlocal hits
        hits += 1
        target, sep, glue = (_unquote(match.group(i)) for i in (1, 2, 3))
        parts = list(target) if sep == "" else target.split(sep)
        return _quote(glue.join(parts))

    def replace(match: re.Match) -> str:
        nonlocal hits
        hits += 1
        target, find, sub = (_unquote(match.group(i)) for i in (1, 2, 3))
        # A string argument replaces only the first occurrence in JS.
        return _quote(target.replace(find, sub, 1))

    def slice_(match: re.Match) -> str:
        nonlocal hits
        target, method = _unquote(match.group(1)), match.group(2).lower()
        start = int(match.group(3))
        second = match.group(4)
        if method == "charat":
            if not 0 <= start < len(target):
                return match.group(0)
            hits += 1
            return _quote(target[start])
        if second is None:
            cut = target[start:]
        elif method == "substr":
            # substr's second argument is a length, the others' is an end index.
            cut = target[start:start + int(second)]
        else:
            cut = target[start:int(second)]
        hits += 1
        return _quote(cut)

    def case_trim(match: re.Match) -> str:
        nonlocal hits
        hits += 1
        return _quote(_CASE_TRIM_OPS[match.group(2).lower()](_unquote(match.group(1))))

    # Repeated, because folding an inner call can expose an outer one.
    for _ in range(20):
        before = text
        text = _REVERSE_CHAIN_RE.sub(reverse, text)
        text = _SPLIT_JOIN_RE.sub(split_join, text)
        text = _REPLACE_RE.sub(replace, text)
        text = _SLICE_RE.sub(slice_, text)
        text = _CASE_TRIM_RE.sub(case_trim, text)
        if text == before:
            break

    return text, hits > 0, f"{hits} call(s)" if hits else ""


def decode_encodings(text: str):
    """Undo the encodings that hide a literal in plain sight.

    Covers hex/unicode escapes inside a literal, `unescape("%41%42")`,
    `atob("...")`, and a bare Base64 string long enough to be one. A candidate
    that does not decode to readable text is left exactly as written rather
    than replaced with mojibake.
    """
    hits = 0

    def escapes(match: re.Match) -> str:
        nonlocal hits
        raw = match.group(0)
        decoded = PlagEncode.decode_escapes(raw[1:-1])
        if decoded == raw[1:-1]:
            return raw
        hits += 1
        return _quote(decoded)

    def unescape(match: re.Match) -> str:
        nonlocal hits
        decoded = PlagEncode.decode_percent(_unquote(match.group(1)))
        if decoded is None:
            return match.group(0)
        hits += 1
        return _quote(decoded)

    def atob(match: re.Match) -> str:
        nonlocal hits
        decoded = PlagEncode.decode_base64(_unquote(match.group(1)))
        if decoded is None:
            return match.group(0)
        hits += 1
        return _quote(decoded)

    def b64_literal(match: re.Match) -> str:
        nonlocal hits
        decoded = PlagEncode.decode_base64(_unquote(match.group(0)))
        if decoded is None:
            return match.group(0)
        hits += 1
        return _quote(decoded)

    text = _ATOB_RE.sub(atob, text)
    text = _UNESCAPE_RE.sub(unescape, text)
    text = re.compile(_LITERAL).sub(escapes, text)
    text = re.compile(_LITERAL).sub(b64_literal, text)
    return text, hits > 0, f"{hits} value(s)" if hits else ""


def track_variables(text: str):
    """Substitute variables whose value is a known literal.

    Sequential and single-assignment only: a name assigned twice is dropped
    rather than propagated, because which value applies at a given line is
    exactly what a static pass cannot know.
    """
    lines = text.split("\n")
    counts: dict[str, int] = {}
    for line in lines:
        m = _ASSIGN_RE.match(line)
        if m:
            counts[m.group(2)] = counts.get(m.group(2), 0) + 1

    known: dict[str, str] = {}
    out: list[str] = []
    hits = 0
    for line in lines:
        m = _ASSIGN_RE.match(line)
        if m and counts.get(m.group(2)) == 1:
            known[m.group(2)] = _unquote(m.group(4))
            out.append(line)
            continue

        def swap(um: re.Match) -> str:
            nonlocal hits
            value = known.get(um.group(1))
            if value is None:
                return um.group(0)
            hits += 1
            return _quote(value)

        # Only outside string literals, so a name mentioned in a message is
        # left as prose.
        pieces = re.split(f"({_LITERAL})", line)
        for i in range(0, len(pieces), 2):
            pieces[i] = _USE_RE.sub(swap, pieces[i])
        out.append("".join(pieces))

    if not hits:
        return text, False, ""
    return "\n".join(out), True, f"{hits} reference(s)"
