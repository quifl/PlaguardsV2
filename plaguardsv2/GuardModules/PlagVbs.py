"""VBScript literal folding.

Obfuscated .vbs leans on three things: `Chr(n)` for characters the author
would rather not spell out, `&` to glue the pieces back together, and
`StrReverse` on a written-backwards literal. Undoing those turns the file
back into readable text without running any of it.

Text rewriting only - no interpreter is involved at any point.
"""
from __future__ import annotations

import re

from . import PlagArith, PlagEncode

_LITERAL = r'"(?:[^"]|"")*"'

# Chr(72), ChrW(&H48), Chr$(72), and the arithmetic forms - Chr(71+1).
_CHR_RE = re.compile(
    r"\bChrW?\$?\s*\(\s*([0-9A-Fa-f&Hh\s+\-*/^()]{1,120}?)\s*\)",
    re.IGNORECASE,
)

# Split / Join / Mid / Left / Right and the case-and-trim family. All fold
# only when every argument is a literal.
_SPLIT_JOIN_RE = re.compile(
    rf"\bJoin\s*\(\s*Split\s*\(\s*({_LITERAL})\s*,\s*({_LITERAL})\s*\)\s*,\s*({_LITERAL})\s*\)",
    re.IGNORECASE,
)
_MID_RE = re.compile(
    rf"\bMid\s*\(\s*({_LITERAL})\s*,\s*(\d{{1,6}})\s*(?:,\s*(\d{{1,6}})\s*)?\)",
    re.IGNORECASE,
)
_LEFT_RIGHT_RE = re.compile(
    rf"\b(Left|Right)\s*\(\s*({_LITERAL})\s*,\s*(\d{{1,6}})\s*\)",
    re.IGNORECASE,
)
_CASE_TRIM_RE = re.compile(
    rf"\b(UCase|LCase|Trim|LTrim|RTrim)\$?\s*\(\s*({_LITERAL})\s*\)",
    re.IGNORECASE,
)

_CASE_TRIM_OPS = {
    "ucase": str.upper, "lcase": str.lower,
    "trim": str.strip, "ltrim": str.lstrip, "rtrim": str.rstrip,
}

_AMP_RE = re.compile(rf"({_LITERAL})\s*&\s*({_LITERAL})")

_REVERSE_RE = re.compile(rf"\bStrReverse\s*\(\s*({_LITERAL})\s*\)", re.IGNORECASE)

_REPLACE_RE = re.compile(
    rf"\bReplace\s*\(\s*({_LITERAL})\s*,\s*({_LITERAL})\s*,\s*({_LITERAL})\s*\)",
    re.IGNORECASE,
)


def _unquote(literal: str) -> str:
    return literal[1:-1].replace('""', '"')


def _quote(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def looks_like_vbscript(text: str) -> bool:
    """Cheap sniff so the passes stay off files that are not VBScript."""
    markers = ("wscript.echo", "strreverse(", "dim ", "vbcrlf", "msgbox")
    lowered = text.lower()
    return sum(1 for m in markers if m in lowered) >= 2


def resolve_chr(text: str):
    """`Chr(72)` -> `"H"`, including `Chr(71+1)` and `ChrW(&H48)`."""
    hits = 0

    def swap(match: re.Match) -> str:
        nonlocal hits
        char = PlagArith.to_char(match.group(1))
        if char is None:
            return match.group(0)
        hits += 1
        return _quote(char)

    result = _CHR_RE.sub(swap, text)
    return result, hits > 0, f"{hits} character(s)" if hits else ""


def fold_concatenation(text: str):
    """`"a" & "b"` -> `"ab"`, repeatedly until nothing is left to join."""
    hits = 0
    for _ in range(200):
        new, count = _AMP_RE.subn(
            lambda m: _quote(_unquote(m.group(1)) + _unquote(m.group(2))), text
        )
        if not count:
            break
        text, hits = new, hits + count
    return text, hits > 0, f"{hits} pair(s)" if hits else ""


def resolve_string_calls(text: str):
    """Fold `StrReverse` and `Replace` over literal arguments."""
    hits = 0

    def reverse(match: re.Match) -> str:
        nonlocal hits
        hits += 1
        return _quote(_unquote(match.group(1))[::-1])

    def replace(match: re.Match) -> str:
        nonlocal hits
        hits += 1
        target, find, sub = (_unquote(match.group(i)) for i in (1, 2, 3))
        return _quote(target.replace(find, sub))

    def split_join(match: re.Match) -> str:
        nonlocal hits
        hits += 1
        target, sep, glue = (_unquote(match.group(i)) for i in (1, 2, 3))
        parts = list(target) if sep == "" else target.split(sep)
        return _quote(glue.join(parts))

    def mid(match: re.Match) -> str:
        nonlocal hits
        target = _unquote(match.group(1))
        # VBScript indexes from 1, not 0.
        start = max(0, int(match.group(2)) - 1)
        length = match.group(3)
        hits += 1
        return _quote(target[start:] if length is None
                      else target[start:start + int(length)])

    def left_right(match: re.Match) -> str:
        nonlocal hits
        which, target, count = match.group(1).lower(), _unquote(match.group(2)), int(match.group(3))
        hits += 1
        return _quote(target[:count] if which == "left" else target[-count:] if count else "")

    def case_trim(match: re.Match) -> str:
        nonlocal hits
        op = _CASE_TRIM_OPS[match.group(1).lower()]
        hits += 1
        return _quote(op(_unquote(match.group(2))))

    # Repeated, because folding an inner call can expose an outer one.
    for _ in range(20):
        before = text
        text = _SPLIT_JOIN_RE.sub(split_join, text)
        text = _REVERSE_RE.sub(reverse, text)
        text = _REPLACE_RE.sub(replace, text)
        text = _MID_RE.sub(mid, text)
        text = _LEFT_RIGHT_RE.sub(left_right, text)
        text = _CASE_TRIM_RE.sub(case_trim, text)
        if text == before:
            break

    return text, hits > 0, f"{hits} call(s)" if hits else ""


def decode_base64_literals(text: str):
    """Replace a literal that is really a Base64 payload with its contents.

    Anything that does not decode to readable text is left as written - a
    long word can be valid Base64 by accident."""
    hits = 0

    def swap(match: re.Match) -> str:
        nonlocal hits
        decoded = PlagEncode.decode_base64(_unquote(match.group(0)))
        if decoded is None:
            return match.group(0)
        hits += 1
        return _quote(decoded)

    result = re.compile(_LITERAL).sub(swap, text)
    return result, hits > 0, f"{hits} literal(s)" if hits else ""


# Dim is a declaration, not an assignment; `x = "literal"` is the interesting one.
_ASSIGN_RE = re.compile(rf'^(\s*)([A-Za-z_]\w*)(\s*=\s*)({_LITERAL})(\s*)$')
_USE_RE = re.compile(r"(?<![\w.])([A-Za-z_]\w*)(?!\w)")

_VBS_KEYWORDS = {
    "dim", "set", "if", "then", "else", "end", "for", "each", "next", "do",
    "loop", "while", "wend", "function", "sub", "call", "and", "or", "not",
    "true", "false", "nothing", "wscript", "echo", "msgbox", "chr", "strreverse",
    "replace", "mid", "left", "right", "len", "instr", "ucase", "lcase",
}


def track_variables(text: str):
    """Substitute variables whose value is a known literal.

    Single-assignment only: a name assigned more than once is left alone,
    because which value applies at a given line is precisely what a static
    pass cannot know.
    """
    lines = text.split("\n")
    counts: dict[str, int] = {}
    for line in lines:
        m = _ASSIGN_RE.match(line)
        if m:
            key = m.group(2).lower()
            counts[key] = counts.get(key, 0) + 1

    known: dict[str, str] = {}
    out: list[str] = []
    hits = 0
    for line in lines:
        m = _ASSIGN_RE.match(line)
        if m and counts.get(m.group(2).lower()) == 1:
            known[m.group(2).lower()] = _unquote(m.group(4))
            out.append(line)
            continue

        def swap(um: re.Match) -> str:
            nonlocal hits
            name = um.group(1).lower()
            if name in _VBS_KEYWORDS:
                return um.group(0)
            value = known.get(name)
            if value is None:
                return um.group(0)
            hits += 1
            return _quote(value)

        # Outside string literals only, so a name mentioned in a message stays
        # prose.
        pieces = re.split(f"({_LITERAL})", line)
        for i in range(0, len(pieces), 2):
            code, _, comment = pieces[i].partition("'")
            pieces[i] = _USE_RE.sub(swap, code) + ("'" + comment if comment else "")
        out.append("".join(pieces))

    if not hits:
        return text, False, ""
    return "\n".join(out), True, f"{hits} reference(s)"
