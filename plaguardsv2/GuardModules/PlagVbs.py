"""VBScript literal folding.

Obfuscated .vbs leans on three things: `Chr(n)` for characters the author
would rather not spell out, `&` to glue the pieces back together, and
`StrReverse` on a written-backwards literal. Undoing those turns the file
back into readable text without running any of it.

Text rewriting only - no interpreter is involved at any point.
"""
from __future__ import annotations

import re

from . import PlagEncode

_LITERAL = r'"(?:[^"]|"")*"'

# Chr(72), ChrW(&H48), Chr$(72)
_CHR_RE = re.compile(r"\bChrW?\$?\s*\(\s*(&[Hh][0-9A-Fa-f]+|\d{1,7})\s*\)", re.IGNORECASE)

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
    """`Chr(72)` -> `"H"`."""
    hits = 0

    def swap(match: re.Match) -> str:
        nonlocal hits
        token = match.group(1)
        try:
            code = int(token[2:], 16) if token[:2].lower() == "&h" else int(token)
        except ValueError:
            return match.group(0)
        if not 0 <= code <= 0x10FFFF:
            return match.group(0)
        hits += 1
        return _quote(chr(code))

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

    text = _REVERSE_RE.sub(reverse, text)
    text = _REPLACE_RE.sub(replace, text)
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
