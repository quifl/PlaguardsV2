"""Batch / cmd variable resolution.

A .bat or .cmd stager hides its payload in `set` assignments and reassembles
it with expansions the shell performs at run time: `%var%`, `!var!` under
delayed expansion, `%var:~offset,length%` carving a slice out of a pool, and
`%var:find=replace%`. Following those assignments in order reproduces the
final line without ever handing anything to a shell.
"""
from __future__ import annotations

import re

MAX_VALUE_LEN = 20_000

_SET_RE = re.compile(
    r"^\s*set\s+(?:/a\s+)?(?:\"(?P<qname>[^\"=]+)=(?P<qvalue>[^\"]*)\"|"
    r"(?P<name>[^=\s]+)=(?P<value>.*?))\s*$",
    re.IGNORECASE,
)

# %name%, !name!, %name:~1,2%, %name:a=b%
_EXPAND_RE = re.compile(
    r"(?P<sigil>[%!])(?P<name>[A-Za-z_][\w#$.-]*)"
    r"(?::~(?P<off>-?\d+)(?:,(?P<len>-?\d+))?|:(?P<find>[^=%!]*)=(?P<sub>[^%!]*))?"
    r"(?P=sigil)"
)


def looks_like_batch(text: str) -> bool:
    """Cheap sniff so the pass stays off files that are not batch."""
    markers = ("@echo off", "setlocal", "endlocal", "%~dp0", "goto :eof")
    lowered = text.lower()
    if any(m in lowered for m in markers):
        return True
    return bool(re.search(r"^\s*set\s+\w+=", text, re.IGNORECASE | re.MULTILINE))


def _uncaret(value: str) -> str:
    """Drop the `^` escapes cmd uses to pass `|`, `&`, `=` and friends."""
    out: list[str] = []
    i = 0
    while i < len(value):
        if value[i] == "^" and i + 1 < len(value):
            out.append(value[i + 1])
            i += 2
            continue
        out.append(value[i])
        i += 1
    return "".join(out)


def _expand(value: str, known: dict[str, str]) -> str:
    """Substitute every %var% / !var! reference we can resolve."""
    def swap(match: re.Match) -> str:
        current = known.get(match.group("name").lower())
        if current is None:
            return match.group(0)

        if match.group("off") is not None:
            start = int(match.group("off"))
            if start < 0:
                start = max(0, len(current) + start)
            if match.group("len") is None:
                return current[start:]
            length = int(match.group("len"))
            return current[start:length] if length < 0 else current[start:start + length]

        if match.group("find") is not None:
            return current.replace(match.group("find"), match.group("sub"))

        return current

    for _ in range(10):
        new = _EXPAND_RE.sub(swap, value)
        if new == value:
            break
        value = new
    return value[:MAX_VALUE_LEN]


def resolve_variables(text: str):
    """Rewrite each line with the values its variables held at that point.

    `set` lines keep their resolved right-hand side so the chain stays
    readable, and `echo` lines show what would actually have been printed.
    """
    known: dict[str, str] = {}
    out: list[str] = []
    changed = 0

    for line in text.split("\n"):
        match = _SET_RE.match(line)
        if match is not None:
            name = match.group("qname") or match.group("name") or ""
            raw = match.group("qvalue")
            if raw is None:
                raw = match.group("value") or ""
            resolved = _uncaret(_expand(raw, known))
            known[name.strip().lower()] = resolved
            rewritten = f"set {name.strip()}={resolved}"
            if rewritten.strip() != line.strip():
                changed += 1
            out.append(rewritten)
            continue

        resolved = _expand(line, known)
        # Only unescape once the expansions are done, or a caret in a value
        # would be eaten before it ever reached the line it belongs to.
        if resolved != line:
            resolved = _uncaret(resolved)
            changed += 1
        out.append(resolved)

    if not changed:
        return text, False, ""
    return "\n".join(out), True, f"{changed} line(s)"
