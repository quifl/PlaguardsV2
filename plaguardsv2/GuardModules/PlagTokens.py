"""Tokenizer for the restricted PowerShell expression subset understood by
PlagTrace. Purely lexical - it never executes anything."""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_TOKENS = 20000


@dataclass
class Token:
    kind: str   # str | num | var | op | name | punct
    value: str


_NUM_RE = re.compile(r"\d+")
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_VAR_RE = re.compile(r"\$(?:\{(?P<braced>[^}]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")
_OPERATOR_WORDS = ("join", "split", "replace", "bxor", "band", "bor", "f", "eq", "ne", "lt", "gt", "le", "ge")


def tokenize(text: str) -> list[Token] | None:
    """Return a token list, or None if the input contains something outside
    the supported subset in a way that makes tokenizing unsafe."""
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        if len(tokens) > MAX_TOKENS:
            return None
        c = text[i]

        if c in " \t\r\n":
            i += 1
            continue

        if c == "'":
            j = i + 1
            buf = []
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        buf.append("'")
                        j += 2
                        continue
                    break
                buf.append(text[j])
                j += 1
            if j >= n:
                return None
            tokens.append(Token("str", "".join(buf)))
            i = j + 1
            continue

        if c == '"':
            j = i + 1
            buf = []
            while j < n:
                ch = text[j]
                if ch == "`" and j + 1 < n:
                    buf.append("`" + text[j + 1])
                    j += 2
                    continue
                if ch == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        buf.append('"')
                        j += 2
                        continue
                    break
                buf.append(ch)
                j += 1
            if j >= n:
                return None
            tokens.append(Token("dqstr", "".join(buf)))
            i = j + 1
            continue

        m = _VAR_RE.match(text, i)
        if m:
            name = m.group("braced") if m.group("braced") is not None else m.group("plain")
            tokens.append(Token("var", name))
            i = m.end()
            continue

        if c == "-":
            m = _NAME_RE.match(text, i + 1)
            if m and m.group(0).lower() in _OPERATOR_WORDS:
                tokens.append(Token("op", "-" + m.group(0).lower()))
                i = m.end()
                continue
            tokens.append(Token("op", "-"))
            i += 1
            continue

        m = _NUM_RE.match(text, i)
        if m:
            tokens.append(Token("num", m.group(0)))
            i = m.end()
            continue

        m = _NAME_RE.match(text, i)
        if m:
            tokens.append(Token("name", m.group(0)))
            i = m.end()
            continue

        if c in "+*/":
            tokens.append(Token("op", c))
            i += 1
            continue

        if c in "()[],.:;=@{}":
            tokens.append(Token("punct", c))
            i += 1
            continue

        # Anything else (pipes, redirects, unusual symbols) - unsupported.
        tokens.append(Token("punct", c))
        i += 1

    return tokens
