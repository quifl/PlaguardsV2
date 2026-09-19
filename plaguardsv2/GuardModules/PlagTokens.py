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


# Hex and binary literals have to be recognised here, not later: a bare `\d+`
# matched only the leading "0" of `0x41`, the "x41" lexed as a name and was
# dropped, and the payload byte silently became zero.
_NUM_RE = re.compile(r"0[xX][0-9a-fA-F]+|0[bB][01]+|\d+")
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_VAR_RE = re.compile(r"\$(?:\{(?P<braced>[^}]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")

# A multiplier suffix is unambiguous because it can only ever follow a numeric
# literal, and no PowerShell name may start with a digit - so `1kb` can never
# be the tail of an identifier the way a bare `kb` could.
_MULTIPLIER_RE = re.compile(r"(kb|mb|gb|tb|pb)(?![A-Za-z0-9_])", re.IGNORECASE)
_MULTIPLIERS = {
    "kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3,
    "tb": 1024 ** 4, "pb": 1024 ** 5,
}

# Only list a word here if the parser also dispatches on it. A word that
# tokenizes but is never handled makes the parser drop its right operand and
# return the left one unchanged, which reads downstream as a resolved value.
_OPERATOR_WORDS = (
    "join", "split",
    "replace", "ireplace", "creplace",
    "bxor", "band", "bor", "bnot", "shl", "shr",
    "f", "eq", "ne", "lt", "gt", "le", "ge",
)

# `%` is the modulo operator only directly after a value; everywhere else it
# is the ForEach-Object alias.
_VALUE_KINDS = ("num", "str", "dqstr", "var")
_VALUE_PUNCT = ")]"


def _read_number(text: str, i: int) -> tuple[Token, int] | None:
    """Lex one numeric literal, normalising every base to decimal.

    Normalising here rather than in the parser is deliberate: the parser does
    a plain `int(tok.value)` and stays untouched, so base support adds no new
    parser paths to get wrong.
    """
    m = _NUM_RE.match(text, i)
    if m is None:
        return None
    raw = m.group(0)
    prefix = raw[:2].lower()
    if prefix == "0x":
        value = int(raw, 16)
    elif prefix == "0b":
        value = int(raw, 2)
    else:
        value = int(raw)

    end = m.end()
    suffix = _MULTIPLIER_RE.match(text, end)
    if suffix is not None:
        value *= _MULTIPLIERS[suffix.group(1).lower()]
        end = suffix.end()
    return Token("num", str(value)), end


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

        number = _read_number(text, i)
        if number is not None:
            tok, i = number
            tokens.append(tok)
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

        if c == "%":
            # Disambiguated by operand position, because `%` is both modulo and
            # the ForEach-Object alias: classifying it as an operator wherever
            # it appeared broke every `| %{ ... }` pipeline in the corpus.
            prev = tokens[-1] if tokens else None
            binary = prev is not None and (
                prev.kind in _VALUE_KINDS
                or (prev.kind == "punct" and prev.value in _VALUE_PUNCT)
            )
            tokens.append(Token("op" if binary else "punct", "%"))
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
