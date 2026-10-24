"""Lexical helpers shared by every pass that has to step over string literals.

The passes scan the whole script several times per round, so these jump
between the characters that matter instead of stepping one at a time.
"""
from __future__ import annotations

import re

_DQ_STOP_RE = re.compile(r'[`"]')


def literal_end(text: str, start: int) -> int:
    """Index just past the string literal whose quote is at `start`.

    PowerShell rules: inside "..." a backtick escapes the next character, in
    either kind a doubled quote is an escaped quote, and an unterminated
    literal runs to the end of the text.
    """
    n = len(text)
    quote = text[start]
    j = start + 1
    while j < n:
        if quote == '"':
            stop = _DQ_STOP_RE.search(text, j)
            if stop is None:
                return n
            j = stop.start()
            if text[j] == "`":
                # A trailing backtick escapes nothing; the literal runs out.
                j += 2 if j + 1 < n else 1
                continue
        else:
            j = text.find("'", j)
            if j < 0:
                return n
        if j + 1 < n and text[j + 1] == quote:
            j += 2
            continue
        return j + 1
    return n
