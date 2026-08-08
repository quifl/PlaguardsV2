"""Small regex-building helpers shared across the deobfuscator and signature
rules, kept separate so the nested-group construction is written (and
tested) in exactly one place."""
from __future__ import annotations

import re


def abbreviated_flag(word: str) -> str:
    """Build a regex matching any unique-prefix abbreviation of `word`, the
    way PowerShell.exe resolves abbreviated parameter names itself (e.g.
    -e, -en, -enc, ... -encodedcommand all resolve to -EncodedCommand)."""
    first, rest = word[0], word[1:]
    pattern = ""
    closes = ""
    for ch in rest:
        pattern += f"(?:{re.escape(ch)}"
        closes += ")?"
    return re.escape(first) + pattern + closes
