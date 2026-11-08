"""Gates a transform must pass before the scheduler keeps it.

Each gate compares a pass's input and output and answers keep or roll back.
None of them can prove a rewrite correct; they catch the ways a rewrite is
visibly wrong: code that no longer balances, a "decoded" stage that is
noise, a folded value of the wrong type for where it landed, and a round
that made the script more obfuscated rather than less.

ParseGate uses a tokenizer balance check. With no parser installed that is
the whole check; a tree-sitter based gate can replace it later behind the
same function.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache

from . import PlagScan
from .PlagArtifact import Lang

_PAIRS = {")": "(", "]": "[", "}": "{"}
_OPENERS = "([{"


@dataclass
class GateResult:
    name: str
    ok: bool
    reason: str = ""


def _ps_errors(text: str) -> int:
    stack: list[str] = []
    errors = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"":
            end = PlagScan.literal_end(text, i)
            if end >= n and (end - i < 2 or text[end - 1] != c):
                errors += 1
            i = end
            continue
        if c == "#" or text.startswith("<#", i):
            if c == "<":
                close = text.find("#>", i + 2)
                i = n if close == -1 else close + 2
            else:
                eol = text.find("\n", i)
                i = n if eol == -1 else eol
            continue
        if c == "`":
            i += 2
            continue
        if c in _OPENERS:
            stack.append(c)
        elif c in _PAIRS:
            if stack and stack[-1] == _PAIRS[c]:
                stack.pop()
            else:
                errors += 1
        i += 1
    return errors + len(stack)


def _js_errors(text: str) -> int:
    stack: list[str] = []
    errors = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"`":
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\\":
                    j += 1
                elif text[j] == "\n" and c != "`":
                    break
                j += 1
            if j >= n or text[j] != c:
                errors += 1
            i = j + 1
            continue
        if text.startswith("//", i):
            eol = text.find("\n", i)
            i = n if eol == -1 else eol
            continue
        if text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = n if close == -1 else close + 2
            continue
        if c in _OPENERS:
            stack.append(c)
        elif c in _PAIRS:
            if stack and stack[-1] == _PAIRS[c]:
                stack.pop()
            else:
                errors += 1
        i += 1
    return errors + len(stack)


_VBS_REM_RE = re.compile(r"[ \t]*rem(?:[ \t]|$)", re.IGNORECASE | re.MULTILINE)


def _vbs_errors(text: str) -> int:
    """Over the whole text, not line by line: a folded Chr(10) puts a real
    newline inside a string, and a ` _` continuation carries parentheses
    over to the next line. Comments (' and Rem) run to the end of the line."""
    errors = 0
    depth = 0
    i, n = 0, len(text)
    line_start = True
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            if j >= n:
                errors += 1
            i = j + 1
            line_start = False
            continue
        if c == "'" or (line_start and _VBS_REM_RE.match(text, i)):
            eol = text.find("\n", i)
            i = n if eol == -1 else eol
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            if depth:
                depth -= 1
            else:
                errors += 1
        if c in "\n:":
            line_start = True
        elif c not in " \t":
            line_start = False
        i += 1
    return errors + depth


_COUNTERS = {
    Lang.POWERSHELL: _ps_errors,
    Lang.TEXT: _ps_errors,
    Lang.UNKNOWN: _ps_errors,
    Lang.JAVASCRIPT: _js_errors,
    Lang.VBSCRIPT: _vbs_errors,
}


@lru_cache(maxsize=16)
def structural_errors(text: str, language: str) -> int | None:
    """Unbalanced brackets plus unterminated strings, or None where the
    language has no bracket structure worth checking (batch, binary).

    Cached: a pass's output is the next pass's input, so each text is
    otherwise scanned twice per pass.
    """
    counter = _COUNTERS.get(language)
    return None if counter is None else counter(text)


def parse_gate(before: str, after: str, language: str) -> GateResult:
    """No NEW structural errors: a rewrite may leave an already-broken input
    broken, but it may not break one that was whole."""
    old = structural_errors(before, language)
    if old is None:
        return GateResult("ParseGate", True, "not applicable")
    new = structural_errors(after, language)
    if new > old:
        return GateResult("ParseGate", False, f"structural errors {old} -> {new}")
    return GateResult("ParseGate", True)


# A string literal used where a number is required: as a variable's index,
# or as an operand of arithmetic other than +. Read on the skeleton, so a
# slash or a digit inside a string (a URL) is not arithmetic.
_STRING_AS_INDEX_RE = re.compile(r"\$\w+\s*\[\s*'")
_STRING_IN_ARITH_RE = re.compile(r"'\s*[*/%]\s*\d|\d\s*[*/%]\s*'")


def typed_literal_gate(before: str, after: str, language: str = Lang.POWERSHELL) -> GateResult:
    """A fold must not put a string where the context needs a number."""
    old, new = _skeleton(before, language), _skeleton(after, language)
    for pattern in (_STRING_AS_INDEX_RE, _STRING_IN_ARITH_RE):
        if len(pattern.findall(new)) > len(pattern.findall(old)):
            return GateResult("TypedLiteralGate", False, "string literal folded into a numeric context")
    return GateResult("TypedLiteralGate", True)


_MAGIC = {
    b"MZ": "pe", b"PK\x03\x04": "zip", b"%PDF": "pdf", b"\x1f\x8b": "gzip",
    b"\x7fELF": "elf", b"{\\rtf": "rtf", b"\xd0\xcf\x11\xe0": "ole",
}
MIN_PRINTABLE_RATIO = 0.85


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return good / len(text)


def known_magic(data: bytes) -> str | None:
    for magic, name in _MAGIC.items():
        if data.startswith(magic):
            return name
    return None


def decoded_content_gate(content: str | bytes) -> GateResult:
    """A decoded stage must read as text, or start with a known file magic.

    Anything else is the decoder guessing: Base64 that was really an
    identifier, a key, or ciphertext, rendered as mojibake.
    """
    if isinstance(content, bytes):
        magic = known_magic(content)
        if magic:
            return GateResult("DecodedContentGate", True, f"binary ({magic})")
        try:
            content = content.decode("utf-8")
        except UnicodeDecodeError:
            return GateResult("DecodedContentGate", False, "undecodable bytes with no known magic")
    if not content.strip():
        return GateResult("DecodedContentGate", False, "empty stage")
    ratio = printable_ratio(content)
    if ratio < MIN_PRINTABLE_RATIO:
        return GateResult("DecodedContentGate", False, f"printable ratio {ratio:.2f}")
    return GateResult("DecodedContentGate", True)


# Complexity: what is still encoded, plus the operators that build strings.
_DASHES = str.maketrans({"–": "-", "—": "-", "―": "-"})
_OPERATOR_RE = re.compile(
    r"""['"]\s*\+\s*['"]"""                        # literal + literal
    r"|-join\b|-split\b|-replace\b|-bxor\b|-f\b"
    r"|\[char\]|fromCharCode|\bChrW?\$?\s*\("
    r"|[A-Za-z0-9]`[A-Za-z0-9]"                    # backtick inside a word
    r"|%\w+:~-?\d|!\w+:~-?\d"                      # batch substring
    r"|\w\^\w",                                    # caret inside a word
    re.IGNORECASE,
)
# The scheduler also counts work still to be done on a literal: indexing it,
# calling a method on it, a static call. Folding one of those may expose a
# `+` next to the result, which is progress, not new obfuscation.
_ROUND_OPERATOR_RE = re.compile(
    _OPERATOR_RE.pattern + r"""|['"]\s*\[\s*-?\d|['"]\s*\.\s*\w+\s*\(|\]::\w+""",
    re.IGNORECASE,
)
_ENCODED_RUN_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _entropy(run: str) -> float:
    total = len(run)
    return -sum((k / total) * math.log2(k / total) for k in Counter(run).values())


_JS_STRING_RE = re.compile(r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'")
_VBS_STRING_RE = re.compile(r"\"(?:\"\"|[^\"\n])*\"")


def _skeleton(text: str, language: str) -> str:
    """The text with every string literal's contents removed, quotes kept.

    Operators are counted in code, not in data: a decoded value that happens
    to contain "-join", or an escape like `0 inside a double-quoted string, is
    not obfuscation.
    """
    if language in Lang.PS_LIKE:
        from .PlagDeobfus import _find_string_spans
        out, last = [], 0
        for start, end in _find_string_spans(text):
            out.append(text[last:start])
            out.append(text[start] * 2)
            last = end
        out.append(text[last:])
        return "".join(out)
    if language == Lang.JAVASCRIPT:
        return _JS_STRING_RE.sub(lambda m: m.group(0)[0] * 2, text)
    if language == Lang.VBSCRIPT:
        return _VBS_STRING_RE.sub('""', text)
    return text


@lru_cache(maxsize=16)
def operator_count(text: str, language: str = Lang.POWERSHELL) -> int:
    """String-building operations in code (not in string data). The scheduler's
    complexity rule: a round of pure folding must not raise this."""
    return len(_ROUND_OPERATOR_RE.findall(_skeleton(text.translate(_DASHES), language)))


@lru_cache(maxsize=16)
def complexity(text: str, language: str = Lang.POWERSHELL) -> int:
    """Characters still in long encoded runs (each distinct run once), plus
    ten per string-building operator in code. Lower is more readable. A
    metric for reports and evaluation; the scheduler's rule uses only the
    operator count, since joining a split Base64 string legitimately makes
    one long encoded run out of two short ones."""
    flat = text.translate(_DASHES)
    runs = {m.group(0) for m in _ENCODED_RUN_RE.finditer(flat)}
    encoded = sum(len(run) for run in runs if _entropy(run) >= 4.0)
    return encoded + 10 * len(_OPERATOR_RE.findall(_skeleton(flat, language)))
