"""Sequential variable tracking.

Walks assignments in source order, keeping each variable's current known
literal value, so reassignment chains resolve correctly:

    $dom = "example.invalid"
    $dom = "malicious." + $dom     ->  malicious.example.invalid

Everything is evaluated by PlagEval, which folds literals through pure
string/array operations only - nothing is executed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .PlagEval import UNKNOWN, evaluate, expand_double_quoted

MAX_STATEMENTS = 5000

_ASSIGN_RE = re.compile(r"^\s*\$(?:\{(?P<braced>[^}]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))\s*=(?!=)\s*(?P<expr>.+)$",
                        re.DOTALL)

# [Array]::Reverse($x) mutates its argument in place and returns nothing, so
# it has to be handled as a statement rather than as an expression value.
_ARRAY_REVERSE_RE = re.compile(
    r"^\s*\[(?:System\.)?Array\]::Reverse\(\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$",
    re.IGNORECASE,
)


@dataclass
class TraceResult:
    variables: dict = field(default_factory=dict)
    revealed_strings: list = field(default_factory=list)


def split_statements(text: str) -> list[str]:
    """The non-empty statements, stripped. See scan_statements for the form
    that keeps enough detail to put the text back together."""
    return [stripped for stripped, _sep in scan_statements(text) if stripped]


def scan_statements(text: str) -> list[tuple[str, str]]:
    """Split on ';' and newlines, but only at top level - separators inside
    quotes, brackets, parens or braces don't split.

    Returns `(stripped_statement, separator)` pairs, empty statements
    included, so a caller that rewrites statements can rejoin them with the
    script's own line structure rather than flattening it.
    """
    statements: list[tuple[str, str]] = []
    buf = []
    depth = 0
    i, n = 0, len(text)
    quote = None
    while i < n:
        c = text[i]
        if quote:
            buf.append(c)
            if quote == '"' and c == "`" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if c == quote:
                if i + 1 < n and text[i + 1] == quote:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                quote = None
            i += 1
            continue

        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue

        if c in "([{":
            depth += 1
            buf.append(c)
            i += 1
            continue
        if c in ")]}":
            depth = max(0, depth - 1)
            buf.append(c)
            i += 1
            continue

        if depth == 0 and (c == ";" or c == "\n"):
            statements.append(("".join(buf).strip(), c))
            buf = []
            i += 1
            continue

        buf.append(c)
        i += 1

    if buf:
        statements.append(("".join(buf).strip(), ""))
    return statements


def walk(text: str):
    """Step through the statements, keeping variable state as the script
    would.

    Yields `(statement, name, value, variables, separator)` per statement:
    `name`/`value` are set for an assignment we could resolve and None
    otherwise, `variables` is the state *after* the statement, and
    `separator` is the ';' or newline that followed it. Shared with PlagFold
    so the readable script and the resolved-variables table can never
    disagree about what a value was at a given point.
    """
    variables: dict = {}

    for statement, separator in scan_statements(text)[:MAX_STATEMENTS]:
        if not statement:
            yield statement, None, None, variables, separator
            continue
        rev = _ARRAY_REVERSE_RE.match(statement)
        if rev:
            # An in-place mutation: no assignment, but the value changes.
            name = rev.group("name")
            current = variables.get(name)
            if isinstance(current, list):
                variables[name] = list(reversed(current))
            elif isinstance(current, str):
                variables[name] = current[::-1]
            yield statement, None, None, variables, separator
            continue

        m = _ASSIGN_RE.match(statement)
        if m:
            name = m.group("braced") if m.group("braced") is not None else m.group("plain")
            value = evaluate(m.group("expr"), variables)
            if value is UNKNOWN:
                # Reassigned to something we can't follow - the old value is
                # no longer valid, so forget it rather than reporting stale data.
                variables.pop(name, None)
                yield statement, None, None, variables, separator
            else:
                variables[name] = value
                yield statement, name, value, variables, separator
            continue

        yield statement, None, None, variables, separator


def trace(text: str) -> TraceResult:
    """Resolve as many variables as possible, and collect any fully
    resolved double-quoted strings (these often contain the payload's real
    output, e.g. a Write-Host summary listing every C2 value)."""
    result = TraceResult()
    variables: dict = {}

    for statement, name, _value, variables, _sep in walk(text):
        if name is None and not _ASSIGN_RE.match(statement) \
                and not _ARRAY_REVERSE_RE.match(statement):
            _collect_revealed(statement, variables, result)

    result.variables = {
        k: v for k, v in variables.items()
        if isinstance(v, str) and v.strip()
    }
    return result


_DQ_BODY_RE = re.compile(r'"((?:[^"`]|`.)*)"')


def _collect_revealed(statement: str, variables: dict, result: TraceResult) -> None:
    """Pull out double-quoted strings in non-assignment statements whose
    interpolations we can fully resolve."""
    for m in _DQ_BODY_RE.finditer(statement):
        if "$" not in m.group(1):
            continue
        expanded = expand_double_quoted(m.group(1), variables)
        if expanded is UNKNOWN or not isinstance(expanded, str):
            continue
        if expanded.strip() and expanded not in result.revealed_strings:
            result.revealed_strings.append(expanded)


def enrichment_text(result: TraceResult) -> str:
    """Flatten resolved values into a plain block of text that PlagGrep can
    scan, so resolved IOCs surface as real findings.

    A resolved value is often still a stage - a Base64 blob, or a list of
    character codes. Those are decoded here too: without it a script whose
    only indicator lives one layer down reports no findings at all, even
    though the dashboard was already showing the plaintext.
    """
    from . import PlagEncode

    parts = []
    for name, value in result.variables.items():
        parts.append(f"{name} = {value}")
        payload = PlagEncode.decode_payload(str(value))
        if payload:
            parts.append(payload[1])

    for revealed in result.revealed_strings:
        parts.append(revealed)
        payload = PlagEncode.decode_payload(revealed)
        if payload:
            parts.append(payload[1])
    return "\n".join(parts)
