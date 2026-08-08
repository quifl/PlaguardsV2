"""Folds PowerShell expressions in-place using the static evaluator.

PlagEval already knows how to reduce a literal expression to its value, but
it was only ever asked about assignment right-hand sides, so the readable
script still showed the original noise. These passes push the same evaluator
over the text itself: parenthesised groups, `$(...)` subexpressions inside
double-quoted strings, and whole assignments.

Static like everything else here - the evaluator only folds literals through
pure string and array operations, and anything outside that subset comes back
Unknown and is left exactly as written.
"""
from __future__ import annotations

import re

from . import PlagEval

# A group has to look like it might reduce to something before it is worth
# handing to the evaluator; this keeps the pass off ordinary code.
MAX_GROUP_LEN = 20_000


_CONTROL_ESCAPES = {"\n": "`n", "\r": "`r", "\t": "`t", "\0": "`0", "\a": "`a", "\b": "`b"}


def _as_literal(value: str) -> str:
    """Render a resolved value as a PowerShell literal.

    Single-quoted where possible, since that is the form that cannot
    interpolate. A value carrying newlines or tabs has to be double-quoted
    with backtick escapes instead - writing the raw control character would
    silently change the script's line structure.
    """
    if not any(c in value for c in _CONTROL_ESCAPES):
        return "'" + value.replace("'", "''") + "'"

    out = value.replace("`", "``").replace('"', '`"').replace("$", "`$")
    for char, escape in _CONTROL_ESCAPES.items():
        out = out.replace(char, escape)
    return '"' + out + '"'


def _string_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges covered by string literals, so the scanners can stay
    out of them."""
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch not in "'\"":
            i += 1
            continue
        start = i
        quote = ch
        i += 1
        while i < n:
            if quote == '"' and text[i] == "`":
                i += 2
                continue
            if text[i] == quote:
                if quote == "'" and i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                i += 1
                break
            i += 1
        spans.append((start, i))
    return spans


def _in_spans(index: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= index < end for start, end in spans)


def _match_paren(text: str, open_at: int) -> int | None:
    """Index just past the ')' closing the '(' at `open_at`, ignoring
    parentheses that appear inside string literals."""
    depth = 0
    i = open_at
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"":
            quote = ch
            i += 1
            while i < n:
                if quote == '"' and text[i] == "`":
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def fold_expressions(text: str, variables: dict | None = None):
    """Replace parenthesised groups that reduce to a string with that string.

    Works right-to-left so an outer group is rewritten before the offsets of
    anything before it can shift. `variables` lets a caller supply what each
    name held at this point in the script; with none, only wholly literal
    groups fold.
    """
    variables = variables or {}
    spans = _string_spans(text)
    starts = [
        i for i, ch in enumerate(text)
        if ch == "(" and not _in_spans(i, spans)
    ]

    folded = 0
    for start in reversed(starts):
        end = _match_paren(text, start)
        if end is None or end - start > MAX_GROUP_LEN:
            continue
        # A group butted straight up against a name, a cast or a dot is
        # somebody's argument list; folding it would leave `GetString'abc'`.
        # `Write-Host (expr)` has a space, so free-standing groups still fold.
        prev = text[start - 1] if start else ""
        if prev.isalnum() or prev in "]._":
            continue
        # `@(...)` is an array literal - hand the evaluator the `@` too.
        at = start - 1 if start and text[start - 1] == "@" else start
        inner = text[at:end]
        value = PlagEval.evaluate(inner, variables)
        if not isinstance(value, str) or not value:
            continue
        literal = _as_literal(value)
        if literal == inner:
            continue
        text = text[:at] + literal + text[end:]
        folded += 1
        spans = _string_spans(text)

    if not folded:
        return text, False, ""
    return text, True, f"{folded} expression(s)"


_SUBEXPR_RE = re.compile(r"\$\(")


def fold_subexpressions(text: str):
    """Collapse `$(...)` inside double-quoted strings to its value.

    `"$([char](72))$([char](105))"` is a common way to spell a string one
    character at a time without ever writing the characters down.
    """
    folded = 0
    i = 0
    while True:
        match = _SUBEXPR_RE.search(text, i)
        if match is None:
            break
        open_at = match.end() - 1
        end = _match_paren(text, open_at)
        if end is None or end - open_at > MAX_GROUP_LEN:
            i = match.end()
            continue
        value = PlagEval.evaluate(text[open_at:end], {})
        if not isinstance(value, str):
            i = match.end()
            continue
        # Inside a double-quoted string the value is spliced in as-is; a `"`
        # or a backtick would break out of it, so those are escaped.
        inline = value.replace("`", "``").replace('"', '`"').replace("$", "`$")
        text = text[:match.start()] + inline + text[end:]
        i = match.start() + len(inline)
        folded += 1

    if not folded:
        return text, False, ""
    return text, True, f"{folded} subexpression(s)"


def fold_assignments(text: str):
    """Rewrite each statement with what it actually resolves to.

    An assignment whose expression reduces becomes `$x = '<value>'`, and any
    other statement has its parenthesised arguments folded against the
    variables in scope at that point - so a final `Write-Host` shows the line
    the script would really have printed.

    This is what turns a chain of reassignments into something an analyst can
    read straight down the page.

    The walk comes from PlagTrace rather than being reimplemented here: it
    models in-place mutations like `[Array]::Reverse($x)` that a plain
    assignment scan would miss, and missing one would mean folding a *wrong*
    value into the readable script.
    """
    from . import PlagTrace

    rewritten: list[str] = []
    folded = 0

    for statement, name, value, variables, separator in PlagTrace.walk(text):
        replacement = statement
        if name is not None and isinstance(value, str) and value:
            rebuilt = f"${name} = {_as_literal(value)}"
            if rebuilt != statement:
                replacement, folded = rebuilt, folded + 1
        elif name is None and statement:
            # Not an assignment - but its arguments may still reduce now that
            # the variables around it are known.
            reduced, changed, _detail = fold_expressions(statement, variables)
            if changed:
                replacement, folded = reduced, folded + 1
        # The script's own separators go back in: rejoining everything with
        # newlines would silently reformat the source, and the report shows
        # the as-deobfuscated text next to the reformatted one.
        rewritten.append(replacement + separator)

    if not folded:
        return text, False, ""
    return "".join(rewritten), True, f"{folded} statement(s)"
