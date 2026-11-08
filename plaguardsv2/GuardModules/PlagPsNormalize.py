"""PowerShell spellings that PowerShell itself treats as one thing.

Typographic quotes and dashes are quotes and dashes to PowerShell's
tokenizer; `& 'iex'` is the command `iex`; `iwr` is Invoke-WebRequest.
Writing each in its plain form changes nothing about what the script does
and lets every later pass, and the analyst, read it as written.

Text rewriting only; nothing is executed.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from . import PlagDeobfus, PlagScan
from .PlagArtifact import Lang
from .PlagPassApi import Kind, Pass, PassResult, Record

# PowerShell's own character classes (CharTraits): exactly these are quotes and dashes.
_SINGLE_QUOTES = "‘’‚‛"
_DOUBLE_QUOTES = "“”„"
_DASHES = "–—―"
# Dash look-alikes PowerShell does NOT accept: flagged, never rewritten.
_LOOKALIKE_DASHES = "‒−﹘﹣－"

_QUOTE_MAP = str.maketrans({**{c: "'" for c in _SINGLE_QUOTES}, **{c: '"' for c in _DOUBLE_QUOTES}})
_DASH_MAP = str.maketrans({c: "-" for c in _DASHES})

ALIAS_FILE = Path(__file__).with_name("ps51_aliases.json")


def _outside_strings(text: str, fn) -> tuple[str, int]:
    """Apply `fn(chunk) -> (chunk, count)` to the code between string literals."""
    out, last, total = [], 0, 0
    for start, end in [*PlagDeobfus._find_string_spans(text), (len(text), len(text))]:
        chunk, count = fn(text[last:start])
        out.append(chunk)
        out.append(text[start:end])
        total += count
        last = end
    return "".join(out), total


class UnicodeNormalize(Pass):
    id = "ps.unicode"
    kind = Kind.NORMALIZE
    languages = frozenset({Lang.POWERSHELL})
    label = "normalised typographic quotes and dashes PowerShell reads as plain ones"
    # Runs before comments are masked: the masker knows only ASCII quotes, so
    # a `#` inside a curly-quoted string would otherwise be taken for a comment.
    premask = True

    def apply(self, text, ctx):
        if any(c in text for c in _LOOKALIKE_DASHES):
            ctx.artifact.flags.add("dash-lookalike-not-normalised")
        quotes = sum(text.count(c) for c in _SINGLE_QUOTES + _DOUBLE_QUOTES)
        new = text.translate(_QUOTE_MAP) if quotes else text
        dashes = 0
        if any(c in new for c in _DASHES):
            def swap(chunk):
                n = sum(chunk.count(c) for c in _DASHES)
                return (chunk.translate(_DASH_MAP), n) if n else (chunk, 0)
            new, dashes = _outside_strings(new, swap)
        if new == text:
            return PassResult()
        return PassResult(new, records=[Record(self.label, f"{quotes} quote(s), {dashes} dash(es)")])


# `& 'name'`, `& ("name")`, `. 'name'` at the start of a command.
_CALL_LITERAL_RE = re.compile(
    r"(?P<lead>(?:^|[;|({=]|&&)[ \t]*)(?P<op>[&.])[ \t]*"
    r"(?:\([ \t]*(?P<q1>['\"])(?P<n1>[A-Za-z_][\w.\-]*)(?P=q1)[ \t]*\)|(?P<q2>['\"])(?P<n2>[A-Za-z_][\w.\-]*)(?P=q2))",
    re.MULTILINE,
)


class CallOperatorLiteral(Pass):
    id = "ps.call_literal"
    kind = Kind.NORMALIZE
    languages = frozenset({Lang.POWERSHELL})
    label = "unquoted command name(s) invoked through & or ."

    def apply(self, text, ctx):
        skeleton = _skeleton(text)
        hits = 0

        def repl(m: re.Match) -> str:
            nonlocal hits
            if skeleton[m.start("op")] != m.group("op"):
                return m.group(0)       # inside a string or a comment
            hits += 1
            name = m.group("n1") or m.group("n2")
            # `. 'x'` dot-sources: it runs in the caller's scope, which `x` alone does not.
            return m.group("lead") + (". " + name if m.group("op") == "." else name)

        new = _CALL_LITERAL_RE.sub(repl, text)
        if not hits:
            return PassResult()
        return PassResult(new, records=[Record(self.label, f"{hits} call(s)")])


@lru_cache(maxsize=1)
def builtin_aliases() -> dict[str, str]:
    data = json.loads(ALIAS_FILE.read_text(encoding="utf-8"))
    return {name.lower(): target for name, target in data["aliases"].items()}


# A name at command position: line start, after ; | ( { = && or the call operator.
_COMMAND_RE = re.compile(
    r"(?P<lead>(?:^|[;|({=]|&&|&(?=[ \t]))[ \t]*)(?P<name>[A-Za-z_%?][\w\-%?]*)(?=[ \t({]|$|[;|)}])",
    re.MULTILINE,
)
_DEFINES_RE = re.compile(r"\b(?:Set-Alias|New-Alias|sal|nal)\b", re.IGNORECASE)
_ALIAS_DEF_RE = re.compile(
    r"(?:^|[;|({]|&&)[ \t]*(?:Set-Alias|New-Alias|sal|nal)[ \t]+(?:-Name[ \t]+)?['\"]?(?P<name>[\w\-]+)['\"]?"
    r"[ \t]+(?:-Value[ \t]+)?['\"]?(?P<value>[\w\-]+)['\"]?",
    re.IGNORECASE | re.MULTILINE,
)
_FUNCTION_DEF_RE = re.compile(r"\b(?:function|filter)[ \t]+(?P<name>[\w\-]+)", re.IGNORECASE)

# At a statement's start these are keywords, not the aliases of the same name.
_PIPE_ONLY = {"%", "?", "foreach", "where"}
_ASSIGNED_RE = re.compile(r"[ \t]*=")


_HERE_STRING_RE = re.compile(r"@(?P<q>['\"])[ \t]*\r?\n.*?\r?\n(?P=q)@", re.DOTALL)


_SKELETON_STOP_RE = re.compile(r"['\"#]|<#")


def _skeleton(text: str) -> str:
    """String contents and comments blanked to spaces (quotes and newlines
    kept), offsets unchanged. Here-strings first: the ordinary literal scanner
    does not know them. Comments matter even though the scheduler masks them:
    a pass can add one mid-run (a recipe note), and a name in it is not a
    command."""
    out = list(text)

    def blank(start: int, end: int) -> None:
        for i in range(start, end):
            if out[i] != "\n":
                out[i] = " "

    for m in _HERE_STRING_RE.finditer(text):
        blank(m.start() + 2, m.end() - 2)
    view = "".join(out)
    i, n = 0, len(view)
    while i < n:
        m = _SKELETON_STOP_RE.search(view, i)
        if m is None:
            break
        j = m.start()
        if view[j] in "'\"":
            end = PlagScan.literal_end(view, j)
            blank(j + 1, max(j + 1, end - 1))
        elif view.startswith("<#", j):
            close = view.find("#>", j + 2)
            end = n if close == -1 else close + 2
            blank(j, end)
        elif j == 0 or view[j - 1] in " \t\n;({|":
            eol = view.find("\n", j)
            end = n if eol == -1 else eol
            blank(j, end)
        else:
            end = j + 1             # `#` inside a word is part of it
        i = end
    return "".join(out)


_SWITCH_RE = re.compile(r"(?<![\w$-])switch\b", re.IGNORECASE)
# `class Name : Base {` / `enum Name {`: the header up to the opening brace.
_TYPE_DEF_RE = re.compile(r"(?<![\w$.-])(?:class|enum)[ \t]+[A-Za-z_]\w*[^{;\n]*\{", re.IGNORECASE)


def _body_zones(skeleton: str, opener: int) -> list[tuple[int, int]]:
    """Stretches directly inside the block whose `{` is at `opener`, nested
    blocks excluded."""
    zones: list[tuple[int, int]] = []
    depth, zone_start, j, n = 0, opener + 1, opener + 1, len(skeleton)
    while j < n:
        c = skeleton[j]
        if c == "{":
            if depth == 0:
                zones.append((zone_start, j))
            depth += 1
        elif c == "}":
            if depth == 0:
                zones.append((zone_start, j))
                break
            depth -= 1
            if depth == 0:
                zone_start = j + 1
        j += 1
    return zones


def _declaration_zones(skeleton: str) -> list[tuple[int, int]]:
    """Where a bare word declares rather than runs: a switch label, a class
    member (`sort() { }`), an enum value."""
    zones: list[tuple[int, int]] = []
    for m in _SWITCH_RE.finditer(skeleton):
        i, n, parens = m.end(), len(skeleton), 0
        while i < n and not (skeleton[i] == "{" and parens == 0):
            parens += {"(": 1, ")": -1}.get(skeleton[i], 0)
            if parens < 0:
                break
            i += 1
        if i < n and skeleton[i] == "{":
            zones += _body_zones(skeleton, i)
    for m in _TYPE_DEF_RE.finditer(skeleton):
        zones += _body_zones(skeleton, m.end() - 1)
    return zones


class AliasNormalize(Pass):
    """Built-in Windows PowerShell 5.1 aliases, and the aliases the script
    defines itself with Set-Alias / New-Alias, expanded at command position."""

    id = "ps.alias"
    kind = Kind.NORMALIZE
    languages = frozenset({Lang.POWERSHELL})
    after = ("ps.call_literal",)
    label = "expanded alias(es) to the cmdlet names they stand for"
    confidence = 0.95

    def apply(self, text, ctx):
        skeleton = _skeleton(text)
        builtins = builtin_aliases()
        shadowed = {m.group("name").lower() for m in _FUNCTION_DEF_RE.finditer(skeleton)}
        dynamic: dict[str, tuple[int, str]] = {}
        if _DEFINES_RE.search(skeleton):
            for m in _ALIAS_DEF_RE.finditer(text):
                name, value = m.group("name").lower(), m.group("value")
                target = builtins.get(value.lower(), value)
                if name in dynamic and dynamic[name][1] != target:
                    dynamic[name] = (-1, "")   # redefined: which value applies is not static
                else:
                    dynamic[name] = (m.end(), target)

        edits: list[tuple[int, int, str]] = []
        seen: dict[str, str] = {}
        zones = (_declaration_zones(skeleton)
                 if _SWITCH_RE.search(skeleton) or _TYPE_DEF_RE.search(skeleton) else [])
        for m in _COMMAND_RE.finditer(skeleton):
            raw = m.group("name")
            name = raw.lower()
            if name in shadowed:
                continue
            lead_end = m.start("name")
            lead = m.group("lead").rstrip(" \t")
            if lead.endswith("{") and m.start("lead") > 0 and skeleton[m.start("lead") - 1] == "$":
                continue        # ${name}: a variable
            if _ASSIGNED_RE.match(skeleton, m.end("name")):
                continue        # a hash-table key or property: `@{ sort = 1 }`
            if any(a <= lead_end < b for a, b in zones):
                continue        # a switch label, class member or enum value
            target = None
            if name in dynamic and dynamic[name][0] >= 0 and m.start("name") >= dynamic[name][0]:
                target = dynamic[name][1]
            elif name in builtins and (len(name) > 1 or name in _PIPE_ONLY):
                if name in _PIPE_ONLY and not m.group("lead").lstrip().startswith("|"):
                    continue
                target = builtins[name]
            if not target or target.lower() == name:
                continue
            edits.append((m.start("name"), m.end("name"), target))
            seen.setdefault(raw, target)

        if not edits:
            return PassResult()
        out, last = [], 0
        for start, end, target in edits:
            out.append(text[last:start])
            out.append(target)
            last = end
        out.append(text[last:])
        shown = ", ".join(f"{a} -> {b}" for a, b in list(seen.items())[:4])
        return PassResult("".join(out), confidence=self.confidence,
                          records=[Record(self.label, f"{len(edits)}: {shown}")])


def passes() -> list[Pass]:
    return [UnicodeNormalize(), CallOperatorLiteral(), AliasNormalize()]
