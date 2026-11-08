"""VBScript for the layered pipeline: Execute, ExecuteGlobal and Eval run a
string as code, so once that string is a literal it is opened as its own
layer. Line continuations are joined, and `+` between two literals and the
newline constants next to a literal are folded, so a payload split across
lines or statements becomes one literal first.

Works from one lexer pass that knows where strings and comments (' and Rem)
are. A folded literal may hold a real newline; the lexer reads it as one
string. Nothing is executed.
"""
from __future__ import annotations

import re

from . import PlagVbs
from .PlagArtifact import Lang
from .PlagPassApi import Kind, Pass, PassResult, Record
from .PlagShellArgs import ShellStage, build_result

_REM_RE = re.compile(r"rem(?=[ \t]|$)", re.IGNORECASE | re.MULTILINE)


def scan(text: str) -> list[tuple[str, int, int]]:
    """(kind, start, end) for every string ("str") and comment ("comment")."""
    out: list[tuple[str, int, int]] = []
    i, n = 0, len(text)
    statement_start = True
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
            end = min(j + 1, n)
            out.append(("str", i, end))
            i, statement_start = end, False
            continue
        if c == "'" or (statement_start and _REM_RE.match(text, i)):
            eol = text.find("\n", i)
            end = n if eol == -1 else eol
            out.append(("comment", i, end))
            i = end
            continue
        if c in "\n:":
            statement_start = True
        elif c not in " \t":
            statement_start = False
        i += 1
    return out


def skeleton(text: str, tokens) -> str:
    """String contents blanked (quotes kept), comments blanked; same offsets."""
    out = list(text)
    for kind, start, end in tokens:
        lo, hi = (start + 1, end - 1) if kind == "str" else (start, end)
        for k in range(lo, max(lo, hi)):
            out[k] = " "
    return "".join(out)


def code_strings(text: str) -> list[tuple[int, int]]:
    return [(s, e) for kind, s, e in scan(text) if kind == "str"]


def _apply_edits(text: str, edits) -> str:
    out, last = [], 0
    for start, end, value in sorted(edits):
        if start < last:
            continue
        out.append(text[last:start])
        out.append(value)
        last = end
    out.append(text[last:])
    return "".join(out)


_LIT = r"\"[ ]*\""            # a literal on the skeleton
_CONTINUATION_RE = re.compile(r"[ \t]_[ \t]*\r?\n[ \t]*")


class VbsContinuation(Pass):
    """` _` at the end of a line continues the statement on the next one."""

    id = "vbs.continuation"
    kind = Kind.NORMALIZE
    languages = frozenset({Lang.VBSCRIPT})
    label = "joined VBScript line continuations"

    def apply(self, text, ctx):
        skel = skeleton(text, scan(text))
        edits = [(m.start(), m.end(), " ") for m in _CONTINUATION_RE.finditer(skel)]
        if not edits:
            return PassResult()
        return PassResult(_apply_edits(text, edits), records=[Record(self.label, f"{len(edits)} line(s)")])


_CONSTANTS = {"vbcrlf": "\n", "vbnewline": "\n", "vblf": "\n", "vbcr": "\n", "vbtab": "\t"}
_CONST = r"(?P<name>vbCrLf|vbNewLine|vbLf|vbCr|vbTab)(?![\w])"
_CONST_AFTER_RE = re.compile(rf"(?P<lit>{_LIT})[ \t]*&[ \t]*{_CONST}", re.IGNORECASE)
_CONST_BEFORE_RE = re.compile(rf"(?<![\w.]){_CONST}[ \t]*&[ \t]*(?P<lit>{_LIT})", re.IGNORECASE)
# `+` concatenates two strings; with a number on either side it adds. Fold only
# a pair that starts its expression and is not bound tighter to its right.
_PLUS_RE = re.compile(rf"(?P<a>{_LIT})[ \t]*\+[ \t]*(?P<b>{_LIT})")
_PLUS_LEFT_OK = set("=(,&:\n")
_PLUS_RIGHT_STOP_RE = re.compile(r"[ \t]*(?:[*/\\^]|mod\b)", re.IGNORECASE)


class VbsLiteralFold(Pass):
    """`"a" + "b"` -> `"ab"`, and `"a" & vbCrLf` -> a literal with the newline."""

    id = "vbs.literal_fold"
    kind = Kind.FOLD
    languages = frozenset({Lang.VBSCRIPT})
    label = "folded VBScript + concatenation and newline constants next to literals"

    def apply(self, text, ctx):
        skel = skeleton(text, scan(text))
        edits = []
        for m in _PLUS_RE.finditer(skel):
            k = m.start() - 1
            while k >= 0 and skel[k] in " \t":
                k -= 1
            if k >= 0 and skel[k] not in _PLUS_LEFT_OK:
                # After a name only as a statement's first argument (`WScript.Echo "a" + "b"`).
                word = re.search(r"[A-Za-z_]\w*$", skel[max(0, k - 40):k + 1])
                if word is None or word.group(0).lower() == "mod" or k + 1 == m.start():
                    continue
            if _PLUS_RIGHT_STOP_RE.match(skel, m.end()):
                continue
            a = PlagVbs._unquote(text[m.start("a"):m.end("a")])
            b = PlagVbs._unquote(text[m.start("b"):m.end("b")])
            edits.append((m.start(), m.end(), PlagVbs._quote(a + b)))
        for pattern, after in ((_CONST_AFTER_RE, True), (_CONST_BEFORE_RE, False)):
            for m in pattern.finditer(skel):
                value = PlagVbs._unquote(text[m.start("lit"):m.end("lit")])
                extra = _CONSTANTS[m.group("name").lower()]
                edits.append((m.start(), m.end(), PlagVbs._quote(value + extra if after else extra + value)))
        if not edits:
            return PassResult()
        new = _apply_edits(text, edits)
        if new == text:
            return PassResult()
        return PassResult(new, records=[Record(self.label, f"{len(edits)} expression(s)")])


_EXEC = "Exec" "ute"
_CALL_RE = re.compile(
    rf"(?<![\w.])(?P<fn>{_EXEC}Global|{_EXEC}|Eval)(?:[ \t]*\([ \t]*(?P<p>{_LIT})[ \t]*\)|[ \t]+(?P<s>{_LIT}))",
    re.IGNORECASE,
)
# A statement-form argument is complete only if the statement ends after it.
_STATEMENT_END_RE = re.compile(r"[ \t]*(?:$|[\n:])")


class VbsExecute(Pass):
    id = "handoff.vbs"
    kind = Kind.HANDOFF
    languages = frozenset({Lang.VBSCRIPT})
    label = "opened code run by Execute / ExecuteGlobal / Eval as its own layer"

    def apply(self, text, ctx):
        tokens = scan(text)
        skel = skeleton(text, tokens)
        strings = {s: e for kind, s, e in tokens if kind == "str"}
        stages = []
        for m in _CALL_RE.finditer(skel):
            group = "p" if m.group("p") else "s"
            start, end = m.span(group)
            if strings.get(start) != end or end - start < 2 or text[end - 1] != '"':
                continue
            if group == "s" and not _STATEMENT_END_RE.match(skel, end):
                continue        # `Execute "a" & b`: the code is not one literal
            stages.append(ShellStage(start, end, PlagVbs._unquote(text[start:end]), m.group("fn"), Lang.VBSCRIPT))
        if not stages:
            return PassResult()
        return build_result(text, stages, self.label)


def passes() -> list[Pass]:
    return [VbsContinuation(), VbsLiteralFold(), VbsExecute()]
