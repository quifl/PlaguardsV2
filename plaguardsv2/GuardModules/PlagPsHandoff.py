"""Stages one script hands to another interpreter run, opened as child layers.

The argument of Invoke-Expression, the string given to [ScriptBlock]::Create,
the -EncodedCommand or -Command of a nested powershell: each is a script in
its own right. Taken out of the parent and given its own layer, it gets the
passes for its language and its indicators are traced to it, and the parent
keeps a `<<layer N>>` marker where it was.

Only stages whose text is already a complete literal are taken; nothing is
executed or guessed.
"""
from __future__ import annotations

import re

from . import PlagDeobfus, PlagEval, PlagJsLayer, PlagScan, PlagShellArgs, PlagVbs, PlagVbsLayer
from .PlagArtifact import Lang
from .PlagPassApi import Kind, Pass, PassResult
from .PlagShellArgs import ShellStage, build_result

_HERE_RE = re.compile(r"@(?P<q>['\"])[ \t]*\r?\n(?P<body>.*?)\r?\n(?P=q)@", re.DOTALL)


def _js_requote(value: str, quote: str) -> str:
    return value.replace("\\", "\\\\").replace(quote, "\\" + quote).replace("\n", "\\n").replace("\r", "\\r")


def _vbs_requote(value: str, quote: str) -> str:
    return value.replace('"', '""')


def _shell_stages(text: str, language: str, finder) -> list[ShellStage]:
    """`finder` (encoded_commands / command_strings) over a PowerShell parent,
    or over the command lines a JScript / VBScript parent holds in strings."""
    if language in Lang.PS_LIKE:
        return finder(text, PlagDeobfus._find_string_spans(text), ps_literals=True)
    if language == Lang.JAVASCRIPT:
        stages = PlagShellArgs.in_literals(text, PlagJsLayer.string_spans(text), PlagJsLayer.unquote, _js_requote)
    elif language == Lang.VBSCRIPT:
        stages = PlagShellArgs.in_literals(text, PlagVbsLayer.code_strings(text), PlagVbs._unquote, _vbs_requote)
    else:
        return []
    wanted = "-EncodedCommand" if finder is PlagShellArgs.encoded_commands else "-Command"
    return [st for st in stages if st.detail == wanted]


class ShellEncodedHandoff(Pass):
    """`-EncodedCommand <base64>`: the decoded command becomes its own layer."""

    id = "handoff.shell.enc"
    kind = Kind.HANDOFF
    languages = Lang.PS_LIKE | {Lang.JAVASCRIPT, Lang.VBSCRIPT}
    replaces = ("legacy.ps.decode_encoded_command",)
    label = "opened -EncodedCommand stage(s) as their own layer"

    def apply(self, text, ctx):
        stages = _shell_stages(text, ctx.artifact.language, PlagShellArgs.encoded_commands)
        return build_result(text, stages, self.label)


class ShellCommandHandoff(Pass):
    """`powershell -Command "<script>"`: the script becomes its own layer."""

    id = "handoff.shell.command"
    kind = Kind.HANDOFF
    languages = Lang.PS_LIKE | {Lang.JAVASCRIPT, Lang.VBSCRIPT}
    label = "opened powershell -Command script(s) as their own layer"

    def apply(self, text, ctx):
        stages = _shell_stages(text, ctx.artifact.language, PlagShellArgs.command_strings)
        return build_result(text, stages, self.label)


_IEX = r"(?:Invoke-" r"Expression|iex)"
_IEX_RE = re.compile(rf"(?<![\w$.\-]){_IEX}(?![\w-])", re.IGNORECASE)
# -Command, abbreviated or not, with its value after a blank or a colon.
_COMMAND_PARAM_RE = re.compile(r"-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?(?![\w-])(?:\s*:)?\s*", re.IGNORECASE)
# `& (Get-Command iex) '...'`: the command looked up, then run.
_INDIRECT_IEX_RE = re.compile(
    r"&\s*\(\s*(?:Get-Command|gcm)\s+['\"]?(?:Invoke-" r"Expression|iex)['\"]?\s*\)", re.IGNORECASE)
_SCRIPTBLOCK = r"\[(?:System\.Management\.Automation\.)?Script" r"Block\]"
_SCRIPTBLOCK_RE = re.compile(_SCRIPTBLOCK + r"::Create\s*\(\s*", re.IGNORECASE)
_SCRIPTBLOCK_CAST_RE = re.compile(_SCRIPTBLOCK + r"\s*(?=['\"@])", re.IGNORECASE)
_INVOKE_SCRIPT_RE = re.compile(r"\.Invoke" r"Script\s*\(\s*", re.IGNORECASE)
_NEW_SCRIPTBLOCK_RE = re.compile(r"\.New" r"ScriptBlock\s*\(\s*", re.IGNORECASE)
# What may follow a complete argument: the end of the statement or pipeline,
# a closing bracket, or a comment.
_STATEMENT_END_RE = re.compile(r"[ \t]*(?:$|[;|})\n]|\x00CMT)")


def literal_value(text: str, start: int) -> tuple[str, int] | None:
    """(value, end) for the PowerShell string literal at `start`, if it is
    fully static: single-quoted, or double-quoted with nothing to interpolate
    and no subexpression. Here-strings count."""
    if start >= len(text):
        return None
    if text[start] == "@":
        here = _HERE_RE.match(text, start)
        if here is None:
            return None
        body = here.group("body")
        if here.group("q") == "'":
            return body, here.end()
        if "$(" in body:
            return None
        value = PlagEval.expand_double_quoted(body, {})
        return (value, here.end()) if isinstance(value, str) else None
    if text[start] not in "'\"":
        return None
    end = PlagScan.literal_end(text, start)
    if end - start < 2 or text[end - 1] != text[start]:
        return None
    if text[start] == "'":
        return PlagDeobfus._unescape_ps_string(text[start:end]), end
    body = text[start + 1:end - 1]
    # A subexpression is code run at that point; `$(1+1)` is foldable but
    # `$(whoami)` is not, and neither is a static stage.
    if "$(" in body:
        return None
    value = PlagEval.expand_double_quoted(body, {})
    if not isinstance(value, str):
        return None
    return value, end


def _skip_ws(text: str, i: int) -> int:
    while i < len(text) and text[i] in " \t":
        i += 1
    return i


def _literal_after(text: str, i: int):
    """A literal at `i`, possibly wrapped in parentheses: (start, end, value)."""
    i = _skip_ws(text, i)
    opens, first = 0, i
    while i < len(text) and text[i] == "(":
        opens += 1
        i = _skip_ws(text, i + 1)
    found = literal_value(text, i)
    if found is None:
        return None
    value, j = found
    while opens:
        j = _skip_ws(text, j)
        if j >= len(text) or text[j] != ")":
            return None
        j += 1
        opens -= 1
    return first, j, value


def _literal_before(text: str, pipe: int, by_end: dict):
    """The literal piped into the `|` at index `pipe`, possibly wrapped in
    parentheses: (start, end, value). `by_end` maps a literal's end to its span."""
    j = pipe - 1
    while j >= 0 and text[j] in " \t":
        j -= 1
    closes = 0
    while j >= 0 and text[j] == ")":
        closes += 1
        j -= 1
        while j >= 0 and text[j] in " \t":
            j -= 1
    span = by_end.get(j + 1)
    if span is None:
        return None
    start, k = span[0], span[0] - 1
    for _ in range(closes):
        while k >= 0 and text[k] in " \t":
            k -= 1
        if k < 0 or text[k] != "(":
            return None
        start, k = k, k - 1
    # The literal has to be the whole pipeline input: in `irm 'url' | iex` what
    # reaches iex is irm's output, not the literal.
    while k >= 0 and text[k] in " \t":
        k -= 1
    if k >= 0 and text[k] not in "\n;{(|=":
        return None
    found = literal_value(text, span[0])
    if found is None:
        return None
    end = span[1]
    for _ in range(closes):
        end = _skip_ws(text, end)
        if end >= len(text) or text[end] != ")":
            return None
        end += 1
    return start, end, found[0]


class IexHandoff(Pass):
    """The literal handed to Invoke-Expression (argument or pipeline input,
    called directly or through `& (Get-Command iex)`), to [ScriptBlock]::Create,
    NewScriptBlock or InvokeScript, or cast to [ScriptBlock]. The literal must
    be the whole argument: in `iex ('a' + $b)` the script is not static."""

    id = "handoff.ps.iex"
    kind = Kind.HANDOFF
    languages = Lang.PS_LIKE
    label = "opened script(s) run by Invoke-Expression / ScriptBlock as their own layer"

    def apply(self, text, ctx):
        spans = PlagDeobfus._find_string_spans(text)
        by_end = {span[1]: span for span in spans}
        stages = []
        calls = sorted([*_IEX_RE.finditer(text), *_INDIRECT_IEX_RE.finditer(text)], key=lambda m: m.start())
        for m in calls:
            if PlagDeobfus._inside_any_span(m, spans):
                continue
            after = m.end()
            param = _COMMAND_PARAM_RE.match(text, _skip_ws(text, after))
            if param:
                after = param.end()
            found = _literal_after(text, after)
            if found is not None and _STATEMENT_END_RE.match(text, found[1]):
                start, end, value = found
                stages.append(ShellStage(start, end, value, "Invoke-Expression",
                                         prefix=" " if start == m.end() else ""))
                continue
            k = m.start() - 1
            while k >= 0 and text[k] in " \t":
                k -= 1
            if k >= 0 and text[k] == "|":
                found = _literal_before(text, k, by_end)
                if found is not None:
                    start, end, value = found
                    stages.append(ShellStage(start, end, value, "Invoke-Expression (pipeline)"))
        for pattern, detail in ((_SCRIPTBLOCK_RE, "[ScriptBlock]::Create"), (_INVOKE_SCRIPT_RE, "InvokeScript"),
                                (_NEW_SCRIPTBLOCK_RE, "NewScriptBlock"), (_SCRIPTBLOCK_CAST_RE, "[ScriptBlock] cast")):
            for m in pattern.finditer(text):
                if PlagDeobfus._inside_any_span(m, spans):
                    continue
                found = literal_value(text, m.end())
                if found is None:
                    continue
                value, end = found
                # A call must close right after the literal: `Create('a' + $b)` is not static.
                # A cast binds to the literal alone.
                close = _skip_ws(text, end)
                if pattern is _SCRIPTBLOCK_CAST_RE or (close < len(text) and text[close] == ")"):
                    stages.append(ShellStage(m.end(), end, value, detail))
        if not stages:
            return PassResult()
        return build_result(text, stages, self.label)


def passes() -> list[Pass]:
    return [ShellEncodedHandoff(), ShellCommandHandoff(), IexHandoff()]
