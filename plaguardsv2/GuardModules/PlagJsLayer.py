"""JavaScript for the layered pipeline: code held in strings becomes a layer,
and a few literal-only expressions are folded.

`eval("...")`, `new Function("...")` and a string given to setTimeout or
setInterval are all code an engine would compile; once the string is a
literal it is that code, opened as its own layer. `obj['name']` reads as
`obj.name`, `"abc"[1]` as `"b"` and `"a".concat("b")` as `"ab"`.

Everything here works from one lexer pass that knows where strings,
template literals, regular expressions and comments are, so text inside any
of them is never mistaken for code. Nothing is executed.
"""
from __future__ import annotations

import re

from .PlagArtifact import Lang
from .PlagPassApi import Kind, Pass, PassResult, Record
from .PlagShellArgs import ShellStage, build_result

# After these a `/` starts a regular expression; after anything else it divides.
_REGEX_AFTER_CHARS = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_AFTER_WORDS = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void",
                      "throw", "instanceof", "yield", "await"}
_IDENT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")


def _word_before(text: str, i: int) -> str:
    j = i
    while j > 0 and text[j - 1] in _IDENT_CHARS:
        j -= 1
    return text[j:i]


def _regex_end(text: str, i: int) -> int | None:
    """End of the regular-expression literal starting with the `/` at `i`."""
    j, n, in_class = i + 1, len(text), False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return None
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "/":
            j += 1
            while j < n and text[j] in _IDENT_CHARS:
                j += 1
            return j
        j += 1
    return None


# A `(` after these opens a condition: a `/` right after its `)` starts a
# regular expression (`if (x) /re/.test(s)`), not a division.
_CONDITION_WORDS = {"if", "while", "for", "with"}
_MAX_TEMPLATE_NESTING = 64


def _string_end(text: str, i: int) -> int:
    n, quote = len(text), text[i]
    j = i + 1
    while j < n and text[j] != quote and text[j] != "\n":
        j += 2 if text[j] == "\\" else 1
    return j + 1 if j < n and text[j] == quote else min(j, n)


def _template_end(text: str, i: int, depth: int = 0) -> int:
    """End of the template literal at `i`, `${...}` expressions included."""
    j, n = i + 1, len(text)
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
        elif c == "`":
            return j + 1
        elif c == "$" and text.startswith("${", j) and depth < _MAX_TEMPLATE_NESTING:
            j = _expression_end(text, j + 2, depth + 1)
        else:
            j += 1
    return n


def _expression_end(text: str, j: int, depth: int) -> int:
    """Just past the `}` that closes a template expression starting at `j`."""
    braces, n = 1, len(text)
    while j < n:
        c = text[j]
        if c in "'\"":
            j = _string_end(text, j)
            continue
        if c == "`":
            j = _template_end(text, j, depth)
            continue
        if c == "{":
            braces += 1
        elif c == "}":
            braces -= 1
            if braces == 0:
                return j + 1
        j += 1
    return n


def scan(text: str) -> list[tuple[str, int, int]]:
    """(kind, start, end) for every string ("str"), template literal ("tpl"),
    regular expression ("regex") and comment ("comment"), in order."""
    out: list[tuple[str, int, int]] = []
    i, n = 0, len(text)
    last = before_last = ""     # the last two significant code characters
    last_end = 0                # where the last one ended
    parens: list[bool] = []     # per open `(`: does it open a condition?
    condition_closed_at = -1    # end of the last `)` that closed a condition
    while i < n:
        c = text[i]
        if c in "'\"":
            end = _string_end(text, i)
            out.append(("str", i, end))
            i, before_last, last, last_end = end, last, c, end
            continue
        if c == "`":
            end = _template_end(text, i)
            out.append(("tpl", i, end))
            i, before_last, last, last_end = end, last, c, end
            continue
        if c == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "/":
                eol = text.find("\n", i)
                end = n if eol == -1 else eol
                out.append(("comment", i, end))
                i = end
                continue
            if nxt == "*":
                close = text.find("*/", i + 2)
                end = n if close == -1 else close + 2
                out.append(("comment", i, end))
                i = end
                continue
            if last in "+-" and last and before_last == last:
                regex_ok = False        # `i++ / 2`: a postfix operator, then division
            elif last == ")":
                regex_ok = last_end == condition_closed_at
            else:
                regex_ok = (not last or last in _REGEX_AFTER_CHARS
                            or (last in _IDENT_CHARS and _word_before(text, last_end) in _REGEX_AFTER_WORDS))
            end = _regex_end(text, i) if regex_ok else None
            if end is not None:
                out.append(("regex", i, end))
                i, before_last, last, last_end = end, last, "/", end
                continue
        if c == "(":
            k = i
            while k > 0 and text[k - 1] in " \t":
                k -= 1
            parens.append(_word_before(text, k) in _CONDITION_WORDS)
        elif c == ")" and parens and parens.pop():
            condition_closed_at = i + 1
        if not c.isspace():
            before_last, last, last_end = last, c, i + 1
        i += 1
    return out


def skeleton(text: str, tokens) -> str:
    """The text with string contents blanked (quotes kept) and regular
    expressions and comments blanked entirely. Offsets are unchanged."""
    out = list(text)
    for kind, start, end in tokens:
        lo, hi = (start + 1, end - 1) if kind in ("str", "tpl") else (start, end)
        for k in range(lo, max(lo, hi)):
            out[k] = " "
    return "".join(out)


def string_spans(text: str) -> list[tuple[int, int]]:
    """Static string literals in code: quoted strings, and template literals
    with nothing interpolated."""
    return [(s, e) for kind, s, e in scan(text)
            if kind == "str" or (kind == "tpl" and "${" not in text[s:e])]


_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v"}
_HEX2_RE = re.compile(r"[0-9A-Fa-f]{2}")
_HEX4_RE = re.compile(r"[0-9A-Fa-f]{4}")
_HEX_CP_RE = re.compile(r"\{([0-9A-Fa-f]{1,6})\}")


def unquote(literal: str) -> str:
    """The value of a JavaScript string or template literal, escapes and all."""
    terminated = len(literal) >= 2 and literal[-1] == literal[0]
    body = literal[1:-1] if terminated else literal[1:]
    out: list[str] = []
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        e = body[i + 1]
        if e in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[e])
            i += 2
        elif e == "0" and not body[i + 2:i + 3].isdigit():
            out.append("\0")
            i += 2
        elif e == "x" and _HEX2_RE.fullmatch(body, i + 2, i + 4):
            out.append(chr(int(body[i + 2:i + 4], 16)))
            i += 4
        elif e == "u" and _HEX4_RE.fullmatch(body, i + 2, i + 6):
            out.append(chr(int(body[i + 2:i + 6], 16)))
            i += 6
        elif e == "u" and (cp := _HEX_CP_RE.match(body, i + 2)) and int(cp.group(1), 16) <= 0x10FFFF:
            out.append(chr(int(cp.group(1), 16)))
            i = cp.end()
        elif e == "\r":
            i += 3 if body[i + 2:i + 3] == "\n" else 2       # line continuation
        elif e in "\n  ":
            i += 2
        else:
            out.append(e)                                     # \' \" \\ and unknown escapes
            i += 2
    value = "".join(out)
    try:
        # Join surrogate pairs written as two \u escapes.
        return value.encode("utf-16", "surrogatepass").decode("utf-16")
    except UnicodeError:
        return value


def quote(value: str, q: str = '"') -> str:
    """A JavaScript string literal for `value`, in quote `q`."""
    out = []
    for c in value:
        if c == "\\" or c == q:
            out.append("\\" + c)
        elif c == "\n":
            out.append("\\n")
        elif c == "\r":
            out.append("\\r")
        elif c == "\t":
            out.append("\\t")
        elif ord(c) < 0x20 or c in "  ":
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(c)
    return q + "".join(out) + q


# On the skeleton a literal's contents are blank, so these stay simple.
_LIT = r"\"[^\"\n]*\"|'[^'\n]*'|`[^`]*`"
_HOST = r"(?:(?:window|self|globalThis|this)\s*\.\s*)?"
_EV = "ev" "al"
_CALLS = [
    (re.compile(rf"(?<![\w$.]){_HOST}{_EV}\s*\(\s*(?P<lit>{_LIT})\s*\)"), "eval"),
    (re.compile(rf"(?<![\w$.]){_HOST}{_EV}\s*\(\s*\(\s*(?P<lit>{_LIT})\s*\)\s*\)"), "eval"),
    # Indirect eval, and eval reached through call / apply.
    (re.compile(rf"\(\s*0\s*,\s*{_HOST}{_EV}\s*\)\s*\(\s*(?P<lit>{_LIT})\s*\)"), "eval"),
    (re.compile(rf"(?<![\w$.]){_HOST}{_EV}\s*\.\s*call\s*\(\s*[^,()]*,\s*(?P<lit>{_LIT})\s*\)"), "eval"),
    (re.compile(rf"(?<![\w$.]){_HOST}{_EV}\s*\.\s*apply\s*\(\s*[^,()]*,\s*\[\s*(?P<lit>{_LIT})\s*\]\s*\)"), "eval"),
    (re.compile(rf"(?<![\w$.])(?:new\s+)?{_HOST}Function\s*\(\s*(?:(?:{_LIT})\s*,\s*)*(?P<lit>{_LIT})\s*\)"),
     "Function"),
    (re.compile(rf"(?<![\w$.]){_HOST}(?P<fn>setTimeout|setInterval)\s*\(\s*(?P<lit>{_LIT})\s*[,)]"), "timer"),
    # Internet Explorer's execScript(code[, language]).
    (re.compile(rf"(?<![\w$.]){_HOST}exec" rf"Script\s*\(\s*(?P<lit>{_LIT})\s*(?:,\s*(?P<lang>{_LIT})\s*)?\)"),
     "execScript"),
]
_ASCII_NAME_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_NOT_OBJECTS = {"return", "typeof", "case", "in", "of", "new", "delete", "void", "throw",
                "yield", "await", "else", "do", "instanceof"}


def _skip_blanks(text: str, i: int, step: int) -> int:
    while 0 <= i < len(text) and text[i] in " \t":
        i += step
    return i


class JsCodeStrings(Pass):
    id = "handoff.js"
    kind = Kind.HANDOFF
    languages = frozenset({Lang.JAVASCRIPT})
    label = "opened code passed as a string (eval / Function / timers) as its own layer"

    def apply(self, text, ctx):
        tokens = scan(text)
        skel = skeleton(text, tokens)
        literals = {s: e for kind, s, e in tokens if kind in ("str", "tpl")}
        stages = []
        for pattern, what in _CALLS:
            for m in pattern.finditer(skel):
                start, end = m.span("lit")
                if literals.get(start) != end:
                    continue
                raw = text[start:end]
                if raw[0] == "`" and "${" in raw:
                    continue
                detail = m.group("fn") if what == "timer" else what
                language = Lang.JAVASCRIPT
                if what == "execScript" and m.group("lang"):
                    named = unquote(text[m.start("lang"):m.end("lang")]).strip().lower()
                    language = Lang.VBSCRIPT if named in ("vbscript", "vbs") else Lang.JAVASCRIPT
                stages.append(ShellStage(start, end, unquote(raw), detail, language))
        if not stages:
            return PassResult()
        return build_result(text, stages, self.label)


class JsMemberAccess(Pass):
    """`obj['name']` -> `obj.name` when the name is a plain ASCII identifier.
    Reserved words count: `a.class` is valid since ES5."""

    id = "js.member"
    kind = Kind.NORMALIZE
    languages = frozenset({Lang.JAVASCRIPT})
    label = "rewrote computed member access with a literal name as dot access"

    def apply(self, text, ctx):
        edits = []
        for kind, start, end in scan(text):
            if kind != "str" or end - start < 3 or text[end - 1] != text[start]:
                continue
            name = unquote(text[start:end])
            if not _ASCII_NAME_RE.fullmatch(name):
                continue
            open_at = _skip_blanks(text, start - 1, -1)
            close_at = _skip_blanks(text, end, 1)
            if open_at < 1 or text[open_at] != "[" or close_at >= len(text) or text[close_at] != "]":
                continue
            prev = _skip_blanks(text, open_at - 1, -1)
            if prev < 0:
                continue
            if text[prev] in _IDENT_CHARS:
                word = _word_before(text, prev + 1)
                if word in _NOT_OBJECTS or word[0].isdigit():
                    continue
            elif text[prev] not in ")]":
                continue
            edits.append((open_at, close_at + 1, "." + name))
        if not edits:
            return PassResult()
        return PassResult(_apply_edits(text, edits), records=[Record(self.label, f"{len(edits)} access(es)")])


_INDEX_RE = re.compile(r"[ \t]*\[[ \t]*(\d{1,6})[ \t]*\]")
_CONCAT_RE = re.compile(rf"(?P<base>\"[^\"\n]*\"|'[^'\n]*')\s*\.\s*concat\s*\(\s*(?P<args>(?:{_LIT})(?:\s*,\s*(?:{_LIT}))*)\s*\)")


class JsLiteralFold(Pass):
    """`"abc"[1]` -> `"b"`; `"a".concat("b", "c")` -> `"abc"`. Literals only."""

    id = "js.literal_fold"
    kind = Kind.FOLD
    languages = frozenset({Lang.JAVASCRIPT})
    label = "folded JScript string indexing / concat() over literals"

    def apply(self, text, ctx):
        tokens = scan(text)
        strings = {s: e for kind, s, e in tokens if kind == "str" and e - s >= 2 and text[e - 1] == text[s]}
        edits = []
        for start, end in strings.items():
            m = _INDEX_RE.match(text, end)
            if m is None:
                continue
            value = unquote(text[start:end])
            index = int(m.group(1))
            # JavaScript indexes UTF-16 code units: only fold where those are characters.
            if index < len(value) and all(ord(c) <= 0xFFFF for c in value[:index + 1]):
                edits.append((start, m.end(), quote(value[index], text[start])))
        skel = skeleton(text, tokens)
        for m in _CONCAT_RE.finditer(skel):
            start = m.start("base")
            if strings.get(start) != m.end("base"):
                continue
            args = [(s, e) for s, e in strings.items() if m.start("args") <= s and e <= m.end("args")]
            pieces = re.findall(_LIT, skel[m.start("args"):m.end("args")])
            if len(args) != len(pieces):
                continue        # a template literal among the arguments
            value = unquote(text[start:m.end("base")]) + "".join(unquote(text[s:e]) for s, e in sorted(args))
            edits.append((start, m.end(), quote(value, text[start])))
        edits = _disjoint(edits)
        if not edits:
            return PassResult()
        return PassResult(_apply_edits(text, edits), records=[Record(self.label, f"{len(edits)} expression(s)")])


def _disjoint(edits):
    out, last = [], -1
    for start, end, value in sorted(edits):
        if start >= last:
            out.append((start, end, value))
            last = end
    return out


def _apply_edits(text: str, edits) -> str:
    out, last = [], 0
    for start, end, value in sorted(edits):
        out.append(text[last:start])
        out.append(value)
        last = end
    out.append(text[last:])
    return "".join(out)


def passes() -> list[Pass]:
    return [JsLiteralFold(), JsMemberAccess(), JsCodeStrings()]
