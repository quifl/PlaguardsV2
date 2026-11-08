"""Batch files read the way cmd.exe reads them, one parsing phase at a time.

The phases follow the model dbenham documented for cmd.exe, with the
substring and replace forms as SS64 lists them:

  0  a caret ending a line joins the next line; carriage returns are dropped
  1  percent expansion: %% -> %, %var%, %var:~start,len%, %var:str=repl%,
     %var:*str=repl%; an undefined variable becomes nothing in a batch file
     and stays as written on a command line (a `cmd /c` child)
  2  carets and quotes: outside quotes a caret makes the next character
     literal and is removed; & && | || ( ) split commands; < > redirect
  5  delayed expansion (!var!) when enabled, re-processing carets only on a
     command that contains a "!"
  6  CALL: quoted carets doubled, then a second percent expansion

A parenthesised block is expanded as one unit, so %var% inside it reads the
values from before the block ran. Control flow is followed conservatively:
an assignment that may not run - under IF/ELSE, after && or ||, in a pipe,
in a loop whose items are unknown, inside a GOTO loop or a CALLed label -
leaves its variable unknown rather than guessed, and lines after an
unconditional GOTO or EXIT do not run until the next label. A wrong value
presented as resolved is the failure this module exists to avoid.

Everything here is reading; no command is executed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import PlagDeobfus, PlagShellArgs
from .PlagArtifact import Lang
from .PlagPassApi import Kind, Pass, PassResult, Record

MAX_VALUE_LEN = 32_767     # cmd.exe's limit for one variable
MAX_LINE_LEN = 8_191       # cmd.exe's limit for one command line after expansion
MAX_LINES = 20_000         # lines with something on them; blank padding does not count
MAX_CALL_DEPTH = 32
MAX_FOR_ITEMS = 256

# Stock Windows values, used only when the script never sets the name itself.
WELL_KNOWN = dict(PlagDeobfus._ENV_DEFAULTS)

# Set on the victim host at run time: left exactly as written.
RUNTIME = {
    "temp", "tmp", "appdata", "localappdata", "userprofile", "username", "computername",
    "userdomain", "homedrive", "homepath", "path", "pathext", "os", "random", "date", "time",
    "cd", "errorlevel", "cmdcmdline", "cmdextversion", "systemdrive", "logonserver",
    "sessionname", "onedrive", "programw6432", "psmodulepath", "number_of_processors",
    "highestnumanodenumber", "__appdir__", "__cd__", "driverdata",
}
_RUNTIME_PREFIXES = ("programfiles", "commonprogramfiles", "processor_", "userdomain_")

_ARG_RE = re.compile(r"%(?:\*|~[A-Za-z$:]*[0-9A-Za-z]|[0-9])")
_SUBSTRING_RE = re.compile(r"~\s*(-?\d+)\s*(?:,\s*(-?\d+)\s*)?$")


class _Unknown(Exception):
    """A value cmd.exe would compute that this reading cannot."""


@dataclass
class _State:
    variables: dict = field(default_factory=dict)
    unknown: set = field(default_factory=set)
    delayed: bool = False
    stack: list = field(default_factory=list)
    command_line: bool = False
    undefined: int = 0
    defaults: set = field(default_factory=set)
    loose: int = 0
    capped: int = 0
    notes: list = field(default_factory=list)
    stages: list = field(default_factory=list)

    def forget(self, name: str) -> None:
        key = name.lower()
        self.variables.pop(key, None)
        self.unknown.add(key)

    def assign(self, name: str, value: str) -> None:
        key = name.lower()
        if value == "":
            self.variables.pop(key, None)
        else:
            self.variables[key] = value[:MAX_VALUE_LEN]
        self.unknown.discard(key)

    def view(self, snapshot: dict | None) -> "_State":
        """The state percent expansion reads: inside a block, the variables as
        they were when the block began."""
        if snapshot is None:
            return self
        return _State(variables=snapshot, unknown=set(self.unknown), command_line=self.command_line)

    def absorb(self, other: "_State") -> None:
        if other is not self:
            self.undefined += other.undefined
            self.loose += other.loose
            self.capped += other.capped
            self.defaults |= other.defaults


def _lookup(state: _State, name: str):
    key = name.lower()
    if key in state.variables:
        return state.variables[key], "set"
    if key in state.unknown:
        return None, "runtime"
    if key in WELL_KNOWN:
        state.defaults.add(name.upper())
        return WELL_KNOWN[key], "default"
    if key in RUNTIME or key.startswith(_RUNTIME_PREFIXES):
        return None, "runtime"
    return None, "undefined"


def _substring(value: str, start: int, length: int | None, state: _State) -> str:
    size = len(value)
    begin = size + start if start < 0 else start
    if begin < 0 or begin > size:
        state.loose += 1
    begin = min(max(begin, 0), size)
    if length is None:
        return value[begin:]
    end = size + length if length < 0 else begin + length
    if end < begin or end > size:
        state.loose += 1
    return value[begin:max(begin, min(end, size))]


def _replace(value: str, spec: str, state: _State) -> str:
    find, repl = spec.split("=", 1)
    through = find.startswith("*")
    if through:
        find = find[1:]
    if not find:
        return value
    if any(m.group(0) != find for m in re.finditer(re.escape(find), value, re.IGNORECASE)):
        state.loose += 1
    if through:
        at = value.lower().find(find.lower())
        return value if at == -1 else repl + value[at + len(find):]
    return re.sub(re.escape(find), lambda _m: repl, value, flags=re.IGNORECASE)


def expand_reference(body: str, state: _State) -> str | None:
    """The value of one %body% / !body! reference; None keeps it as written."""
    name, colon, op = body.partition(":")
    if not name:
        return None
    value, status = _lookup(state, name)
    if status == "runtime":
        return None
    if status == "undefined":
        if state.command_line:
            return None
        state.undefined += 1
        return ""
    if not colon:
        return value
    m = _SUBSTRING_RE.match(op)
    if m:
        return _substring(value, int(m.group(1)), int(m.group(2)) if m.group(2) else None, state)
    if "=" in op:
        return _replace(value, op, state)[:MAX_VALUE_LEN]
    return None


def percent_expand(line: str, state: _State) -> str:
    """Phase 1. A line that would exceed cmd.exe's length limit is an error in
    cmd.exe; it is left as written here."""
    out: list[str] = []
    size = 0
    i, n = 0, len(line)
    while i < n:
        j = line.find("%", i)
        if j == -1:
            out.append(line[i:])
            break
        out.append(line[i:j])
        size += j - i
        i = j
        if line.startswith("%%", i):
            piece, i = ("%" if not state.command_line else "%%"), i + 2
        else:
            arg = _ARG_RE.match(line, i)
            close = line.find("%", i + 1)
            if arg:
                piece, i = arg.group(0), arg.end()
            elif close == -1:
                # A lone percent is dropped from a batch file, kept on a command line.
                piece, i = ("%" if state.command_line else ""), i + 1
            else:
                body = line[i + 1:close]
                name, colon, _op = body.partition(":")
                if colon and name and not state.command_line and _lookup(state, name)[1] == "undefined":
                    # A batch file drops `%name:` of an undefined variable and reads on
                    # from there: `a%u:~0,1%b` is `a~0,1b`.
                    state.undefined += 1
                    piece, i = "", i + len(name) + 2
                else:
                    value = expand_reference(body, state)
                    piece, i = (line[i:close + 1] if value is None else value), close + 1
        out.append(piece)
        size += len(piece)
        if size > MAX_LINE_LEN and size > len(line):
            state.capped += 1
            return line
    return "".join(out)


def _tail(piece: str, quoted: bool) -> tuple[bool, bool]:
    """Phase 0: quote state after `piece`, and whether an unescaped caret
    outside quotes ends it (a line continuation)."""
    i, n = 0, len(piece)
    while i < n:
        c = piece[i]
        if c == '"':
            quoted = not quoted
        elif c == "^" and not quoted:
            if i == n - 1:
                return quoted, True
            i += 1
        i += 1
    return quoted, False


_SPECIAL = frozenset("&|<>()")


def caret_quote(line: str) -> tuple[str, list[tuple[int, str]]]:
    """Phase 2: the line with escapes resolved, and the position of every
    unescaped, unquoted & | < > ( ) in it."""
    if "^" not in line and '"' not in line and not any(c in _SPECIAL for c in line):
        return line, []
    out: list[str] = []
    specials: list[tuple[int, str]] = []
    quoted = False
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == '"':
            quoted = not quoted
            out.append(c)
        elif c == "^" and not quoted:
            if i + 1 < n:
                out.append(line[i + 1])
                i += 1
        else:
            if not quoted and c in _SPECIAL:
                specials.append((len(out), c))
            out.append(c)
        i += 1
    return "".join(out), specials


@dataclass
class _Cmd:
    start: int
    end: int
    op: str = ""            # separator before it: "", "&", "&&", "|", "||"
    opens: str = ""         # "group", "if", "else" or "for" when a block opens after it
    depth: int = 0          # blocks open while it was read
    conditional: bool = False
    closes: int = 0         # blocks closed right after it
    redirects: list = field(default_factory=list)


_HEADER_RE = re.compile(r"^[\s,;=@]*(?:(?P<if>if\b.*)|(?P<for>for\b.*\bdo)|(?P<else>else))\s*$",
                        re.IGNORECASE | re.DOTALL)
_TARGET_RE = re.compile(r"[ \t]*(?:&\d|\"[^\"]*\"|[^\s&|<>()]+)")


def _redirects(text: str, specials, start: int, end: int) -> list[tuple[int, int]]:
    """Each redirection inside text[start:end] (operator, stream digit and
    target), as spans relative to `start`."""
    spans: list[tuple[int, int]] = []
    covered = -1
    for pos, ch in specials:
        if ch not in "<>" or not start <= pos < end or pos < covered:
            continue
        a = pos
        if pos > start and text[pos - 1].isdigit() and (pos - 1 == start or text[pos - 2] in " \t"):
            a = pos - 1
        b = pos + 1
        if b < end and text[b] == ">":
            b += 1
        target = _TARGET_RE.match(text, b, end)
        if target:
            b = target.end()
        covered = b
        spans.append((a - start, b - start))
    return spans


def split_commands(text: str, specials, blocks: list) -> list[_Cmd]:
    """Commands of one line, in order. `blocks` is the stack of open blocks,
    carried from line to line and updated here."""
    cmds: list[_Cmd] = []
    start, op = 0, ""
    literal = 0

    def cmd(end, **kw) -> _Cmd:
        # A FOR body is not conditional in itself: the loop runs it once per
        # item, and the parser decides from the items whether that is known.
        made = _Cmd(start, end, op, depth=len(blocks),
                    conditional=any(b not in ("group", "for") for b in blocks), **kw)
        cmds.append(made)
        return made

    k = 0
    while k < len(specials):
        pos, ch = specials[k]
        if ch in "&|":
            sep = ch
            if k + 1 < len(specials) and specials[k + 1] == (pos + 1, ch):
                sep, k = ch * 2, k + 1
            cmd(pos)
            start, op = pos + len(sep), sep
        elif ch == "(":
            prefix = text[start:pos]
            head = _HEADER_RE.match(prefix) if prefix.strip(" \t,;=@") else None
            if not prefix.strip(" \t,;=@"):
                cmd(pos, opens="group")
                blocks.append("group")
                start, op = pos + 1, ""
            elif head:
                kind = "if" if head.group("if") else ("for" if head.group("for") else "else")
                cmd(pos, opens=kind)
                blocks.append(kind)
                start, op = pos + 1, ""
            else:
                literal += 1
        elif ch == ")":
            if literal:
                literal -= 1
            elif blocks:
                cmd(pos, closes=1)
                blocks.pop()
                start, op = pos + 1, ""
        k += 1
    cmd(len(text))
    for c in cmds:
        c.redirects = _redirects(text, specials, c.start, c.end)
    return cmds


# set /a: cmd.exe's integer expressions, 32-bit two's complement throughout.
_SETA_TOKEN_RE = re.compile(
    r"\s*(?:(?P<num>0[xX][0-9A-Fa-f]+|\d+)|(?P<name>[A-Za-z_$#@.][\w$#@.]*)"
    r"|(?P<op><<=|>>=|<<|>>|[-+*/%&^|]=|[-+*/%&^|~!=(),]))"
)
_ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "&=", "^=", "|=", "<<=", ">>="}


def _wrap(v: int) -> int:
    return ((v + (1 << 31)) % (1 << 32)) - (1 << 31)


def _number(text: str) -> int:
    if text[:2].lower() == "0x":
        if len(text) > 10:
            raise _Unknown
        return _wrap(int(text, 16))
    if len(text) > 1 and text[0] == "0":
        if not re.fullmatch(r"[0-7]+", text) or len(text) > 12:
            raise _Unknown
        return _wrap(int(text, 8))
    if len(text) > 10 or int(text) > 2_147_483_647:
        raise _Unknown       # cmd.exe: "Numbers are limited to 32-bits of precision"
    return int(text)


def _binary(op: str, a: int, b: int) -> int:
    if op in ("/", "%") and b == 0:
        raise _Unknown       # cmd.exe: "Divide by zero error"
    if op == "+":
        return _wrap(a + b)
    if op == "-":
        return _wrap(a - b)
    if op == "*":
        return _wrap(a * b)
    if op == "/":
        return _wrap(int(a / b))
    if op == "%":
        return _wrap(a - b * int(a / b))
    if op == "&":
        return _wrap(a & b)
    if op == "^":
        return _wrap(a ^ b)
    if op == "|":
        return _wrap(a | b)
    if op == "<<":
        return _wrap(a << (b & 31))
    if op == ">>":
        return _wrap(a >> (b & 31))
    raise _Unknown


class _SetA:
    _LEVELS = [("|",), ("^",), ("&",), ("<<", ">>"), ("+", "-"), ("*", "/", "%")]

    def __init__(self, expr: str, state: _State):
        self.state = state
        self.tokens: list[tuple[str, str]] = []
        pos = 0
        expr = expr.strip()
        while pos < len(expr):
            m = _SETA_TOKEN_RE.match(expr, pos)
            if m is None or m.end() == pos:
                raise _Unknown
            kind = m.lastgroup
            self.tokens.append((kind, m.group(kind)))
            pos = m.end()
        self.i = 0
        self.targets: list[str] = [t for idx, (k, t) in enumerate(self.tokens)
                                   if k == "name" and idx + 1 < len(self.tokens)
                                   and self.tokens[idx + 1][1] in _ASSIGN_OPS]

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else (None, None)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def run(self) -> None:
        while True:
            self.assignment()
            kind, value = self.peek()
            if value == ",":
                self.take()
                continue
            if kind is not None:
                raise _Unknown
            return

    def value_of(self, name: str) -> int:
        value, status = _lookup(self.state, name)
        if status == "undefined":
            return 0
        if status == "runtime" or value is None or not re.fullmatch(r"\s*-?(?:0[xX][0-9A-Fa-f]+|\d+)\s*", value):
            raise _Unknown
        text = value.strip()
        negative = text.startswith("-")
        number = _number(text.lstrip("-"))
        return _wrap(-number) if negative else number

    def assignment(self) -> int:
        kind, value = self.peek()
        if kind == "name" and self.i + 1 < len(self.tokens) and self.tokens[self.i + 1][1] in _ASSIGN_OPS:
            name = value
            self.i += 1
            op = self.take()[1]
            right = self.assignment()
            result = right if op == "=" else _binary(op[:-1], self.value_of(name), right)
            self.state.assign(name, str(result))
            return result
        return self.level(0)

    def level(self, depth: int) -> int:
        if depth == len(self._LEVELS):
            return self.unary()
        left = self.level(depth + 1)
        while self.peek()[1] in self._LEVELS[depth]:
            op = self.take()[1]
            left = _binary(op, left, self.level(depth + 1))
        return left

    def unary(self) -> int:
        kind, value = self.take()
        if value == "-":
            return _wrap(-self.unary())
        if value == "+":
            return self.unary()
        if value == "~":
            return _wrap(~self.unary())
        if value == "!":
            return 0 if self.unary() else 1
        if value == "(":
            result = self.assignment()
            while self.peek()[1] == ",":
                self.take()
                result = self.assignment()
            if self.take()[1] != ")":
                raise _Unknown
            return result
        if kind == "num":
            return _number(value)
        if kind == "name":
            return self.value_of(value)
        raise _Unknown


_LEAD_RE = re.compile(r"^[\s,;=@]*")
_WORD_RE = re.compile(r"[^\s,;=(&|<>]+")
_SET_A_RE = re.compile(r"^/a\s*(?P<expr>.*)$", re.IGNORECASE | re.DOTALL)
_SET_P_RE = re.compile(r"^/p\s*\"?(?P<name>[^=\"]+)=", re.IGNORECASE)
_FOR_RE = re.compile(
    r"^for\s+(?P<switch>/[fld]\s+|/r(?:\s+(?![%\"'])[^\s%]+)?\s+)?(?:(?P<opts>\"[^\"]*\"|'[^']*')\s+)?"
    r"%(?P<var>[A-Za-z])\s+in\s*\((?P<set>.*?)\)\s*do(?:\s+(?P<body>.*))?$",
    re.IGNORECASE | re.DOTALL,
)
_EMBEDDED_SET_RE = re.compile(r"\bset\s+(?:/[ap]\s+)?\"?(?P<name>[^=\s\"]+)\s*[-+*/%&^|<>]*=", re.IGNORECASE)
_LABEL_RE = re.compile(r"^\s*:(?!:)\s*(?P<name>[^\s:+]+)")
_COMMENT_RE = re.compile(r"^\s*(?:@?rem(?:[\s:.]|$)|::)", re.IGNORECASE)


def _assigned_names(segment: str) -> list[str]:
    return [m.group("name") for m in _EMBEDDED_SET_RE.finditer(segment)]


def _strip_spans(text: str, spans) -> str:
    out, last = [], 0
    for a, b in spans:
        out.append(text[last:a])
        last = b
    out.append(text[last:])
    return "".join(out)


def _assign(body: str, state: _State, conditional: bool, redirects=()) -> None:
    """Follow one `set` command (body starts at the word `set`)."""
    rest = body[3:].lstrip(" \t")
    offset = len(body) - len(rest)
    arith = _SET_A_RE.match(rest)
    if arith:
        expr = arith.group("expr").strip()
        expr = expr[1:-1] if len(expr) >= 2 and expr[0] == expr[-1] == '"' else expr.replace('"', "")
        try:
            calc = _SetA(expr, state)
        except _Unknown:
            for name in re.findall(r"([A-Za-z_$#@.][\w$#@.]*)\s*(?:<<|>>|[-+*/%&^|])?=(?!=)", expr):
                state.forget(name)
            return
        if conditional:
            for name in calc.targets:
                state.forget(name)
            return
        try:
            calc.run()
        except _Unknown:
            for name in calc.targets:
                state.forget(name)
        return
    prompt = _SET_P_RE.match(rest)
    if prompt:
        state.forget(prompt.group("name").lstrip())
        return
    if rest.startswith('"'):
        last = rest.rfind('"')
        inner = rest[1:last] if last > 0 else rest[1:]
    else:
        spans = [(a - offset, b - offset) for a, b in redirects if a >= offset]
        inner = _strip_spans(rest, spans) if spans else rest
    if "=" not in inner:
        return
    name, value = inner.split("=", 1)
    # Leading blanks are separators; trailing ones are part of the name.
    name = name.lstrip(" \t")
    if not name:
        return
    # A FOR variable reaches here already substituted (or the loop forgot the
    # name), so `%x` left in a value is text: `a%b`, `%E2%80%A6`, `%~dp0`.
    if conditional:
        state.forget(name)
    else:
        state.assign(name, value)


def _for_options(opts: str) -> dict:
    opts = opts[1:-1] if opts and opts[0] in "\"'" else (opts or "")
    out = {"tokens": "1", "delims": " \t", "eol": ";", "skip": 0, "usebackq": "usebackq" in opts.lower()}
    m = re.search(r"tokens=([0-9,*\-]+)", opts, re.IGNORECASE)
    if m:
        out["tokens"] = m.group(1)
    m = re.search(r"eol=(.)", opts, re.IGNORECASE)
    if m:
        out["eol"] = m.group(1)
    m = re.search(r"skip=(\d{1,6})", opts, re.IGNORECASE)
    if m:
        out["skip"] = int(m.group(1))
    m = re.search(r"delims=", opts, re.IGNORECASE)
    if m:
        rest = opts[m.end():]
        stop = re.search(r" (?=tokens=|eol=|skip=|usebackq)", rest, re.IGNORECASE)
        out["delims"] = rest[:stop.start()] if stop else rest
    return out


def _token_numbers(spec: str) -> tuple[list[int], bool] | None:
    """FOR /F's tokens= list, clamped to 1..31; None when malformed."""
    numbers: set[int] = set()
    star = spec.endswith("*")
    for part in spec.rstrip("*").split(","):
        if not part:
            continue
        m = re.fullmatch(r"(\d{1,6})(?:-(\d{1,6}))?", part)
        if m is None:
            return None
        low = int(m.group(1))
        high = int(m.group(2)) if m.group(2) else low
        numbers.update(range(max(low, 1), min(high, 31) + 1))
    return sorted(numbers), star


def for_f_tokens(line: str, options: dict) -> list[str | None] | None:
    """The values FOR /F assigns for one line, in variable order; None when
    the line is skipped."""
    spec = _token_numbers(options["tokens"])
    if spec is None:
        return None
    numbers, star = spec
    delims = options["delims"]
    pieces: list[tuple[int, int]] = []
    i, n = 0, len(line)
    while i < n:
        while i < n and line[i] in delims:
            i += 1
        if i >= n:
            break
        start = i
        while i < n and line[i] not in delims:
            i += 1
        pieces.append((start, i))
    if not pieces or (options["eol"] and line[pieces[0][0]] == options["eol"]):
        return None
    values: list[str | None] = [line[pieces[k - 1][0]:pieces[k - 1][1]] if k <= len(pieces) else None
                                for k in numbers]
    if star:
        last = numbers[-1] if numbers else 0
        values.append(line[pieces[last][0]:] if last < len(pieces) else None)
    return values


def _for_items(head: re.Match, state: _State) -> list[dict] | None:
    """What a FOR loop iterates over, as {letter: value} per iteration, or
    None when that depends on the host (files, command output)."""
    switch = (head.group("switch") or "").strip().lower()
    letter = head.group("var")
    source = head.group("set").strip()
    letters = [chr(ord(letter) + k) for k in range(32)]
    if switch.startswith("/f"):
        options = _for_options(head.group("opts") or "")
        literal, command = ("'", "`") if options["usebackq"] else ('"', "'")
        if source.startswith(command) and source.endswith(command):
            state.notes.append(Record("FOR /F over command output: recorded, not evaluated", source[:120]))
            return None
        if not (len(source) >= 2 and source.startswith(literal) and source.endswith(literal)):
            state.notes.append(Record("FOR /F over a file: recorded, not read", source[:120]))
            return None
        items = []
        for text in source[1:-1].split("\n")[options["skip"]:]:
            values = for_f_tokens(text, options)
            if values is not None:
                # A requested token the line does not have leaves its variable empty.
                items.append({letters[k]: "" if v is None else v for k, v in enumerate(values)})
        return items
    if switch.startswith("/l"):
        parts = [p for p in re.split(r"[\s,;=]+", source) if p]
        if len(parts) != 3 or not all(re.fullmatch(r"-?\d{1,9}", p) for p in parts):
            return None
        first, step, last = (int(p) for p in parts)
        if step == 0:
            return None
        values = range(first, last + (1 if step > 0 else -1), step)
        if len(values) > MAX_FOR_ITEMS:
            return None
        return [{letter: str(v)} for v in values]
    if switch:
        return None   # /d and /r walk the file system
    items = [p for p in re.findall(r'"[^"]*"|[^\s,;=]+', source)]
    if any(c in p for p in items for c in "*?") or len(items) > MAX_FOR_ITEMS:
        return None
    return [{letter: p} for p in items]


def _substitute(segment: str, item: dict) -> str:
    def swap(m: re.Match) -> str:
        tilde, letter = m.group(1), m.group(2)
        if letter not in item:
            return m.group(0)
        value = item[letter]
        return value.strip('"') if tilde else value
    return re.sub(r"%(~?)([A-Za-z])", swap, segment)


def _double_quoted_carets(text: str) -> str:
    out, quoted = [], False
    for c in text:
        if c == '"':
            quoted = not quoted
        out.append("^^" if c == "^" and quoted else c)
    return "".join(out)


_EXE = r"(?<![\w.\-])"
_CMD_C_RE = re.compile(_EXE + r"cmd(?:\.exe)?(?P<switches>(?:[ \t]+/[a-z](?::\w+)?)*?)[ \t]+/[ckr](?=[ \t\"])[ \t]*",
                       re.IGNORECASE)
_MSHTA_RE = re.compile(_EXE + r"mshta(?:\.exe)?[ \t]+", re.IGNORECASE)
_HOST_RE = re.compile(_EXE + r"(?:c|w)script(?:\.exe)?(?:[ \t]+//?\w+(?::\w+)?)*[ \t]+(?P<file>\"[^\"\n]+\"|[^ \t\n]+)",
                      re.IGNORECASE)


def _stages(segment: str, base: int, state: _State) -> None:
    """Scripts this command hands to another interpreter, as stages with
    spans in the parsed output (`base` is where the segment sits)."""
    regions = PlagShellArgs.dq_regions(segment)
    end_of = len(segment)
    for m in _CMD_C_RE.finditer(segment):
        inside = PlagShellArgs.container(regions, m.start())
        limit = PlagShellArgs._inner_end(segment, inside) if inside else end_of
        start, stop = m.end(), limit
        while stop > start and segment[stop - 1] in " \t":
            stop -= 1
        body = segment[start:stop]
        if len(body) >= 2 and body[0] == '"' and body[-1] == '"':
            start, stop, body = start + 1, stop - 1, body[1:-1]
        inherit = {"variables": dict(state.variables), "unknown": sorted(state.unknown),
                   "delayed": "/v:on" in m.group("switches").lower(), "command_line": True}
        state.stages.append((base + start, base + stop, body, Lang.BATCH, "cmd /c", inherit,
                             segment[start:stop]))
    for m in _MSHTA_RE.finditer(segment):
        start = m.end()
        quoted = start < end_of and segment[start] == '"'
        if quoted:
            close = segment.find('"', start + 1)
            start, stop = start + 1, (close if close != -1 else end_of)
        else:
            stop = end_of
            while stop > start and segment[stop - 1] in " \t":
                stop -= 1
        body = segment[start:stop]
        scheme, sep, code = body.partition(":")
        language = {"javascript": Lang.JAVASCRIPT, "vbscript": Lang.VBSCRIPT}.get(scheme.lower()) if sep else None
        if language is None:
            state.notes.append(Record("mshta run on a file or URL: recorded, not fetched", body[:120]))
            continue
        code_start = start + len(scheme) + 1
        state.stages.append((base + code_start, base + stop, code, language, f"mshta {scheme.lower()}:", None,
                             segment[code_start:stop]))
    for found in (PlagShellArgs.encoded_commands(segment, regions, separators="&|\n"),
                  PlagShellArgs.command_strings(segment, regions, separators="&|\n")):
        for st in found:
            state.stages.append((base + st.start, base + st.end, st.content, Lang.POWERSHELL, st.detail, None,
                                 segment[st.start:st.end]))
    for m in _HOST_RE.finditer(segment):
        state.notes.append(Record("script host run on a file: recorded, the file is not part of the input",
                                  m.group("file").strip('"')[:120]))


@dataclass
class _Loop:
    depth: int
    items: list | None
    conditional: bool
    body: list = field(default_factory=list)


class _Parser:
    def __init__(self, text: str, inherit: dict | None):
        self.state = _State()
        if inherit:
            self.state.variables.update(inherit.get("variables") or {})
            self.state.unknown.update(inherit.get("unknown") or ())
            self.state.delayed = bool(inherit.get("delayed"))
            self.state.command_line = bool(inherit.get("command_line"))
        lines = text.replace("\r", "").split("\n")
        cut, filled = len(lines), 0
        for k, line in enumerate(lines):
            if line.strip():
                filled += 1
                if filled > MAX_LINES:
                    cut = k
                    break
        self.physical, self.beyond = lines[:cut], lines[cut:]
        self.labels: dict[str, int] = {}
        self.assignments: list[tuple[int, str]] = []
        for idx, raw in enumerate(self.physical):
            if _COMMENT_RE.match(raw):
                continue
            label = _LABEL_RE.match(raw)
            if label:
                self.labels.setdefault(label.group("name").lower(), idx)
            for name in _assigned_names(raw):
                self.assignments.append((idx, name))
        self.blocks: list[str] = []
        self.loops: list[_Loop] = []
        self.snapshot: dict | None = None
        self.dead = False
        self.changed = 0

    # control flow

    def _forget_from(self, first: int, last: int | None = None) -> None:
        for idx, name in self.assignments:
            if idx >= first and (last is None or idx <= last):
                self.state.forget(name)

    def _control(self, kind: str, target: str, conditional: bool, idx: int) -> None:
        if kind == "goto":
            label = target.lstrip(":").lower()
            at = self.labels.get(label)
            if at is not None and at <= idx:
                self._forget_from(at, idx)     # a loop: values inside it change per pass
            if not conditional:
                self.dead = True
        elif kind == "exit" and not conditional:
            self.dead = True
        elif kind == "call":
            at = self.labels.get(target.lstrip(":").lower())
            if at is not None:
                self._forget_from(at)

    # commands

    def dispatch(self, segment: str, conditional: bool, redirects=(), depth: int = 0, base: int = -1):
        """Run one command for its effect on the variables. Returns (text, control)."""
        state = self.state
        lead = _LEAD_RE.match(segment).group(0)
        body = segment[len(lead):]
        if state.delayed and "!" in body:
            body = delayed_expand(body, state)
            redirects = ()
        word_m = _WORD_RE.match(body)
        word = word_m.group(0).lower() if word_m else ""
        text = lead + body
        if base >= 0:
            _stages(text, base, state)
        if word == "call" and depth < MAX_CALL_DEPTH:
            rest = body[word_m.end():]
            target = rest.strip()
            if target.startswith(":"):
                return text, ("call", target.split()[0], conditional)
            rest = percent_expand(_double_quoted_carets(rest), state)
            rest, _specials = caret_quote(rest)
            _inner, control = self.dispatch(rest, conditional, (), depth + 1)
            return lead + body[:word_m.end()] + rest, control
        if word in ("setlocal", "endlocal"):
            if conditional:
                return text, None
            if word == "setlocal":
                state.stack.append((dict(state.variables), set(state.unknown), state.delayed))
                opts = body.lower()
                if "enabledelayedexpansion" in opts:
                    state.delayed = True
                elif "disabledelayedexpansion" in opts:
                    state.delayed = False
            elif state.stack:
                state.variables, state.unknown, state.delayed = state.stack.pop()
            return text, None
        if word == "goto":
            target = body[word_m.end():].strip().split()
            return text, ("goto", target[0] if target else "", conditional)
        if word == "exit":
            return text, ("exit", "", conditional)
        if word == "if":
            for name in _assigned_names(body):
                state.forget(name)
            return text, None
        if word == "for":
            # A FOR the caller could not run (nested in a loop body, or a form it
            # does not read): what it assigns is unknown afterwards.
            for name in _assigned_names(body):
                state.forget(name)
            return text, None
        if word == "set" or body[:4].lower() in ("set ", "set\t", "set/") or body.lower() == "set":
            shift = len(lead)
            _assign(body, state, conditional, [(a - shift, b - shift) for a, b in redirects])
        return text, None

    def run_loop(self, loop: _Loop) -> None:
        if loop.items is None or loop.conditional:
            for segment, _cond in loop.body:
                for name in _assigned_names(segment):
                    self.state.forget(name)
            return
        for item in loop.items:
            for segment, cond in loop.body:
                self.dispatch(_substitute(segment, item), cond)

    # lines

    def parse(self) -> "Parsed":
        out: list[str] = []
        offset = 0
        i = 0
        physical = self.physical
        while i < len(physical):
            idx, raw = i, physical[i]
            i += 1
            if not raw.strip():
                out.append(raw)
                offset += len(raw) + 1
                continue
            if not _COMMENT_RE.match(raw) and _LABEL_RE.match(raw):
                self.dead = False
                out.append(raw)
                offset += len(raw) + 1
                continue
            if self.dead or _COMMENT_RE.match(raw):
                out.append(raw)
                offset += len(raw) + 1
                continue
            view = self.state.view(self.snapshot)
            parts = [percent_expand(raw, view)]
            original = raw
            quoted, cont = _tail(parts[0], False)
            while cont and i < len(physical):
                nxt = physical[i]
                original += "\n" + nxt
                i += 1
                expanded = percent_expand(nxt, view)
                parts[-1] = parts[-1][:-1]
                piece = "^" + expanded if expanded else ""
                parts.append(piece)
                quoted, cont = _tail(piece, quoted)
            self.state.absorb(view)
            text, specials = caret_quote("".join(parts))
            opened_here = not self.blocks
            if opened_here:
                before = dict(self.state.variables)
            cmds = split_commands(text, specials, self.blocks)
            line = self.execute(text, cmds, idx, offset)
            if opened_here and self.blocks:
                self.snapshot = before
            if not self.blocks:
                self.snapshot = None
            if line != original:
                self.changed += 1
            out.append(line)
            offset += len(line) + 1
        out.extend(self.beyond)
        return Parsed("\n".join(out), self.changed, self.state)

    def execute(self, text: str, cmds: list[_Cmd], idx: int, offset: int) -> str:
        pieces: list[str] = []
        last = 0
        position = 0
        inline_cond = False
        k = 0
        while k < len(cmds):
            c = cmds[k]
            between = text[last:c.start]
            pieces.append(between)
            position += len(between)
            segment = text[c.start:c.end]
            last = c.end
            conditional = c.conditional or inline_cond or c.op in ("&&", "||", "|") or \
                (k + 1 < len(cmds) and cmds[k + 1].op == "|")
            stripped = _LEAD_RE.sub("", segment)
            head = _FOR_RE.match(stripped) if stripped[:3].lower() == "for" else None
            in_loop = bool(self.loops) and c.depth >= self.loops[-1].depth
            if self.dead:
                new = segment
            elif c.opens == "for":
                items = _for_items(head, self.state) if head else None
                if in_loop:
                    self.loops[-1].body.append((segment, conditional))
                self.loops.append(_Loop(c.depth + 1, items, conditional or in_loop))
                new = segment
            elif c.opens:
                new = segment
            elif in_loop:
                self.loops[-1].body.append((segment, conditional))
                _stages(segment, offset + position, self.state)
                new = segment
            elif head is not None:
                # FOR with its DO body on this line: the rest of the line is the body.
                rest = [text[x.start:x.end] for x in cmds[k + 1:]]
                body = [head.group("body") or ""] + rest
                items = _for_items(head, self.state)
                loop = _Loop(0, items, conditional, [(b, conditional) for b in body if b.strip()])
                self.run_loop(loop)
                if items is not None and not conditional and len(items) * len(body) <= MAX_FOR_ITEMS:
                    expanded = [_substitute(b, item).strip() for item in items for b in body if b.strip()]
                    new = " & ".join(e for e in expanded if e) or segment
                    _stages(new, offset + position, self.state)
                    pieces.append(new)
                    position += len(new)
                    return "".join(pieces)
                if head.group("body"):
                    # The loop was not run, but what its body hands over is still a stage.
                    body_at = c.start + len(segment) - len(stripped) + head.start("body")
                    _stages(text[body_at:], offset + position + body_at - c.start, self.state)
                pieces.append(text[c.start:])
                return "".join(pieces)
            else:
                word = _WORD_RE.match(stripped)
                if word and word.group(0).lower() == "if":
                    inline_cond = True
                new, control = self.dispatch(segment, conditional, c.redirects, base=offset + position)
                if control is not None:
                    self._control(control[0], control[1], control[2], idx)
            pieces.append(new)
            position += len(new)
            if c.closes:
                # c was read inside the block its `)` closes, at that block's depth.
                while self.loops and self.loops[-1].depth >= c.depth:
                    self.run_loop(self.loops.pop())
            k += 1
        tail = text[last:]
        pieces.append(tail)
        return "".join(pieces)


def delayed_expand(line: str, state: _State) -> str:
    """Phase 5, for a command that contains `!` with delayed expansion on."""
    out: list[str] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == "^":
            if i + 1 < n:
                out.append(line[i + 1])
            i += 2
            continue
        if c == "!":
            close = line.find("!", i + 1)
            if close == -1:
                i += 1
                continue
            value = expand_reference(line[i + 1:close], state)
            out.append(line[i:close + 1] if value is None else value)
            i = close + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


@dataclass
class Parsed:
    text: str
    changed_lines: int
    state: _State


def parse(text: str, inherit: dict | None = None) -> Parsed:
    """Run the phases over a whole batch file. `inherit` seeds the variables,
    delayed expansion and command-line context of a `cmd /c` child."""
    return _Parser(text, inherit).parse()


class BatchParse(Pass):
    id = "batch.parse"
    kind = Kind.NORMALIZE
    languages = frozenset({Lang.BATCH})
    replaces = ("legacy.cmd.resolve_variables",)
    once = True
    label = "parsed batch expansion and escape phases (cmd.exe order)"

    def apply(self, text, ctx):
        parsed = parse(text, getattr(ctx.artifact, "inherit", None))
        state = parsed.state
        ctx.state["batch"] = (parsed.text, list(state.stages))
        notes = list(state.notes)
        if state.capped:
            notes.append(Record("line longer than cmd.exe's 8191-character limit after expansion: "
                                "left as written", f"{state.capped} line(s)"))
        if parsed.text == text:
            return PassResult(notes=notes)
        records = [Record(self.label, f"{parsed.changed_lines} line(s)")]
        assumed = False
        if state.undefined:
            records.append(Record("expanded variable(s) never set in the script to nothing "
                                  "(assumed undefined on the host)", f"{state.undefined} reference(s)", True))
            assumed = True
        if state.defaults:
            records.append(Record("used assumed stock Windows value(s)",
                                  ", ".join(sorted(state.defaults)), True))
            assumed = True
        if state.loose:
            records.append(Record("matched case-insensitively or clamped a substring "
                                  "(assumed cmd.exe semantics)", f"{state.loose} time(s)", True))
            assumed = True
        return PassResult(parsed.text, records=records, notes=notes, assumed=assumed,
                          confidence=0.75 if state.undefined else 0.9)


class BatchHandoff(Pass):
    """Scripts a batch file hands to another interpreter, found by the parser
    with each command's own boundaries: `cmd /c`, `mshta javascript:` /
    `vbscript:`, and powershell `-EncodedCommand` / `-Command`."""

    id = "handoff.batch"
    kind = Kind.HANDOFF
    languages = frozenset({Lang.BATCH})
    after = ("batch.parse",)
    label = "opened script(s) a batch file hands to another interpreter as their own layer"

    def apply(self, text, ctx):
        parsed = ctx.state.pop("batch", None)
        if parsed is None or parsed[0] != text:
            return PassResult()
        # A span is trusted only if the text there is still what the parser saw.
        stages = [PlagShellArgs.ShellStage(start, end, content, detail, language, inherit)
                  for start, end, content, language, detail, inherit, expected in parsed[1]
                  if 0 <= start <= end <= len(text) and text[start:end] == expected]
        return PlagShellArgs.build_result(text, stages, self.label)


def passes() -> list[Pass]:
    return [BatchParse(), BatchHandoff()]
