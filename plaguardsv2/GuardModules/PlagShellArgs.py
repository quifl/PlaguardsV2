"""Reading a command line the way the program on the other end reads it.

`powershell -e AAB"CC"DD` reaches powershell.exe as `-e AABCCDD`: quotes
glue argument pieces together and are then removed. Both cmd.exe and
PowerShell's native-command invocation hand arguments over like that, so a
payload split by quotes is one payload. This module finds the places where
one shell hands a script to another and says what that script is.

Every reading is bounded: an argument never runs past the string literal
that contains the command line (`-ArgumentList "-enc ..."`), nor past the
end of the command it belongs to (`;`, `|`, `&`, a newline). Reading past
either used to swallow the closing quote, and with it the next stage.

Reading only; nothing is executed.
"""
from __future__ import annotations

import base64
import bisect
import re
from dataclasses import dataclass

from . import PlagScan
from .PlagArtifact import MARKER_SLOT, ChildSpec, Edge
from .PlagPassApi import PassResult, Record, child_token
from .regex_utils import abbreviated_flag

MARKER_ONLY_RE = re.compile("^\\s*(?:(?:<<layer \\d+>>|\u27e6[\u2580-\u259f]*\\d+\u27e7)\\s*)+$")
MIN_STAGE_CHARS = 3

# powershell.exe reads the en dash, em dash, horizontal bar and `/` as `-` too.
_DASH = "[-–—―/]"
_ENC_FLAG_RE = re.compile(
    rf"(?<![\w/-]){_DASH}(?:ec|{abbreviated_flag('encodedcommand')})(?=[ \t\"'])", re.IGNORECASE)
# The executable name alone: a path before it ends in \ or /, which the
# lookbehind admits. An optional greedy path prefix made the scan quadratic.
_SHELL_EXE = r"(?:power" r"shell|pwsh)(?:\.exe)?"
_PS_INVOCATION_RE = re.compile(rf"(?<![\w.-]){_SHELL_EXE}(?![\w.-])", re.IGNORECASE)
_COMMAND_FLAG_RE = re.compile(rf"(?<![\w/-]){_DASH}{abbreviated_flag('command')}(?=[ \t\"'])", re.IGNORECASE)
# After -File the remaining arguments belong to that script, not to a -Command.
_FILE_FLAG_RE = re.compile(rf"(?<![\w/-]){_DASH}(?:f|fi|fil|file)(?=[ \t\"'])", re.IGNORECASE)
_B64_BODY_RE = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")


@dataclass
class ShellStage:
    start: int          # the span a child token replaces
    end: int
    content: str
    detail: str
    language: str = "powershell"
    inherit: dict | None = None
    prefix: str = ""    # parent text shown before the layer marker
    suffix: str = ""    # and after it


def usable(content: str) -> bool:
    return len(content.strip()) >= MIN_STAGE_CHARS and not MARKER_ONLY_RE.match(content)


def build_result(text: str, stages, label: str, edge: str = Edge.HANDOFF) -> PassResult:
    """One child token per stage, covering exactly the stage's span; a stage
    overlapping one already taken is skipped. The scheduler swaps the token for
    the stage's replacement (with the layer marker) or, if the child is refused,
    for the original span, so a refusal leaves the parent byte-identical."""
    stages = sorted((s for s in stages if usable(s.content)), key=lambda s: s.start)
    pieces, children, last = [], [], 0
    for stage in stages:
        if stage.start < last:
            continue
        pieces.append(text[last:stage.start])
        pieces.append(child_token(len(children)))
        children.append(ChildSpec(language=stage.language, content=stage.content, edge=edge,
                                  detail=stage.detail, source_span=text[stage.start:stage.end],
                                  template=stage.prefix + MARKER_SLOT + stage.suffix,
                                  inherit=stage.inherit))
        last = stage.end
    if not children:
        return PassResult()
    pieces.append(text[last:])
    return PassResult("".join(pieces), children=children,
                      records=[Record(label, f"{len(children)} stage(s)")])


def skip_blanks(text: str, i: int, limit: int | None = None) -> int:
    limit = len(text) if limit is None else limit
    while i < limit and text[i] in " \t":
        i += 1
    return i


def container(regions, pos: int):
    """The string-literal region (start, end) strictly containing `pos`, if any."""
    if not regions:
        return None
    k = bisect.bisect_right(regions, (pos, float("inf"))) - 1
    if k >= 0 and regions[k][0] < pos < regions[k][1]:
        return regions[k]
    return None


def _inner_end(text: str, region) -> int:
    """Where a region's content stops: before its closing quote."""
    start, end = region
    return end - 1 if end - start >= 2 and text[end - 1] == text[start] else end


def read_native_arg(text: str, i: int, limit: int) -> tuple[str, int]:
    """One argument from `i`: text and double-quoted sections glued together,
    quotes removed, ending at whitespace or a separator outside quotes, and
    never past `limit`. Returns (value, end)."""
    out: list[str] = []
    quoted = False
    while i < limit:
        c = text[i]
        if c == '"':
            quoted = not quoted
            i += 1
            continue
        if c == "\n" or (not quoted and c in " \t;|&"):
            break
        out.append(c)
        i += 1
    return "".join(out), i


class _Ends:
    """Positions of command separators outside string literals, so finding
    where any command ends is a binary search instead of a rescan."""

    def __init__(self, text: str, regions, separators: str):
        self.size = len(text)
        pattern = re.compile("[" + re.escape(separators) + "]")
        self.positions = [m.start() for m in pattern.finditer(text) if container(regions, m.start()) is None]

    def after(self, pos: int) -> int:
        k = bisect.bisect_left(self.positions, pos)
        return self.positions[k] if k < len(self.positions) else self.size


def _mostly_ascii(text: str) -> bool:
    """Script text is mostly ASCII whatever its strings say; bytes that were
    never UTF-16 decode as a run of CJK ideographs instead."""
    visible = [c for c in text if not c.isspace()]
    return bool(visible) and sum(1 for c in visible if ord(c) < 128) * 2 >= len(visible)


def _decode_utf16(b64: str) -> str | None:
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
    except Exception:
        return None
    for codec in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(codec)
        except UnicodeDecodeError:
            continue
        if _mostly_ascii(text):
            return text
    return None


def _next_element(text: str, region, regions):
    """`-ArgumentList '-enc','<value>'`: the literal after the comma that
    follows `region`, as (content_start, content_end, value)."""
    i = skip_blanks(text, region[1])
    if i >= len(text) or text[i] != ",":
        return None
    i = skip_blanks(text, i + 1)
    k = bisect.bisect_left(regions, (i, -1))
    if k >= len(regions) or regions[k][0] != i:
        return None
    start, end = regions[k]
    if end - start < 2 or text[end - 1] != text[start]:
        return None
    value = text[start + 1:end - 1]
    return start + 1, end - 1, value.replace("''", "'") if text[start] == "'" else value


def _limit_for(text: str, pos: int, regions, bound: int | None, ends: _Ends) -> int:
    inside = container(regions, pos)
    if inside is not None:
        return _inner_end(text, inside)
    end = ends.after(pos)
    return end if bound is None else min(end, bound)


def encoded_commands(text: str, regions=None, ps_literals: bool = False, bound: int | None = None,
                     separators: str = ";|\n") -> list[ShellStage]:
    """Every -EncodedCommand argument that decodes to text. Only the argument
    is replaced; the flag stays as the sample wrote it."""
    stages: list[ShellStage] = []
    ends = None
    consumed = 0
    for m in _ENC_FLAG_RE.finditer(text, 0, bound if bound is not None else len(text)):
        if m.start() < consumed:
            continue        # inside the argument of an earlier flag: text, not a flag
        ends = ends or _Ends(text, regions, separators)
        limit = _limit_for(text, m.start(), regions, bound, ends)
        start = skip_blanks(text, m.end(), limit)
        inside = container(regions, m.start())
        if start >= limit:
            element = _next_element(text, inside, regions) if ps_literals and inside else None
            if element is None:
                continue
            start, end, value = element
        elif ps_literals and text[start] == "'" and inside is None:
            end = min(PlagScan.literal_end(text, start), limit)
            value = text[start + 1:end - 1].replace("''", "'")
        else:
            value, end = read_native_arg(text, start, limit)
            value = value.strip("'")
        consumed = end
        value = "".join(value.split())
        if not _B64_BODY_RE.match(value):
            continue
        decoded = _decode_utf16(value)
        if decoded is None or not decoded.strip():
            continue
        stages.append(ShellStage(start, end, decoded, "-EncodedCommand"))
    return stages


def _command_text(text: str, start: int, limit: int, ps_literals: bool):
    """The script a -Command flag hands over: (content_start, content_end, script)."""
    start = skip_blanks(text, start, limit)
    if start >= limit:
        return None
    c = text[start]
    if c == '"':
        j = start + 1
        out = []
        while j < limit:
            if text[j] == "\\" and j + 1 < limit and text[j + 1] == '"':
                out.append('"')
                j += 2
                continue
            if text[j] == '"':
                if j + 1 < limit and text[j + 1] == '"':
                    out.append('"')
                    j += 2
                    continue
                break
            if text[j] == "\n":
                break
            out.append(text[j])
            j += 1
        return start + 1, j, "".join(out)
    if c == "'" and ps_literals:
        end = min(PlagScan.literal_end(text, start), limit)
        return start + 1, max(start + 1, end - 1), text[start + 1:end - 1].replace("''", "'")
    if c == "{":
        return None   # a script block is already inline code
    end = limit
    while end > start and text[end - 1] in " \t":
        end -= 1
    return start, end, text[start:end]


def command_strings(text: str, regions=None, ps_literals: bool = False, bound: int | None = None,
                    separators: str = ";|\n") -> list[ShellStage]:
    """`powershell ... -Command <script>`: the script, as a child stage. The
    flag must belong to that invocation: before the end of its command and
    before any -File, whose remaining arguments are the file's."""
    stages: list[ShellStage] = []
    ends = None
    flags = files = None
    consumed = 0
    for inv in _PS_INVOCATION_RE.finditer(text, 0, bound if bound is not None else len(text)):
        if inv.start() < consumed:
            continue        # inside a script already taken: that layer reads it
        if flags is None:
            # Every flag position once, so each invocation is a binary search.
            ends = _Ends(text, regions, separators)
            flags = [(m.start(), m.end()) for m in _COMMAND_FLAG_RE.finditer(text)]
            files = [m.start() for m in _FILE_FLAG_RE.finditer(text)]
        limit = _limit_for(text, inv.start(), regions, bound, ends)
        k = bisect.bisect_left(flags, (inv.end(), 0))
        if k >= len(flags) or flags[k][0] >= limit:
            continue
        flag_start, flag_end = flags[k]
        f = bisect.bisect_left(files, inv.end())
        if f < len(files) and files[f] < flag_start:
            continue
        inside = container(regions, flag_start)
        if inside is not None:
            # `-ArgumentList "-c ..."`: the script ends where that string does.
            limit = min(limit, _inner_end(text, inside))
        found = _command_text(text, flag_end, limit, ps_literals and inside is None)
        if found is None and ps_literals and inside is not None and skip_blanks(text, flag_end, limit) >= limit:
            found = _next_element(text, inside, regions)
        if found is None:
            continue
        cstart, cend, script = found
        consumed = cend
        if len(script.strip()) < 2:
            continue
        stages.append(ShellStage(cstart, cend, script, "-Command"))
    return stages


_SHELL_HINT_RE = re.compile(_SHELL_EXE, re.IGNORECASE)


def dq_regions(text: str) -> list[tuple[int, int]]:
    """Double-quoted sections of a command line, as cmd.exe and
    CommandLineToArgv see them; an unclosed quote runs to the end."""
    regions, start = [], None
    for i, c in enumerate(text):
        if c == '"':
            if start is None:
                start = i
            else:
                regions.append((start, i + 1))
                start = None
    if start is not None:
        regions.append((start, len(text)))
    return regions


def in_literals(text: str, spans, unquote, requote) -> list[ShellStage]:
    """PowerShell stages in command lines held by string literals of another
    language (`sh.Run "powershell -enc ..."`). Each literal is decoded and read
    as a command line. Where the literal has no escapes the stage covers just
    the argument; otherwise the whole literal is rewritten around the marker."""
    stages: list[ShellStage] = []
    for start, end in spans:
        raw = text[start:end]
        if end - start < 2 or not _SHELL_HINT_RE.search(raw):
            continue
        value = unquote(raw)
        if not isinstance(value, str):
            continue
        regions = dq_regions(value)
        found = [*encoded_commands(value, regions, separators="&|\n"),
                 *command_strings(value, regions, separators="&|\n")]
        found.sort(key=lambda st: st.start)
        if raw[1:-1] == value:
            for st in found:
                stages.append(ShellStage(start + 1 + st.start, start + 1 + st.end, st.content, st.detail))
        elif found:
            st = found[0]
            quote = raw[0]
            stages.append(ShellStage(start, end, st.content, st.detail,
                                     prefix=quote + requote(value[:st.start], quote),
                                     suffix=requote(value[st.end:], quote) + quote))
    return stages
