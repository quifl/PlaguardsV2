"""Static, non-executing PowerShell deobfuscation.

Every transform here is a text/regex rewrite of literal values. Nothing in
this module ever calls eval/exec or invokes PowerShell itself - the input is
always treated as untrusted text.
"""
from __future__ import annotations

import ast
import base64
import gzip
import operator
import re
import zlib
from dataclasses import dataclass, field

from . import PlagCmd, PlagEncode, PlagFold, PlagJs, PlagVbs
from .regex_utils import abbreviated_flag

MAX_PASSES = 10
MAX_INPUT_SIZE = 5_000_000
MIN_B64_TOKEN_LEN = 16

_SQ = r"'(?:[^']|'')*'"
_DQ = r'"(?:[^"`]|`.)*"'
_STR = f"(?:{_SQ}|{_DQ})"

_ENC_FLAG_RE = re.compile(
    "-" + abbreviated_flag("encodedcommand") +
    r"\s+(['\"]?)(?P<b64>[A-Za-z0-9+/]{%d,}={0,2})\1" % MIN_B64_TOKEN_LEN,
    re.IGNORECASE,
)

_ENCODING_CODECS = {
    "utf8": "utf-8",
    "unicode": "utf-16-le",
    "ascii": "ascii",
    "utf32": "utf-32-le",
    "utf7": "utf-7",
    "bigendianunicode": "utf-16-be",
    "default": "utf-8",
}

_FROMBASE64_WRAPPED_RE = re.compile(
    r"\[(?:System\.)?Text\.Encoding\]::(?P<enc>UTF8|Unicode|ASCII|UTF32|UTF7|BigEndianUnicode|Default)\s*\.\s*GetString\(\s*"
    r"\[(?:System\.)?Convert\]::FromBase64String\(\s*(?P<q>['\"])(?P<b64>[A-Za-z0-9+/=]{%d,})(?P=q)\s*\)\s*\)"
    % MIN_B64_TOKEN_LEN,
    re.IGNORECASE,
)

_FROMBASE64_PLAIN_RE = re.compile(
    r"\[(?:System\.)?Convert\]::FromBase64String\(\s*(?P<q>['\"])(?P<b64>[A-Za-z0-9+/=]{%d,})(?P=q)\s*\)"
    % MIN_B64_TOKEN_LEN,
    re.IGNORECASE,
)

_CONCAT_RE = re.compile(rf"(?P<a>{_STR})\s*\+\s*(?P<b>{_STR})")

_JOIN_ARRAY_RE = re.compile(
    rf"@?\(\s*(?P<items>{_STR}(?:\s*,\s*{_STR})*)\s*\)\s*-join\s*(?P<sep>{_STR})",
    re.IGNORECASE,
)

# The lookahead matters: matching a leading run of literal arguments and
# stopping at the first variable used to drop the `-f` and leave the rest of
# the arguments behind as a bare comma list.
_FORMAT_OP_RE = re.compile(
    rf"(?P<fmt>{_STR})\s*-f\s*(?P<args>{_STR}(?:\s*,\s*{_STR})*)\s*(?=[)\];]|\n|$)",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(r"\{(\d+)\}")

_ARITH_TOKEN = r"\d+(?:\s*[+\-*/]\s*\d+)*"

_CHAR_SINGLE_RE = re.compile(rf"\[char\]\s*(0x[0-9A-Fa-f]+|{_ARITH_TOKEN})", re.IGNORECASE)
_CHAR_PAREN_RE = re.compile(rf"\[char\]\s*\(\s*({_ARITH_TOKEN})\s*\)", re.IGNORECASE)

_CHAR_ARRAY_RE = re.compile(
    r"\[char\[\]\]\s*\(\s*(?P<codes>(?:(?:0x[0-9A-Fa-f]+|%s)\s*,\s*)*(?:0x[0-9A-Fa-f]+|%s))\s*\)"
    r"(?:\s*-join\s*(?P<sep>%s))?" % (_ARITH_TOKEN, _ARITH_TOKEN, _STR),
    re.IGNORECASE,
)

_BXOR_RE = re.compile(
    r"\[char\]\s*\(\s*(0x[0-9A-Fa-f]+|\d+)\s*-bxor\s*(0x[0-9A-Fa-f]+|\d+)\s*\)",
    re.IGNORECASE,
)

# --- $ShellId / string-indexing / variable-propagation ---------------------

_SHELLID_RE = re.compile(r"\$ShellId\b", re.IGNORECASE)
_SHELLID_VALUE = "Microsoft.PowerShell"

_STRING_INDEX_RE = re.compile(rf"({_STR})\s*\[\s*(-?\d+)\s*\]")

_ASSIGN_COUNT_RE = re.compile(r"\$(\w+)\s*[+\-*/%]?=(?!=)")
_LITERAL_ASSIGN_RE = re.compile(rf"\$(\w+)\s*=\s*({_STR})\s*(?=[;\n]|$)", re.MULTILINE)

# --- numeric-array -> char idioms (annotated, not rewritten in place) ------

_NUM_ARRAY_ELEMENT = rf"(?:\(?\s*{_ARITH_TOKEN}\s*\)?)"
_NUM_ARRAY_ASSIGN_RE = re.compile(
    rf"\$(\w+)\s*=\s*@\(\s*((?:{_NUM_ARRAY_ELEMENT}\s*,\s*)*{_NUM_ARRAY_ELEMENT})\s*\)",
    re.IGNORECASE,
)

_BYTE_ARRAY_ASSIGN_RE = re.compile(
    r"\$(\w+)\s*=\s*\[byte\[\]\]\s*@\(\s*((?:\d+\s*,\s*)*\d+)\s*\)",
    re.IGNORECASE,
)

_ALLOWED_BINOPS = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
}
_ALLOWED_UNARYOPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


@dataclass
class DeobfuscationResult:
    original: str
    deobfuscated: str
    # Same transforms, but with the input's own line structure left alone.
    # `deobfuscated` additionally runs through prettify(); a report shows both
    # so the analyst can line the result up against the original.
    deobfuscated_raw: str = ""
    pass_log: list[str] = field(default_factory=list)
    truncated: bool = False
    iterations: int = 0


def _language_passes(source: str) -> list:
    """Passes for the non-PowerShell script types this tool also accepts.

    Each is gated on a cheap sniff of the source: a `&`-concatenation folder
    turned loose on PowerShell, or `%var%` expansion applied to a log file,
    would rewrite things that only look similar.
    """
    extra = []
    if PlagVbs.looks_like_vbscript(source):
        extra += [
            ("resolved VBScript Chr() character(s)", PlagVbs.resolve_chr),
            ("folded VBScript & concatenation", PlagVbs.fold_concatenation),
            ("folded VBScript string call(s)", PlagVbs.resolve_string_calls),
            ("decoded VBScript base64 literal(s)", PlagVbs.decode_base64_literals),
            ("propagated VBScript literal variable(s)", PlagVbs.track_variables),
        ]
    if PlagJs.looks_like_script(source):
        extra += [
            ("resolved String.fromCharCode sequence(s)", PlagJs.resolve_char_codes),
            ("decoded JScript escape/atob/base64 value(s)", PlagJs.decode_encodings),
            ("folded JScript + concatenation", PlagJs.fold_concatenation),
            ("folded JScript string method chain(s)", PlagJs.fold_string_methods),
            ("propagated JScript literal variable(s)", PlagJs.track_variables),
        ]
    if PlagCmd.looks_like_batch(source):
        extra += [("expanded batch variable(s)", PlagCmd.resolve_variables)]
    return extra


def run(source: str) -> DeobfuscationResult:
    truncated = False
    text = source
    if len(text) > MAX_INPUT_SIZE:
        text = text[:MAX_INPUT_SIZE]
        truncated = True

    text = _normalize(text)
    text, comments = _mask_comments(text)
    log: list[str] = []

    passes = [
        ("propagated single-assignment literal variables", _propagate_literal_variables),
        ("resolved $ShellId (assumed default Windows PowerShell value)", _resolve_shellid),
        ("resolved literal string indexing", _resolve_string_indexing),
        ("decoded -EncodedCommand base64 (UTF-16LE)", _decode_encoded_command),
        ("decoded [Convert]::FromBase64String literal(s)", _decode_frombase64_literals),
        ("folded literal string concatenation", _fold_string_concatenation),
        ("folded -join on literal array", _fold_join_operator),
        ("folded -f format operator on literals", _fold_format_operator),
        ("resolved [char] code point(s)", _resolve_char_codes),
        ("resolved literal -bxor char code(s)", _resolve_bxor),
        ("collapsed $(...) subexpressions", PlagFold.fold_subexpressions),
        ("evaluated literal expressions", PlagFold.fold_expressions),
        ("resolved assignments to their values", PlagFold.fold_assignments),
        ("annotated XOR-encoded byte array(s)", _annotate_xor_byte_array),
        ("annotated numeric-array-to-char loop(s)", _annotate_char_array_loop),
        ("stripped junk backtick escapes", _strip_junk_backticks),
        ("stripped redundant [string] cast(s)", _strip_redundant_casts),
        ("decoded standalone encoded payload(s)", _decode_standalone_payloads),
    ]
    passes += _language_passes(source)

    iterations = 0
    for i in range(MAX_PASSES):
        iterations = i + 1
        changed_this_round = False
        for label, fn in passes:
            new_text, changed, detail = fn(text)
            if changed:
                text = new_text
                changed_this_round = True
                entry = f"Pass {i + 1}: {label}"
                if detail:
                    entry += f" ({detail})"
                log.append(entry)
        if not changed_this_round:
            break

    text = _unmask_comments(text, comments)
    raw = _final_cleanup(text)
    text = _final_cleanup(prettify(text))
    if truncated:
        log.append("Input truncated to first %d characters before analysis" % MAX_INPUT_SIZE)

    return DeobfuscationResult(
        original=source,
        deobfuscated=text,
        deobfuscated_raw=raw,
        pass_log=log,
        truncated=truncated,
        iterations=iterations,
    )


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"`\n\s*", " ", text)
    return text


_COMMENT_TOKEN_RE = re.compile(r"\x00CMT(\d+)\x00")


def _mask_comments(text: str) -> tuple[str, list[str]]:
    """Temporarily replace comment text with an inert sentinel token before
    any pass runs. Every regex-based fold below (concatenation, -join, -f,
    etc.) matches quote characters wherever they appear in the raw text -
    without this, a quote inside a comment (e.g. `# -> "Obfuscated"`) can
    pair with an unrelated quote elsewhere and cause the pass to treat real
    code in between as part of a bogus string literal, corrupting it.
    Comments are restored verbatim once every pass has finished.

    This has to be a single left-to-right scan that tracks string vs.
    comment state together (mirroring `_find_string_spans`) rather than
    reusing that helper afterwards - a comment containing a quote character
    would otherwise make quote-span detection itself misfire, which is
    exactly the bug this function exists to prevent."""
    comments: list[str] = []
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in ("'", '"'):
            quote = c
            j = i + 1
            terminated = False
            while j < n:
                if quote == '"' and text[j] == "`" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == quote:
                    if j + 1 < n and text[j + 1] == quote:
                        j += 2
                        continue
                    j += 1
                    terminated = True
                    break
                j += 1
            if not terminated:
                j = n
            out.append(text[i:j])
            i = j
        elif text[i:i + 2] == "<#":
            end = text.find("#>", i + 2)
            end = end + 2 if end != -1 else n
            comments.append(text[i:end])
            out.append(f"\x00CMT{len(comments) - 1}\x00")
            i = end
        elif c == "#":
            eol = text.find("\n", i)
            end = eol if eol != -1 else n
            comments.append(text[i:end])
            out.append(f"\x00CMT{len(comments) - 1}\x00")
            i = end
        else:
            out.append(c)
            i += 1
    return "".join(out), comments


def _unmask_comments(text: str, comments: list[str]) -> str:
    def repl(m: re.Match) -> str:
        return comments[int(m.group(1))]

    return _COMMENT_TOKEN_RE.sub(repl, text)


def _unescape_ps_string(literal: str) -> str:
    if not literal:
        return ""
    quote = literal[0]
    body = literal[1:-1]
    if quote == "'":
        return body.replace("''", "'")
    out = []
    i = 0
    escapes = {
        "n": "\n", "t": "\t", "r": "\r", "0": "\0", "a": "\a",
        "b": "\b", "f": "\f", "v": "\v", "'": "'", '"': '"',
        "`": "`", "#": "#", "$": "$",
    }
    while i < len(body):
        c = body[i]
        if c == "`" and i + 1 < len(body):
            nxt = body[i + 1]
            out.append(escapes.get(nxt, nxt))
            i += 2
            continue
        if c == '"' and i + 1 < len(body) and body[i + 1] == '"':
            out.append('"')
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _make_ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _escape_for_comment(value: str) -> str:
    """Render arbitrary decoded text as a single printable line safe to
    splice into a PowerShell comment - non-printable/control bytes (which
    could otherwise break out of the comment, e.g. a real newline) are
    shown as \\xNN escapes instead of embedded raw."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in value)


def _find_string_spans(text: str):
    spans = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in ("'", '"'):
            quote = c
            j = i + 1
            terminated = False
            while j < n:
                if quote == '"' and text[j] == "`" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == quote:
                    if j + 1 < n and text[j + 1] == quote:
                        j += 2
                        continue
                    j += 1
                    terminated = True
                    break
                j += 1
            if not terminated:
                j = n
            spans.append((i, j))
            i = j
        else:
            i += 1
    return spans


def _apply_outside_strings(text: str, transform):
    spans = _find_string_spans(text)
    if not spans:
        new = transform(text)
        return new, new != text
    parts = []
    last = 0
    changed = False
    for start, end in spans:
        outside = text[last:start]
        new_outside = transform(outside)
        if new_outside != outside:
            changed = True
        parts.append(new_outside)
        parts.append(text[start:end])
        last = end
    tail = text[last:]
    new_tail = transform(tail)
    if new_tail != tail:
        changed = True
    parts.append(new_tail)
    return "".join(parts), changed


def _b64_decode_text(b64: str) -> str | None:
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        return None
    try:
        return raw.decode("utf-16-le")
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace")


def _safe_eval_arith(expr: str) -> int | None:
    """Evaluate a simple arithmetic expression (digits, + - * /, parens
    only) without using eval() on untrusted input."""
    try:
        node = ast.parse(expr.strip(), mode="eval").body
    except SyntaxError:
        return None

    def _eval(n):
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
            return n.value
        if isinstance(n, ast.BinOp) and type(n.op) in _ALLOWED_BINOPS:
            return _ALLOWED_BINOPS[type(n.op)](_eval(n.left), _eval(n.right))
        if isinstance(n, ast.UnaryOp) and type(n.op) in _ALLOWED_UNARYOPS:
            return _ALLOWED_UNARYOPS[type(n.op)](_eval(n.operand))
        raise ValueError("disallowed expression")

    try:
        result = _eval(node)
    except Exception:
        return None
    if isinstance(result, float):
        if not result.is_integer():
            return None
        result = int(result)
    return result


# ---------------------------------------------------------------------------
# passes
# ---------------------------------------------------------------------------

def _resolve_shellid(text: str):
    count = [0]

    def transform(chunk: str) -> str:
        def repl(m: re.Match) -> str:
            count[0] += 1
            return _make_ps_literal(_SHELLID_VALUE)
        return _SHELLID_RE.sub(repl, chunk)

    new_text, changed = _apply_outside_strings(text, transform)
    return new_text, changed, (f"{count[0]} reference(s)" if count[0] else "")


def _resolve_string_indexing(text: str):
    real_spans = set(_find_string_spans(text))
    count = [0]

    def repl(m: re.Match) -> str:
        if (m.start(1), m.end(1)) not in real_spans:
            return m.group(0)
        value = _unescape_ps_string(m.group(1))
        idx = int(m.group(2))
        try:
            ch = value[idx]
        except IndexError:
            return m.group(0)
        count[0] += 1
        return _make_ps_literal(ch)

    new_text = _STRING_INDEX_RE.sub(repl, text)
    return new_text, count[0] > 0, (f"{count[0]} index(es)" if count[0] else "")


def _propagate_literal_variables(text: str):
    assign_counts: dict[str, int] = {}
    for m in _ASSIGN_COUNT_RE.finditer(text):
        assign_counts[m.group(1)] = assign_counts.get(m.group(1), 0) + 1

    literal_values: dict[str, str] = {}
    for m in _LITERAL_ASSIGN_RE.finditer(text):
        name = m.group(1)
        if assign_counts.get(name) != 1 or name in literal_values:
            continue
        literal_values[name] = _unescape_ps_string(m.group(2))

    if not literal_values:
        return text, False, ""

    names_pattern = "|".join(re.escape(n) for n in literal_values)
    ref_re = re.compile(rf"\$(?:{names_pattern})\b(?!\s*=(?!=))")

    count = [0]

    def transform(chunk: str) -> str:
        def repl(m: re.Match) -> str:
            name = m.group(0)[1:]
            count[0] += 1
            return _make_ps_literal(literal_values[name])
        return ref_re.sub(repl, chunk)

    new_text, changed = _apply_outside_strings(text, transform)
    return new_text, changed, (f"{count[0]} reference(s)" if count[0] else "")


def _annotate_xor_byte_array(text: str):
    count = [0]
    additions: list[tuple[int, str]] = []

    for m in _BYTE_ARRAY_ASSIGN_RE.finditer(text):
        var_name = m.group(1)
        try:
            byte_values = [int(v) for v in m.group(2).split(",")]
        except ValueError:
            continue

        loop_re = re.compile(
            rf"\${re.escape(var_name)}\[\s*\$\w+\s*\]\s*=\s*\${re.escape(var_name)}\[\s*\$\w+\s*\]"
            r"\s*-bxor\s*(\$(\w+)|0x[0-9A-Fa-f]+|\d+)",
            re.IGNORECASE,
        )
        loop_match = loop_re.search(text)
        if not loop_match:
            continue
        marker = f"# [PlaguardsV2] ${var_name} resolves via XOR"
        if marker in text:
            continue

        key_token, key_var = loop_match.group(1), loop_match.group(2)
        if key_var:
            key_assign = re.search(
                rf"\${re.escape(key_var)}\s*=\s*(0x[0-9A-Fa-f]+|\d+)\b", text, re.IGNORECASE
            )
            if not key_assign:
                continue
            key_token = key_assign.group(1)

        try:
            key = int(key_token, 16) if key_token.lower().startswith("0x") else int(key_token)
            decoded = bytes((b ^ key) & 0xFF for b in byte_values).decode("utf-8", errors="replace")
        except Exception:
            continue

        count[0] += 1
        display = _make_ps_literal(_escape_for_comment(decoded))
        additions.append((
            loop_match.end(),
            f"\n# [PlaguardsV2] ${var_name} resolves via XOR (key={key}) to: {display}",
        ))

    if not additions:
        return text, False, ""
    new_text = text
    for pos, annotation in sorted(additions, key=lambda x: -x[0]):
        new_text = new_text[:pos] + annotation + new_text[pos:]
    return new_text, True, (f"{count[0]} array(s)" if count[0] else "")


def _annotate_char_array_loop(text: str):
    count = [0]
    additions: list[tuple[int, str]] = []

    for m in _NUM_ARRAY_ASSIGN_RE.finditer(text):
        var_name = m.group(1)
        elements = [e.strip().strip("()").strip() for e in m.group(2).split(",")]
        values = [_safe_eval_arith(e) for e in elements]
        if any(v is None for v in values):
            continue
        try:
            decoded = "".join(chr(v) for v in values)
        except (ValueError, OverflowError):
            continue

        loop_re = re.compile(
            rf"foreach\s*\(\s*\$(\w+)\s+in\s+\${re.escape(var_name)}\s*\)\s*\{{[^{{}}]*"
            r"\[char\]\s*\$\1\b[^{}]*\}",
            re.IGNORECASE,
        )
        loop_match = loop_re.search(text)
        if not loop_match:
            continue
        marker = f"# [PlaguardsV2] ${var_name} resolves via this loop"
        if marker in text:
            continue

        count[0] += 1
        display = _make_ps_literal(_escape_for_comment(decoded))
        additions.append((
            loop_match.end(),
            f"\n{marker} to: {display}",
        ))

    if not additions:
        return text, False, ""
    new_text = text
    for pos, annotation in sorted(additions, key=lambda x: -x[0]):
        new_text = new_text[:pos] + annotation + new_text[pos:]
    return new_text, True, (f"{count[0]} loop(s)" if count[0] else "")


def _decode_encoded_command(text: str):
    count = [0]

    def repl(m: re.Match) -> str:
        decoded = _b64_decode_text(m.group("b64"))
        if decoded is None:
            return m.group(0)
        count[0] += 1
        return decoded

    new_text = _ENC_FLAG_RE.sub(repl, text)
    return new_text, count[0] > 0, (f"{count[0]} block(s)" if count[0] else "")


def _maybe_inflate(raw: bytes) -> bytes:
    """If the decoded bytes look like a compressed stream (a common way to
    shrink/obscure a staged payload before base64-encoding it), decompress
    them; otherwise return unchanged."""
    if raw[:2] == b"\x1f\x8b":
        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    try:
        return zlib.decompress(raw, -zlib.MAX_WBITS)
    except Exception:
        return raw


def _decode_frombase64_literals(text: str):
    count = [0]

    def repl_wrapped(m: re.Match) -> str:
        codec = _ENCODING_CODECS.get(m.group("enc").lower(), "utf-8")
        b64 = m.group("b64")
        try:
            padded = b64 + "=" * (-len(b64) % 4)
            raw = base64.b64decode(padded, validate=False)
            decoded = raw.decode(codec, errors="replace")
        except Exception:
            return m.group(0)
        count[0] += 1
        return _make_ps_literal(decoded)

    def repl_plain(m: re.Match) -> str:
        b64 = m.group("b64")
        try:
            padded = b64 + "=" * (-len(b64) % 4)
            raw = base64.b64decode(padded, validate=False)
        except Exception:
            return m.group(0)
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            # Doesn't look like plain UTF-8 text - it may be a compressed
            # stage (a common way to shrink/obscure a payload before
            # base64-encoding it). Try inflating it before giving up.
            inflated = _maybe_inflate(raw)
            try:
                decoded = inflated.decode("utf-8")
            except UnicodeDecodeError:
                decoded = inflated.decode("latin-1", errors="replace")
        count[0] += 1
        return _make_ps_literal(decoded)

    text = _FROMBASE64_WRAPPED_RE.sub(repl_wrapped, text)
    text = _FROMBASE64_PLAIN_RE.sub(repl_plain, text)
    return text, count[0] > 0, (f"{count[0]} literal(s)" if count[0] else "")


def _fold_string_concatenation(text: str):
    real_spans = set(_find_string_spans(text))
    count = [0]

    def repl(m: re.Match) -> str:
        if (m.start("a"), m.end("a")) not in real_spans or (m.start("b"), m.end("b")) not in real_spans:
            return m.group(0)
        a = _unescape_ps_string(m.group("a"))
        b = _unescape_ps_string(m.group("b"))
        count[0] += 1
        return _make_ps_literal(a + b)

    new_text = _CONCAT_RE.sub(repl, text)
    return new_text, count[0] > 0, (f"{count[0]} pair(s)" if count[0] else "")


def _real_substrings(text: str, group_text: str, group_start: int, real_spans: set) -> list[str] | None:
    """Extract each _STR match within group_text, but only accept it if its
    absolute position is a genuine string span - rejects any match built
    from misinterpreted quote characters (e.g. a quote inside a comment
    pairing with an unrelated one elsewhere)."""
    items = []
    for lm in re.finditer(_STR, group_text):
        abs_span = (group_start + lm.start(), group_start + lm.end())
        if abs_span not in real_spans:
            return None
        items.append(lm.group(0))
    return items


def _fold_join_operator(text: str):
    real_spans = set(_find_string_spans(text))
    count = [0]

    def repl(m: re.Match) -> str:
        items = _real_substrings(text, m.group("items"), m.start("items"), real_spans)
        if items is None or (m.start("sep"), m.end("sep")) not in real_spans:
            return m.group(0)
        sep = _unescape_ps_string(m.group("sep"))
        joined = sep.join(_unescape_ps_string(it) for it in items)
        count[0] += 1
        return _make_ps_literal(joined)

    new_text = _JOIN_ARRAY_RE.sub(repl, text)
    return new_text, count[0] > 0, (f"{count[0]} array(s)" if count[0] else "")


def _fold_format_operator(text: str):
    real_spans = set(_find_string_spans(text))
    count = [0]

    def repl(m: re.Match) -> str:
        if (m.start("fmt"), m.end("fmt")) not in real_spans:
            return m.group(0)
        raw_args = _real_substrings(text, m.group("args"), m.start("args"), real_spans)
        if raw_args is None:
            return m.group(0)
        fmt = _unescape_ps_string(m.group("fmt"))
        args = [_unescape_ps_string(a) for a in raw_args]

        def sub_placeholder(pm: re.Match) -> str:
            idx = int(pm.group(1))
            if 0 <= idx < len(args):
                count[0] += 1
                return args[idx]
            return pm.group(0)

        result = _PLACEHOLDER_RE.sub(sub_placeholder, fmt)
        return _make_ps_literal(result) if count[0] else m.group(0)

    new_text = _FORMAT_OP_RE.sub(repl, text)
    return new_text, count[0] > 0, (f"{count[0]} placeholder(s)" if count[0] else "")


def _code_to_char(token: str) -> str:
    token = token.strip()
    if token.lower().startswith("0x"):
        return chr(int(token, 16))
    if re.fullmatch(r"-?\d+", token):
        return chr(int(token))
    val = _safe_eval_arith(token)
    if val is None:
        raise ValueError(f"cannot resolve char code: {token}")
    return chr(val)


def _resolve_char_codes(text: str):
    real_spans = set(_find_string_spans(text))
    count = [0]

    def repl_single(m: re.Match) -> str:
        try:
            ch = _code_to_char(m.group(1))
        except (ValueError, OverflowError):
            return m.group(0)
        count[0] += 1
        return _make_ps_literal(ch)

    def repl_array(m: re.Match) -> str:
        if m.group("sep") and (m.start("sep"), m.end("sep")) not in real_spans:
            return m.group(0)
        codes = [c.strip() for c in m.group("codes").split(",")]
        try:
            chars = [_code_to_char(c) for c in codes]
        except (ValueError, OverflowError):
            return m.group(0)
        sep = _unescape_ps_string(m.group("sep")) if m.group("sep") else ""
        count[0] += 1
        return _make_ps_literal(sep.join(chars))

    text = _CHAR_ARRAY_RE.sub(repl_array, text)
    text = _CHAR_PAREN_RE.sub(repl_single, text)
    text = _CHAR_SINGLE_RE.sub(repl_single, text)
    return text, count[0] > 0, (f"{count[0]} value(s)" if count[0] else "")


def _resolve_bxor(text: str):
    count = [0]

    def repl(m: re.Match) -> str:
        try:
            a = int(m.group(1), 16) if m.group(1).lower().startswith("0x") else int(m.group(1))
            b = int(m.group(2), 16) if m.group(2).lower().startswith("0x") else int(m.group(2))
            ch = chr(a ^ b)
        except (ValueError, OverflowError):
            return m.group(0)
        count[0] += 1
        return _make_ps_literal(ch)

    new_text = _BXOR_RE.sub(repl, text)
    return new_text, count[0] > 0, (f"{count[0]} value(s)" if count[0] else "")


def _strip_junk_backticks(text: str):
    count = [0]
    pattern = re.compile(r"(?<=[A-Za-z0-9])`(?=[A-Za-z0-9])")

    def transform(chunk: str) -> str:
        def repl(m):
            count[0] += 1
            return ""
        return pattern.sub(repl, chunk)

    new_text, changed = _apply_outside_strings(text, transform)
    return new_text, changed, (f"{count[0]} backtick(s)" if count[0] else "")


# The lookahead matters: `[string]::Join(...)` is a static method call on the
# String type, not a cast, and dropping the prefix would leave `::Join(...)`.
MAX_ANNOTATED_LINES = 400


def _decode_standalone_payloads(text: str):
    """Decode a line that is *entirely* an encoded payload.

    A .txt or .log dropped on the tool is often just the blob - a Base64
    stage, or a list of character codes - with no surrounding code for the
    other passes to hook into. The original line is kept and the plaintext
    added beneath it, so the file still reads as what was submitted.
    """
    lines = text.split("\n")
    if len(lines) > MAX_ANNOTATED_LINES:
        return text, False, ""

    out: list[str] = []
    hits = 0
    for line in lines:
        out.append(line)
        stripped = line.strip()
        # Short lines are ordinary prose far more often than a payload.
        if len(stripped) < PlagEncode.MIN_B64_LEN or stripped.startswith("#"):
            continue
        payload = PlagEncode.decode_payload(stripped)
        if payload is None:
            continue
        how, decoded = payload
        hits += 1
        out.append(f"# [decoded from {how}] {decoded}")

    if not hits:
        return text, False, ""
    return "\n".join(out), True, f"{hits} line(s)"


_REDUNDANT_CAST_RE = re.compile(r"\[(?:System\.)?String\](?!\s*::)\s*", re.IGNORECASE)


def _strip_redundant_casts(text: str):
    """Drop `[string]` casts.

    They change nothing about a value that is already a string; they are there
    to break up a signature and to make the line harder to read.
    """
    count = [0]

    def transform(chunk: str) -> str:
        def repl(_m):
            count[0] += 1
            return ""
        return _REDUNDANT_CAST_RE.sub(repl, chunk)

    new_text, changed = _apply_outside_strings(text, transform)
    return new_text, changed, (f"{count[0]} cast(s)" if count[0] else "")


def _split_top_level_statements(line: str) -> list[str]:
    """Split a physical line on ';' separators that are at the top level -
    i.e. not inside a string literal or a bracketed expression."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = None
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if quote:
            buf.append(c)
            if quote == '"' and c == "`" and i + 1 < n:
                buf.append(line[i + 1])
                i += 2
                continue
            if c == quote:
                if i + 1 < n and line[i + 1] == quote:
                    buf.append(line[i + 1])
                    i += 2
                    continue
                quote = None
            i += 1
            continue

        if c in ("'", '"'):
            quote = c
            buf.append(c)
        elif c in "([{":
            depth += 1
            buf.append(c)
        elif c in ")]}":
            depth = max(0, depth - 1)
            buf.append(c)
        elif c == ";" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1

    if buf:
        parts.append("".join(buf))
    return parts


def prettify(text: str) -> str:
    """Put each top-level statement on its own line.

    Obfuscated payloads are usually one enormous ';'-joined line. Splitting
    it is purely cosmetic - no token is added or removed apart from the
    separators - but it turns an unreadable wall into something an analyst
    can actually scan.
    """
    out: list[str] = []
    for line in text.split("\n"):
        statements = _split_top_level_statements(line)
        # Only reformat when it genuinely helps.
        if len(statements) < 2:
            out.append(line)
            continue
        cleaned = [s.strip() for s in statements]
        cleaned = [s for s in cleaned if s]
        for idx, statement in enumerate(cleaned):
            suffix = ";" if idx < len(cleaned) - 1 or line.rstrip().endswith(";") else ""
            out.append(statement + suffix)
    return "\n".join(out)


def _final_cleanup(text: str) -> str:
    lines = [line.rstrip() for line in text.split("\n")]
    cleaned: list[str] = []
    blank_run = 0
    for line in lines:
        if line == "":
            blank_run += 1
            if blank_run > 1:
                continue
        else:
            blank_run = 0
        cleaned.append(line)
    return "\n".join(cleaned).strip("\n")
