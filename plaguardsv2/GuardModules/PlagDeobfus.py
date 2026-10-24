"""Static, non-executing PowerShell deobfuscation.

Every transform here is a text/regex rewrite of literal values. Nothing in
this module ever calls eval/exec or invokes PowerShell itself - the input is
always treated as untrusted text.
"""
from __future__ import annotations

import ast
import base64
import bisect
import gzip
import math
import operator
import re
import zlib
from urllib.parse import unquote, unquote_plus
from collections import Counter
from dataclasses import dataclass, field

from . import PlagCmd, PlagEncode, PlagFold, PlagJs, PlagLoader, PlagMagic, PlagScan, PlagVbs
from .regex_utils import abbreviated_flag

MAX_PASSES = 10
MAX_INPUT_SIZE = 5_000_000
MIN_B64_TOKEN_LEN = 16

# Base64 layers peeled per literal. Bounded: untrusted input can nest itself
# arbitrarily, or self-referentially, just to make the analyser spin.
MAX_B64_NEST_DEPTH = 8

# Residual blobs: the length floor keeps identifiers and prose out. Separate
# entropy floors, since hex tops out at 4.0 bits/char against Base64's 6.0.
MIN_RESIDUAL_BLOB_LEN = 40
RESIDUAL_ENTROPY_MIN = 4.0
RESIDUAL_HEX_ENTROPY_MIN = 3.2

# A hex run of exactly a digest's width is a hash, which the IOC extractor
# already reports as itself - not an encoded stage that failed to resolve.
_HASH_DIGEST_HEX_LENGTHS = frozenset({40, 56, 64, 96, 128})

PREVIEW_WIDTH = 96

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

# FromBase64String ignores whitespace, so wrapped blobs are joined into one
# literal. The closing delimiter bounds the whitespace class.
_B64_WS_BODY = r"[A-Za-z0-9+/][A-Za-z0-9+/=\s]*[A-Za-z0-9+/=]"
_FROMBASE64_CALL = r"\[(?:System\.)?Convert\]::FromBase64String\(\s*"

_B64_HERESTRING_RE = re.compile(
    rf"(?P<call>{_FROMBASE64_CALL})@(?P<q>['\"])\s*(?P<body>{_B64_WS_BODY})\s*(?P=q)@",
    re.IGNORECASE,
)
_B64_QUOTED_WS_RE = re.compile(
    rf"(?P<call>{_FROMBASE64_CALL})(?P<q>['\"])(?P<body>{_B64_WS_BODY})(?P=q)",
    re.IGNORECASE,
)

# Undone only where the script names a decoder: "%20" inside a URL is
# already part of that URL's value.
_URL_DECODE_RE = re.compile(
    r"\[(?:System\.)?(?:Uri|Web\.HttpUtility|Net\.WebUtility|Web\.HttpServerUtility)\]"
    r"::(?P<fn>UnescapeDataString|UrlDecode)\(\s*"
    r"(?P<q>['\"])(?P<body>[^'\"\n]*%[0-9A-Fa-f]{2}[^'\"\n]*)(?P=q)\s*\)",
    re.IGNORECASE,
)

_CONCAT_RE = re.compile(rf"(?P<a>{_STR})\s*\+\s*(?P<b>{_STR})")

_JOIN_ARRAY_RE = re.compile(
    rf"@?\(\s*(?P<items>{_STR}(?:\s*,\s*{_STR})*)\s*\)\s*-join\s*(?P<sep>{_STR})",
    re.IGNORECASE,
)

# The lookahead matters: stopping at the first variable dropped the `-f` and
# left the remaining arguments behind as a bare comma list.
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

# $ShellId / string-indexing / variable-propagation

_SHELLID_RE = re.compile(r"\$ShellId\b", re.IGNORECASE)
_SHELLID_VALUE = "Microsoft.PowerShell"

# Assumed stock-Windows defaults, not derived from the sample: without them a
# command sliced out of $env:ComSpec is unreadable. The label says "assumed".
_ENV_DEFAULTS = {
    "comspec": r"C:\Windows\system32\cmd.exe",
    "windir": r"C:\Windows",
    "systemroot": r"C:\Windows",
    "programdata": r"C:\ProgramData",
    "allusersprofile": r"C:\ProgramData",
    "public": r"C:\Users\Public",
    # TEMP and TMP are absent: they vary per account, so there is no default,
    # and a placeholder path here gets extracted as fabricated indicators.
}

# $PSHOME is an automatic variable rather than an environment one, but it is
# fixed for Windows PowerShell 5.1 and gets sliced the same way $ShellId does.
_PSHOME_VALUE = r"C:\Windows\System32\WindowsPowerShell\v1.0"

# The lookahead keeps an assignment target (`$env:TEMP = ...`) intact -
# rewriting it to a literal would produce `'C:\...' = ...`, which is not code.
_ENV_VAR_RE = re.compile(
    r"\$(?:env:(?P<plain>\w+)|\{env:(?P<braced>\w+)\})(?!\s*=(?!=))",
    re.IGNORECASE,
)
_PSHOME_RE = re.compile(r"\$PSHOME\b(?!\s*=(?!=))", re.IGNORECASE)

_STRING_INDEX_RE = re.compile(rf"({_STR})\s*\[\s*(-?\d+)\s*\]")

_ASSIGN_COUNT_RE = re.compile(r"\$(\w+)\s*[+\-*/%]?=(?!=)")
_LITERAL_ASSIGN_RE = re.compile(rf"\$(\w+)\s*=\s*({_STR})\s*(?=[;\n]|$)", re.MULTILINE)

# numeric-array -> char idioms (annotated, not rewritten in place)

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
class ResidualBlob:
    """A long high-entropy run still present in the final output.

    Offsets are into `DeobfuscationResult.deobfuscated`. This is reporting
    only - the engine never runs anything to open one of these, so the honest
    statement is "still encoded", never a guess at the contents.
    """
    offset: int
    length: int
    entropy: float
    reason: str


@dataclass
class TransformRecord:
    """Structured provenance for one applied transform.

    Parallel to `pass_log`, which stays a plain list[str] because the report
    and its templates read it today. `assumed` is the load-bearing field: a
    value this engine supplied from a default is not the same evidence as one
    folded out of the sample, and the analyst has to be able to tell.
    """
    name: str
    detail: str = ""
    before: str = ""
    after: str = ""
    assumed: bool = False
    iteration: int = 0


@dataclass
class DeobfuscationResult:
    original: str
    deobfuscated: str
    # The same transforms with the input's own line structure kept, so a report
    # can line it up against the original. `deobfuscated` is also prettified.
    deobfuscated_raw: str = ""
    pass_log: list[str] = field(default_factory=list)
    truncated: bool = False
    iterations: int = 0
    # False when the pass loop ran out of budget while still making progress.
    # Unrelated to `truncated`, which is about input size.
    converged: bool = True
    residual_blobs: list[ResidualBlob] = field(default_factory=list)
    transforms: list[TransformRecord] = field(default_factory=list)


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
        ("resolved well-known $env: value(s) (assumed default Windows values)", _resolve_env_variables),
        ("resolved literal string indexing", _resolve_string_indexing),
        ("decoded -EncodedCommand base64 (UTF-16LE)", _decode_encoded_command),
        ("normalised line-wrapped Base64 literal(s)", _normalize_base64_whitespace),
        ("decoded [Convert]::FromBase64String literal(s)", _decode_frombase64_literals),
        ("decoded percent-encoded literal(s)", _decode_url_encoded),
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
        ("recovered XOR-decoded byte-array payload", PlagLoader.recover_xor_loop),
    ]
    passes += _language_passes(source)
    # Tried only in a round where no dedicated pass changed anything, so a
    # generic recipe search never pre-empts the decoder written for that case.
    fallback_passes = [
        ("decoded encoded run(s) with a CyberChef-style recipe", _magic_decode_runs),
    ]

    iterations = 0
    transforms: list[TransformRecord] = []
    converged = True

    def apply(stage, round_no: int) -> bool:
        nonlocal text
        changed_any = False
        for label, fn in stage:
            before = text
            new_text, changed, detail = fn(text)
            if not changed:
                continue
            text = new_text
            changed_any = True
            entry = f"Pass {round_no}: {label}"
            if detail:
                entry += f" ({detail})"
            log.append(entry)
            preview_before, preview_after = _change_previews(before, new_text)
            transforms.append(TransformRecord(
                name=label,
                detail=detail,
                before=preview_before,
                after=preview_after,
                assumed="assumed" in label.lower(),
                iteration=round_no,
            ))
        return changed_any

    for i in range(MAX_PASSES):
        iterations = i + 1
        if not apply(passes, i + 1) and not apply(fallback_passes, i + 1):
            break
    else:
        # Out of rounds while still rewriting: the output is half-peeled, and saying
        # so separates "nothing left to do" from "gave up".
        converged = False
        log.append(
            f"Fixed point not reached after {MAX_PASSES} passes: output is only "
            f"partially deobfuscated and may still contain encoded stages"
        )

    text = _unmask_comments(text, comments)
    raw = _final_cleanup(text)
    text = _final_cleanup(prettify(text))
    if truncated:
        log.append("Input truncated to first %d characters before analysis" % MAX_INPUT_SIZE)

    residual_blobs = _scan_residual_blobs(text)
    if residual_blobs:
        log.append(
            f"{len(residual_blobs)} high-entropy blob(s) left unresolved by static "
            f"analysis: still encoded, contents not recovered"
        )

    return DeobfuscationResult(
        original=source,
        deobfuscated=text,
        deobfuscated_raw=raw,
        pass_log=log,
        truncated=truncated,
        iterations=iterations,
        converged=converged,
        residual_blobs=residual_blobs,
        transforms=transforms,
    )


# helpers

def _normalize(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"`\n\s*", " ", text)
    return text


_COMMENT_TOKEN_RE = re.compile(r"\x00CMT(\d+)\x00")


_MASK_STOP_RE = re.compile(r"['\"#]|<#")


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
        # Ordinary text is copied in one slice up to the next quote or comment.
        stop = _MASK_STOP_RE.search(text, i)
        if stop is None:
            out.append(text[i:])
            break
        if stop.start() > i:
            out.append(text[i:stop.start()])
            i = stop.start()
        c = text[i]
        if c in ("'", '"'):
            j = PlagScan.literal_end(text, i)
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


_QUOTE_START_RE = re.compile(r"['\"]")


def _find_string_spans(text: str):
    """(start, end) of every string literal, sorted and disjoint."""
    spans = []
    i = 0
    while True:
        m = _QUOTE_START_RE.search(text, i)
        if m is None:
            return spans
        i = m.start()
        j = PlagScan.literal_end(text, i)
        spans.append((i, j))
        i = j


def _inside_any_span(m: re.Match, spans) -> bool:
    """Is this match wholly contained in an existing string literal?

    A match that merely *encloses* a literal (the quoted Base64 argument of a
    decoder call, say) is not inside one and must still be rewritten.
    """
    # Spans are sorted and disjoint: only the last one starting at or before the
    # match can contain it. A linear scan per match made large scripts quadratic.
    k = bisect.bisect_right(spans, (m.start(), float("inf"))) - 1
    return k >= 0 and spans[k][0] <= m.start() and m.end() <= spans[k][1]


def _preview(value: str) -> str:
    """One short printable line standing in for a span of script.

    Comment sentinels and control characters are folded away: a preview is
    read by a human in a report, and an embedded newline or \\x00CMT token
    would break the line it is rendered on.
    """
    flat = _COMMENT_TOKEN_RE.sub("<comment>", value)
    flat = re.sub(r"\s+", " ", flat).strip()
    flat = "".join(c if c.isprintable() else "." for c in flat)
    if len(flat) <= PREVIEW_WIDTH:
        return flat
    return flat[:PREVIEW_WIDTH - 3] + "..."


def _change_previews(before: str, after: str) -> tuple[str, str]:
    """Preview the region a pass actually rewrote, not the head of the file.

    A transform that fires 4000 characters in would otherwise record two
    identical previews and prove nothing about what it did.
    """
    limit = min(len(before), len(after))
    i = 0
    while i < limit and before[i] == after[i]:
        i += 1
    start = max(0, i - PREVIEW_WIDTH // 4)
    window = PREVIEW_WIDTH * 2
    return _preview(before[start:start + window]), _preview(after[start:start + window])


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    total = len(value)
    return -sum(
        (n / total) * math.log2(n / total) for n in Counter(value).values()
    )


# '=' is padding, so only at the end of a run: in the body it absorbed a
# "name=" prefix and made "?param=<base64>" look encrypted. No mid-token start.
_RESIDUAL_RUN_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{%d,}={0,2}(?![A-Za-z0-9+/=])"
    % MIN_RESIDUAL_BLOB_LEN
)
_HEX_RUN_RE = re.compile(r"[0-9A-Fa-f]+")


def _residual_reason(run: str, is_hex: bool) -> str:
    if is_hex:
        return "hex-like run with no recoverable text; likely an encrypted or binary stage"
    raw = _b64_bytes(run)
    if raw is None:
        return "high-entropy run left unresolved by every pass"
    try:
        _maybe_inflate(raw).decode("utf-8")
    except UnicodeDecodeError:
        return ("Base64-like run decoding to non-text bytes even after inflation; "
                "an encrypted or otherwise opaque stage")
    return "Base64-like run not reached by any decoder call this engine recognises"


_RECOVERED_PROBE_LEN = 24


def _already_recovered(run: str, text: str) -> bool:
    """True when this run's plaintext is already sitting in the output.

    Several passes deliberately keep the encoded source next to the decoded
    result - _decode_standalone_payloads leaves the original line in place,
    and literal propagation copies a literal rather than moving it. Scanning
    the final text without accounting for that made the engine announce that a
    payload was "still encoded, contents not recovered" on the very same run
    where it had decoded it and the plaintext appeared two lines further down.
    Saying so is worse than saying nothing: it is a confident claim about the
    analysis that is simply untrue.
    """
    decoded = _b64_bytes(run)
    if not decoded:
        return False
    try:
        plain = decoded.decode("utf-8")
    except UnicodeDecodeError:
        try:
            plain = _maybe_inflate(decoded).decode("utf-8")
        except (UnicodeDecodeError, OSError, EOFError):
            return False
    probe = plain.strip()[:_RECOVERED_PROBE_LEN]
    return len(probe) >= 8 and probe in text


def _magic_recovered(run: str, text: str) -> bool:
    """True when the recipe search opened this run and its plaintext is in the output."""
    result = PlagMagic.magic(run)
    if result is None:
        return False
    probe = result.output.strip()[:_RECOVERED_PROBE_LEN]
    return len(probe) >= 8 and probe in text


def _scan_residual_blobs(text: str) -> list[ResidualBlob]:
    """Report the encoded runs that survived every pass.

    When static analysis genuinely cannot continue - an encrypted stage, a key
    that never appears in the sample - the analyst needs to be told that, not
    left to spot a wall of Base64 by eye. Nothing here decodes speculatively
    or executes anything; it only measures and names what is still opaque.
    """
    blobs: list[ResidualBlob] = []
    for m in _RESIDUAL_RUN_RE.finditer(text):
        run = m.group(0)
        is_hex = _HEX_RUN_RE.fullmatch(run) is not None
        if is_hex and len(run) in _HASH_DIGEST_HEX_LENGTHS:
            continue
        entropy = _shannon_entropy(run)
        floor = RESIDUAL_HEX_ENTROPY_MIN if is_hex else RESIDUAL_ENTROPY_MIN
        if entropy < floor:
            continue
        if _already_recovered(run, text) or _magic_recovered(run, text):
            continue
        blobs.append(ResidualBlob(
            offset=m.start(),
            length=len(run),
            entropy=round(entropy, 2),
            reason=_residual_reason(run, is_hex),
        ))
    return blobs


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


def _b64_bytes(b64: str) -> bytes | None:
    """Raw bytes for a Base64 token, padding it first. Obfuscators routinely
    strip the '=' padding, so a missing one is not a reason to give up.

    Whitespace is removed before the padding is worked out, not left to the
    decoder to discard: counting it toward the length computes the wrong
    amount of padding and turns a line-wrapped blob into a decode failure.
    """
    token = "".join(b64.split())
    try:
        return base64.b64decode(token + "=" * (-len(token) % 4), validate=False)
    except Exception:
        return None


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


# passes

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


def _decode_b64_wrapped(m: re.Match) -> str | None:
    """Decoded text for a Text.Encoding::GetString(FromBase64String(...)) match."""
    codec = _ENCODING_CODECS.get(m.group("enc").lower(), "utf-8")
    raw = _b64_bytes(m.group("b64"))
    if raw is None:
        return None
    try:
        return raw.decode(codec, errors="replace")
    except Exception:
        return None


def _decode_b64_plain(m: re.Match) -> str | None:
    """Decoded text for a bare FromBase64String(...) match, or None when the
    bytes are not text.

    A non-UTF-8 result may still be a compressed stage (a common way to shrink
    or obscure a payload before encoding it), so inflation is tried first.
    Beyond that the call is left alone deliberately: an encrypted or XOR-ed
    stage rendered as latin-1 mojibake destroys the exact bytes a later pass
    needs to recover it.
    """
    raw = _b64_bytes(m.group("b64"))
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    try:
        return _maybe_inflate(raw).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _rewrite_frombase64(text: str, render) -> tuple[str, int]:
    """Run both FromBase64String substitutions over `text`, handing each
    successfully decoded string to `render` to produce its replacement.

    Two things here are load-bearing. Matches sitting inside an existing string
    literal are skipped - the same guard `_fold_string_concatenation` applies -
    so a decoder call that is merely quoted script text is never rewritten. And
    the spans are recomputed between the two substitutions, because the first
    one moves every offset after it.
    """
    count = 0

    def substitute(decoder):
        def repl(m: re.Match) -> str:
            nonlocal count
            if _inside_any_span(m, spans):
                return m.group(0)
            decoded = decoder(m)
            if decoded is None:
                return m.group(0)
            count += 1
            return render(decoded)
        return repl

    spans = _find_string_spans(text)
    text = _FROMBASE64_WRAPPED_RE.sub(substitute(_decode_b64_wrapped), text)
    spans = _find_string_spans(text)
    text = _FROMBASE64_PLAIN_RE.sub(substitute(_decode_b64_plain), text)
    return text, count


def _peel_frombase64_layers(text: str, depth: int = 0) -> str:
    """Resolve further FromBase64String layers inside already-decoded text,
    returning plain text rather than a quoted literal.

    Nesting has to be resolved here, before the caller quotes the result once,
    or a multi-layer payload is silently destroyed: quoting each layer as it is
    peeled splices unescaped quote characters into the middle of the literal
    built by the layer above it, which fragments that literal and leaves the
    assignment folder keeping only the first fragment.
    """
    if depth >= MAX_B64_NEST_DEPTH:
        return text
    # Before peeling, not after: a line-wrapped blob one stage down is
    # invisible until contiguous, and by fragment time it is already quoted.
    text = _normalize_base64_whitespace(text)[0]
    # Fold at every level: a spliced inner stage lands glued to what preceded it
    # ("$s = $d = ..."), so its values must be resolved before the splice.
    peeled, count = _rewrite_frombase64(
        text,
        lambda decoded: _fold_decoded_fragment(
            _peel_frombase64_layers(decoded, depth + 1)
        ),
    )
    return peeled if count else text


# Passes safe to re-run on a decoded fragment. Excludes the decoders, which
# own nesting, and the annotating passes, whose output is top-level commentary.
_FRAGMENT_PASS_NAMES = (
    "_resolve_string_indexing",
    "_fold_string_concatenation",
    "_fold_join_operator",
    "_fold_format_operator",
    "_resolve_char_codes",
    "_resolve_bxor",
    "_strip_junk_backticks",
    "_strip_redundant_casts",
    "_propagate_literal_variables",
    "_decode_url_encoded",
)
MAX_FRAGMENT_ROUNDS = 6
_fragment_passes_cache: list | None = None


def _fragment_passes() -> list:
    """Resolved on first use, not at import - several of these are defined
    further down the module than this helper."""
    global _fragment_passes_cache
    if _fragment_passes_cache is None:
        g = globals()
        _fragment_passes_cache = [g[name] for name in _FRAGMENT_PASS_NAMES]
        _fragment_passes_cache += [
            PlagFold.fold_subexpressions,
            PlagFold.fold_expressions,
            PlagFold.fold_assignments,
        ]
    return _fragment_passes_cache


def _fold_decoded_fragment(text: str) -> str:
    """Fold a decoded stage as SCRIPT before it is re-quoted as a value.

    A decoded Base64 stage is almost always script, not data - the whole point
    of staging is that the next layer is code. Quoting it verbatim freezes it
    as a literal, so any value construction inside it (concatenation, -f,
    character codes) is never folded and the indicator it assembles stays
    hidden. Measured: every value style resolved at depth 0 but only the ones
    whose payload appeared verbatim survived a single staging layer.

    Running the value passes over the fragment first means the literal that
    finally gets quoted already contains the resolved indicator. Nothing is
    executed here - these are the same literal-folding passes the top level
    runs, just applied one layer down.
    """
    for _ in range(MAX_FRAGMENT_ROUNDS):
        changed_any = False
        for fn in _fragment_passes():
            try:
                new_text, changed, _detail = fn(text)
            except Exception:
                # A fragment may not be well-formed script, and a pass failing on it is no
                # reason to lose the fragment.
                continue
            if changed:
                text = new_text
                changed_any = True
        if not changed_any:
            break
    return text


def _decode_frombase64_literals(text: str):
    new_text, count = _rewrite_frombase64(
        text,
        lambda decoded: _make_ps_literal(
            _fold_decoded_fragment(_peel_frombase64_layers(decoded))
        ),
    )
    return new_text, count > 0, (f"{count} literal(s)" if count else "")


def _resolve_env_variables(text: str):
    count = [0]

    def transform(chunk: str) -> str:
        def repl(m: re.Match) -> str:
            name = (m.group("plain") or m.group("braced") or "").lower()
            value = _ENV_DEFAULTS.get(name)
            if value is None:
                # Every other environment variable depends on the victim host,
                # so anything we substituted would be invention, not analysis.
                return m.group(0)
            count[0] += 1
            return _make_ps_literal(value)

        def repl_pshome(m: re.Match) -> str:
            count[0] += 1
            return _make_ps_literal(_PSHOME_VALUE)

        chunk = _ENV_VAR_RE.sub(repl, chunk)
        return _PSHOME_RE.sub(repl_pshome, chunk)

    new_text, changed = _apply_outside_strings(text, transform)
    return new_text, changed, (f"{count[0]} variable(s)" if count[0] else "")


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


def _normalize_base64_whitespace(text: str):
    """Collapse a Base64 argument that has been broken across lines.

    Scoped to the argument of a FromBase64String call rather than applied to
    every here-string: outside that call the newlines are part of the string's
    real value, and removing them would change what the script does.
    """
    count = [0]

    def repl(m: re.Match) -> str:
        body = m.group("body")
        stripped = "".join(body.split())
        # A no-op reported as a change would stop the pass loop reaching a
        # fixed point.
        if stripped == body or len(stripped) < MIN_B64_TOKEN_LEN:
            return m.group(0)
        if _b64_bytes(stripped) is None:
            return m.group(0)
        count[0] += 1
        return f"{m.group('call')}'{stripped}'"

    new_text = _B64_HERESTRING_RE.sub(repl, text)
    new_text = _B64_QUOTED_WS_RE.sub(repl, new_text)
    return new_text, count[0] > 0, (f"{count[0]} literal(s)" if count[0] else "")


def _decode_url_encoded(text: str):
    """Resolve percent-encoded literals passed to a named URL decoder.

    UrlDecode and UnescapeDataString differ on one point - the former treats
    '+' as a space and the latter does not - so they are decoded separately
    rather than through whichever happens to be handy.
    """
    count = [0]

    def repl(m: re.Match) -> str:
        if _inside_any_span(m, spans):
            return m.group(0)
        body = m.group("body")
        decoder = unquote_plus if m.group("fn").lower() == "urldecode" else unquote
        try:
            decoded = decoder(body, errors="replace")
        except Exception:
            return m.group(0)
        if decoded == body:
            return m.group(0)
        count[0] += 1
        return _make_ps_literal(decoded)

    spans = _find_string_spans(text)
    new_text = _URL_DECODE_RE.sub(repl, text)
    return new_text, count[0] > 0, (f"{count[0]} literal(s)" if count[0] else "")


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


_DECODED_MARKER = "# [decoded from "


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
    for index, line in enumerate(lines):
        out.append(line)
        stripped = line.strip()
        # Short lines are ordinary prose far more often than a payload.
        if len(stripped) < PlagEncode.MIN_B64_LEN or stripped.startswith("#"):
            continue
        # Idempotency guard: without it this pass re-decodes the same blob each round,
        # never converges, stacks duplicate comments, and reports converged False.
        following = lines[index + 1].lstrip() if index + 1 < len(lines) else ""
        if following.startswith(_DECODED_MARKER):
            continue
        payload = PlagEncode.decode_payload(stripped)
        if payload is None:
            continue
        how, decoded = payload
        hits += 1
        out.append(f"{_DECODED_MARKER}{how}] {decoded}")

    if not hits:
        return text, False, ""
    return "\n".join(out), True, f"{hits} line(s)"


_RECIPE_MARKER = "# [recipe: "


def _magic_decode_runs(text: str):
    """Open encoded runs no dedicated pass reached, using PlagMagic's recipe search.

    The run stays where it is and the plaintext goes on a marked line beneath
    it, so the recipe can be checked against the source in CyberChef.
    """
    inserts: dict[int, list[str]] = {}
    recipes: list[str] = []
    for run in PlagMagic.candidates(text):
        result = PlagMagic.magic(run)
        if result is None:
            continue
        # Already decoded, by this pass on an earlier round or by a dedicated one.
        probe = result.output.strip()[:_RECOVERED_PROBE_LEN]
        if len(probe) >= 8 and probe in text:
            continue
        line_no = text.count("\n", 0, text.find(run))
        inserts.setdefault(line_no, []).append(
            f"{_RECIPE_MARKER}{result.label}] {result.output.strip()}"
        )
        recipes.append(result.label)

    if not recipes:
        return text, False, ""
    out: list[str] = []
    for index, line in enumerate(text.split("\n")):
        out.append(line)
        out.extend(inserts.get(index, ()))
    kinds = ", ".join(sorted(set(recipes)))
    return "\n".join(out), True, f"{len(recipes)} run(s): {kinds}"


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


_SPLIT_STOP_RE = re.compile(r"['\"(\[{)\]};]")


def _split_top_level_statements(line: str) -> list[str]:
    """Split a physical line on ';' separators that are at the top level -
    i.e. not inside a string literal or a bracketed expression."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i, n = 0, len(line)
    while i < n:
        # Copy ordinary text in one slice up to the next character that matters.
        stop = _SPLIT_STOP_RE.search(line, i)
        if stop is None:
            buf.append(line[i:])
            break
        k = stop.start()
        if k > i:
            buf.append(line[i:k])
        c = line[k]
        if c in ("'", '"'):
            end = PlagScan.literal_end(line, k)
            buf.append(line[k:end])
            i = end
            continue
        if c in "([{":
            depth += 1
            buf.append(c)
        elif c in ")]}":
            depth = max(0, depth - 1)
            buf.append(c)
        elif depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i = k + 1

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
