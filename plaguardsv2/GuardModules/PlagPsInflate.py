"""Base64 and compressed stages in PowerShell, opened as child layers.

A Base64 literal that decodes to a script is a stage, not a value: it gets
its own layer and its own passes. One that decodes to a plain value (a URL,
a banner) is folded in place as before. A compressed stage is inflated under
a size and a ratio limit, and the reader / decompressor / memory-stream
wrapper around it is replaced by the layer marker, since the wrapper does
nothing but unpack it.

Decoding only; nothing is executed.
"""
from __future__ import annotations

import bisect
import re

from . import PlagDeobfus, PlagEncode, PlagGates, PlagRouter
from .PlagArtifact import ChildSpec, Edge, Lang
from .PlagPassApi import Kind, Pass, PassResult, Record, child_token

_FROM_B64 = r"\[(?:System\.)?Convert\]::From" r"Base64String\(\s*"
_B64_CALL_RE = re.compile(_FROM_B64 + r"(?P<q>['\"])(?P<b64>[A-Za-z0-9+/=\s]{16,})(?P=q)\s*\)", re.IGNORECASE)
_READ_ALL = ".read" "toend()"
_READER_RE = re.compile(r"Stream" r"Reader", re.IGNORECASE)
_DECOMPRESSOR_RE = re.compile(r"(?:Deflate|GZip)" r"Stream", re.IGNORECASE)
_IEX_BEFORE_RE = re.compile(r"(?:Invoke-" r"Expression|iex)\s*\(?\s*$", re.IGNORECASE)
# A decoded value is a stage only if it reads as more than one word.
_SEVERAL_WORDS_RE = re.compile(r"[\s;|]")
_BOMS = (b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")


def _inflated_text(out: bytes) -> str:
    """Inflated bytes as text: UTF-16 when they carry a BOM or the NULs of
    UTF-16 (a StreamReader given [Text.Encoding]::Unicode), else UTF-8, else
    each byte as one character."""
    if out.startswith(_BOMS) or b"\x00" in out[:4096]:
        return PlagEncode.decode_script(out)
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return out.decode("latin-1")


def _open_paren(text: str, close: int, spans) -> int | None:
    """Index of the '(' matching the ')' at `close`, skipping string literals."""
    depth = 0
    i = close
    while i >= 0:
        k = bisect.bisect_right(spans, (i, float("inf"))) - 1
        if k >= 0 and spans[k][0] <= i < spans[k][1]:
            i = spans[k][0] - 1
            continue
        if text[i] == ")":
            depth += 1
        elif text[i] == "(":
            depth -= 1
            if depth == 0:
                return i
        i -= 1
    return None


def _wrapper_span(text: str, call: re.Match, spans) -> tuple[int, int] | None:
    """The whole `(<reader>(<decompressor>(...<call>...))).ReadToEnd()`
    expression around a Base64 call, when it is written as one expression."""
    eol = text.find("\n", call.end())
    eol = len(text) if eol == -1 else eol
    read = text.lower().find(_READ_ALL, call.end(), eol)
    if read <= 0 or text[read - 1] != ")":
        return None
    start = _open_paren(text, read - 1, spans)
    if start is None or start > call.start():
        return None
    region = text[start:read]
    if not (_READER_RE.search(region) and _DECOMPRESSOR_RE.search(region)):
        return None
    return start, read + len(_READ_ALL)


def _children_result(text: str, found, label: str) -> PassResult:
    """found: (start, end, content, edge, detail) per stage."""
    found.sort(key=lambda f: f[0])
    pieces, children, last = [], [], 0
    for start, end, content, edge, detail in found:
        if start < last or not content.strip():
            continue
        pieces.append(text[last:start])
        pieces.append(child_token(len(children)))
        children.append(ChildSpec(language="", content=content, edge=edge, detail=detail,
                                  source_span=text[start:end]))
        last = end
    if not children:
        return PassResult()
    pieces.append(text[last:])
    return PassResult("".join(pieces), children=children,
                      records=[Record(label, f"{len(children)} stage(s)")])


class InflateHandoff(Pass):
    """A Base64 literal whose bytes are a gzip / zlib / raw-deflate stream."""

    id = "handoff.ps.inflate"
    kind = Kind.DECODE
    languages = Lang.PS_LIKE
    label = "inflated compressed stage(s) into their own layer"

    def apply(self, text, ctx):
        spans = PlagDeobfus._find_string_spans(text)
        limits = ctx.limits
        cap = min(limits.max_decoded_bytes_total, PlagEncode.MAX_INFLATE_BYTES)
        found, refused = [], []
        for m in _B64_CALL_RE.finditer(text):
            if PlagDeobfus._inside_any_span(m, spans):
                continue
            raw = PlagDeobfus._b64_bytes(m.group("b64"))
            if not raw:
                continue
            out, why = PlagEncode.bounded_decompress(raw, cap, limits.max_decompression_ratio)
            if out is None:
                if why != "not a compressed stream":
                    refused.append(why)
                continue
            content = _inflated_text(out)
            span = _wrapper_span(text, m, spans)
            start, end = span if span else (m.start(), m.end())
            found.append((start, end, content, Edge.DECOMPRESS,
                          "decompressor wrapper" if span else "compressed Base64"))
        result = _children_result(text, found, self.label)
        result.limits = [{"limit": "max_decompression", "detail": why} for why in refused]
        return result


def _bounded_plain(limits):
    """The legacy plain-call decoder, with inflation held to the run's limits:
    text as UTF-8, else an inflated stage as UTF-8, else nothing."""
    cap = min(limits.max_decoded_bytes_total, PlagEncode.MAX_INFLATE_BYTES)

    def decode(m: re.Match) -> str | None:
        raw = PlagDeobfus._b64_bytes(m.group("b64"))
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
        out, _why = PlagEncode.bounded_decompress(raw, cap, limits.max_decompression_ratio)
        if out is None:
            return None
        try:
            return out.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return decode


class FromBase64Layers(Pass):
    """FromBase64String one layer at a time: a decoded script becomes a child
    layer, a decoded value is folded in place as the legacy pass did. A value
    that does not read as text is left as written."""

    id = "ps.frombase64"
    kind = Kind.DECODE
    languages = Lang.PS_LIKE
    replaces = ("legacy.ps.decode_frombase64_literals",)
    label = "decoded [Convert]::FromBase64String literal(s)"

    def apply(self, text, ctx):
        children: list[ChildSpec] = []
        inlined = 0
        current = text

        def substitute(decoder, spans):
            def repl(m: re.Match) -> str:
                nonlocal inlined
                if PlagDeobfus._inside_any_span(m, spans):
                    return m.group(0)
                decoded = decoder(m)
                if decoded is None or not PlagGates.decoded_content_gate(decoded).ok:
                    return m.group(0)
                if (_SEVERAL_WORDS_RE.search(decoded.strip())
                        and PlagRouter.identify(decoded) not in (Lang.TEXT, Lang.UNKNOWN)):
                    run = _IEX_BEFORE_RE.search(current, 0, m.start()) is not None
                    children.append(ChildSpec(
                        language="", content=decoded, edge=Edge.HANDOFF if run else Edge.DECODE,
                        detail="FromBase64String -> Invoke-Expression" if run else "FromBase64String",
                        source_span=m.group(0)))
                    return child_token(len(children) - 1)
                inlined += 1
                return PlagDeobfus._make_ps_literal(PlagDeobfus._fold_decoded_fragment(decoded))
            return repl

        for pattern, decoder in ((PlagDeobfus._FROMBASE64_WRAPPED_RE, PlagDeobfus._decode_b64_wrapped),
                                 (PlagDeobfus._FROMBASE64_PLAIN_RE, _bounded_plain(ctx.limits))):
            current = pattern.sub(substitute(decoder, PlagDeobfus._find_string_spans(current)), current)
        if not children and not inlined:
            return PassResult()
        detail = f"{len(children) + inlined} literal(s)" + (f", {len(children)} as layer(s)" if children else "")
        return PassResult(current, children=children, records=[Record(self.label, detail)])


def passes() -> list[Pass]:
    return [InflateHandoff(), FromBase64Layers()]
