"""Generate an inert, labelled deobfuscation corpus.

Ground truth comes from the seed, never from the engine. That direction matters:
the audit found an existing fixture whose expected value had been copied from
the engine's own output, which made the bug invisible to the suite. Here the
payload is chosen first and the obfuscated form is derived from it, so the
label cannot drift toward whatever the engine happens to do.

Every sample is inert. Payloads are RFC 2606 reserved names and RFC 5737
documentation addresses, and every script terminates in Write-Host.

Contamination control
---------------------
Samples are split by *configuration*, not randomly. A random split would put
structurally identical siblings on both sides - two samples from the same
value-style differ only in the literal - and the score would measure template
memorisation. The dev and holdout splits here use the same technique families
but disjoint payload pools and disjoint parameterisation (different junk
characters, different concatenation boundaries, different nesting depths), so
a holdout score answers "does this generalise past the literal I developed
against" rather than "did I memorise it".
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field


# payload pools - disjoint between splits
PAYLOADS = {
    "dev": [
        ("domain", "malicious.example.invalid"),
        ("domain", "stage2.example.invalid"),
        ("ip", "198.51.100.24"),
        ("url", "http://cdn.example.invalid/a.ps1"),
    ],
    "holdout": [
        ("domain", "beacon.test.invalid"),
        ("domain", "update.example.invalid"),
        ("ip", "203.0.113.9"),
        ("url", "http://host.test.invalid/b.ps1"),
    ],
}

# Parameterisation differs per split so the holdout is not a re-spelling of dev.
PARAMS = {
    "dev": {"junk": "#", "pad": "ZZ", "xor": 0x42, "shift": 3, "parts": 3},
    "holdout": {"junk": "~", "pad": "QQQ", "xor": 0x5B, "shift": 7, "parts": 2},
}


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# value styles: each spells the SAME payload a different way
# Each maps to a specific audit finding, so a per-style score localises defects.
def vs_literal(value, p):
    return _q(value)


def vs_concat(value, p):
    third = max(1, len(value) // 3)
    a, b, c = value[:third], value[third:third * 2], value[third * 2:]
    return f"{_q(a)} + {_q(b)} + {_q(c)}"


def vs_charcodes(value, p):
    codes = ",".join(str(ord(ch)) for ch in value)
    return f"(({codes}) | %{{[char]$_}}) -join ''"


def vs_format(value, p):
    half = len(value) // 2
    return f"'{{0}}{{1}}' -f {_q(value[:half])},{_q(value[half:])}"


def vs_replace_junk(value, p):
    junk = p["junk"]
    salted = junk.join(value[i:i + 4] for i in range(0, len(value), 4))
    return f"{_q(salted)} -replace {_q(junk)},''"


def vs_reverse(value, p):
    rev = value[::-1]
    return f"-join ({_q(rev)}[{len(value) - 1}..0])"


def vs_substring(value, p):
    pad = p["pad"]
    return f"{_q(pad + value + pad)}.Substring({len(pad)},{len(value)})"


def vs_b64_value(value, p):
    return (f"[Text.Encoding]::UTF8.GetString("
            f"[Convert]::FromBase64String('{_b64(value)}'))")


def vs_hex_chars(value, p):
    """Exercises hex literals - audit finding A3."""
    head = " + ".join(f"[char]0x{ord(ch):02x}" for ch in value[:3])
    return f"{head} + {_q(value[3:])}"


def vs_convert_hex(value, p):
    """Exercises [Convert]::ToInt32(s,16) - audit finding A7."""
    head = " + ".join(
        f"[char][Convert]::ToInt32('{ord(ch):02X}',16)" for ch in value[:3]
    )
    return f"{head} + {_q(value[3:])}"


def vs_splitjoin(value, p):
    junk = p["junk"]
    salted = junk.join(value[i:i + 5] for i in range(0, len(value), 5))
    return f"({_q(salted)} -split {_q(junk)}) -join ''"


def vs_array_reverse(value, p):
    """[Array]::Reverse mutates in place, so this is inherently several
    statements - it gets the whole-script shape rather than an expression."""
    rev = value[::-1]
    return ("__SCRIPT__"
            f"$c = {_q(rev)}.ToCharArray()\n"
            "[Array]::Reverse($c)\n"
            "$d = (-join $c)\n"
            "Write-Host $d")


def vs_encoded_command(value, p):
    """powershell -EncodedCommand takes UTF-16LE base64."""
    inner = f"Write-Host {_q(value)}"
    blob = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
    return f"__ENCCMD__{blob}"


def vs_gzip_b64(value, p):
    """A compressed stage - common because it shrinks a payload and hides
    keywords from naive string matching at the same time."""
    import gzip as _gzip
    # mtime=0: gzip stamps the current time by default, which would change the
    # corpus fingerprint every run and unfreeze the holdout.
    raw = _gzip.compress(f"Write-Host {_q(value)}".encode("utf-8"), mtime=0)
    return "__GZIP__" + base64.b64encode(raw).decode("ascii")


def vs_combo(value, p):
    """Several techniques stacked, the way a real obfuscator chains them.
    Single techniques in isolation are the easy case; this is the one that
    catches passes which only work when nothing else has run first."""
    junk = p["junk"]
    third = max(1, len(value) // 3)
    a, b, c = value[:third], value[third:third * 2], value[third * 2:]
    a_codes = ",".join(str(ord(ch)) for ch in a)
    b_salted = junk.join(b[i:i + 3] for i in range(0, len(b), 3))
    return (f"((({a_codes}) | %{{[char]$_}}) -join '')"
            f" + ({_q(b_salted)} -replace {_q(junk)},'')"
            f" + ('{{0}}' -f {_q(c)})")


# Harder styles, added once the original fifteen scored 100% and the corpus
# stopped discriminating. Each is a real obfuscator technique.
def vs_b64_concat(value, p):
    """The Base64 *literal* split across concatenation, so the blob only
    exists after a fold. Ordering test: decoding has to happen after the
    concat pass, not on whatever the first pass happened to see."""
    blob = _b64(value)
    n = p["parts"]
    size = max(1, len(blob) // n)
    chunks = [blob[i:i + size] for i in range(0, len(blob), size)]
    joined = " + ".join(_q(c) for c in chunks)
    return f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String({joined}))"


def vs_deflate_b64(value, p):
    """Raw DeflateStream rather than Gzip - the same staging idea without the
    gzip header, which is what a header-sniffing decoder gets wrong."""
    import zlib as _zlib
    # [2:-4] strips the zlib header and adler32 tail, leaving the raw deflate
    # stream .NET's DeflateStream expects. Level pinned so the corpus is stable.
    raw = _zlib.compress(f"Write-Host {_q(value)}".encode("utf-8"), 9)[2:-4]
    return "__DEFLATE__" + base64.b64encode(raw).decode("ascii")


def vs_replace_method(value, p):
    """.Replace() the method, not -replace the operator: a different parse
    shape for the same intent, and method calls take no regex."""
    junk = p["junk"]
    salted = junk.join(value[i:i + 4] for i in range(0, len(value), 4))
    return f"{_q(salted)}.Replace({_q(junk)},'')"


def vs_format_reorder(value, p):
    """-f with the arguments out of order and one reused. Real obfuscators
    randomise placeholder order; taking them positionally in sequence happens
    to work only while the order is already 0,1,2."""
    third = max(1, len(value) // 3)
    a, b, c = value[:third], value[third:third * 2], value[third * 2:]
    return f"'{{2}}{{0}}{{1}}' -f {_q(b)},{_q(c)},{_q(a)}"


def vs_string_join_static(value, p):
    """[string]::Join over a [char[]] cast - the static-method spelling of
    -join, which a -join-shaped pattern misses."""
    codes = ",".join(str(ord(ch)) for ch in value)
    return f"[string]::Join('',[char[]]({codes}))"


def vs_xor_key(value, p):
    """Single-byte XOR over a byte array - the standard loader stage."""
    key = p["xor"]
    body = ",".join("0x%02x" % (ord(ch) ^ key) for ch in value)
    return f"-join (@({body}) | %{{[char]($_ -bxor 0x{key:02x})}})"


def vs_rot_shift(value, p):
    """Additive character shift: arithmetic inside the [char] cast rather
    than a table of final code points."""
    shift = p["shift"]
    body = ",".join(str(ord(ch) + shift) for ch in value)
    return f"-join (({body}) | %{{[char]([int]$_ - {shift})}})"


def vs_url_encoded(value, p):
    """Percent-encoding - cheap, readable to a machine, and invisible to a
    keyword scan looking for the host."""
    pct = "".join("%%%02X" % ord(ch) for ch in value)
    return f"[uri]::UnescapeDataString('{pct}')"


def vs_reversed_b64(value, p):
    """The Base64 blob stored backwards and reversed at runtime: two stages
    that only yield anything when both are undone, in order."""
    blob = _b64(value)
    return (f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("
            f"-join {_q(blob[::-1])}[{len(blob) - 1}..0]))")


def vs_backtick_split(value, p):
    """Backticks inside type and method names. PowerShell drops them at parse
    time, so [Con`vert] is [Convert] - but only to a reader that strips them
    before matching, which is the point."""
    return (f"[Text.En`coding]::UTF8.Get`String("
            f"[Con`vert]::FromBase64Str`ing('{_b64(value)}'))")


def vs_interp_subexpr(value, p):
    """$(...) subexpressions inside a double-quoted string - the value is
    assembled by the interpolation, not by any operator."""
    head = "".join(f"$([char]{ord(ch)})" for ch in value[:3])
    return f'"{head}{value[3:]}"'


def vs_charcode_arith(value, p):
    """Code points written as arithmetic, so no literal code point appears."""
    shift = p["shift"]
    head = " + ".join(
        f"[char]({ord(ch) - shift} + {shift})" for ch in value[:3]
    )
    return f"{head} + {_q(value[3:])}"


def vs_b64_whitespace(value, p):
    """Base64 broken across lines in a here-string. .NET ignores whitespace
    inside a Base64 run; a regex anchored on a contiguous token does not."""
    blob = _b64(value)
    cut = len(blob) // 2
    return ("[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(@'\n"
            f"{blob[:cut]}\n{blob[cut:]}\n'@))")


# Second harder tier, after the first also reached 100%: composition and the
# string/numeric API surface, where one-spelling patterns stop generalising.
def vs_hex_split_join(value, p):
    """A hex table split on a separator and converted per byte - the usual
    shape of a loader's embedded string table."""
    junk = p["junk"]
    body = junk.join("%02x" % ord(ch) for ch in value)
    return (f"({_q(body)} -split {_q(junk)} | "
            f"%{{[char][Convert]::ToByte($_,16)}}) -join ''")


def vs_nested_format(value, p):
    """-f nested inside -f. Resolving the outer one first leaves a format
    string as an argument, so this only comes out if the inner is folded
    first - which is the ordering the single-level style cannot test."""
    third = max(1, len(value) // 3)
    a, b, c = value[:third], value[third:third * 2], value[third * 2:]
    return f"'{{0}}{{1}}' -f ('{{1}}{{0}}' -f {_q(b)},{_q(a)}),{_q(c)}"


def vs_insert_remove(value, p):
    """.Insert() putting back a chunk that was cut out, so no contiguous
    spelling of the value appears anywhere in the source."""
    cut = max(1, len(value) // 3)
    chunk = value[cut:cut + 4]
    stripped = value[:cut] + value[cut + 4:]
    return f"{_q(stripped)}.Insert({cut},{_q(chunk)})"


def vs_tochar_convert(value, p):
    """[Convert]::ToChar - the numeric-family spelling of [char]."""
    head = " + ".join(f"[Convert]::ToChar({ord(ch)})" for ch in value[:3])
    return f"{head} + {_q(value[3:])}"


def vs_index_reorder(value, p):
    """Split into pieces stored out of order, reassembled by indexing. The
    source holds every character but in the wrong sequence."""
    junk = p["junk"]
    third = max(1, len(value) // 3)
    a, b, c = value[:third], value[third:third * 2], value[third * 2:]
    scrambled = junk.join([b, c, a])
    return f"(({_q(scrambled)} -split {_q(junk)})[2,0,1]) -join ''"


def vs_hexarray_join(value, p):
    """Code points as hex inside a [char[]] cast rather than decimal."""
    codes = ",".join("0x%02x" % ord(ch) for ch in value)
    return f"-join [char[]]({codes})"


VALUE_STYLES = {
    "literal": vs_literal,
    "concat": vs_concat,
    "charcodes": vs_charcodes,
    "format": vs_format,
    "replace_junk": vs_replace_junk,
    "reverse": vs_reverse,
    "substring": vs_substring,
    "b64_value": vs_b64_value,
    "hex_chars": vs_hex_chars,
    "convert_hex": vs_convert_hex,
    "splitjoin": vs_splitjoin,
    "array_reverse": vs_array_reverse,
    "encoded_command": vs_encoded_command,
    "gzip_b64": vs_gzip_b64,
    "combo": vs_combo,
    # harder set
    "b64_concat": vs_b64_concat,
    "deflate_b64": vs_deflate_b64,
    "replace_method": vs_replace_method,
    "format_reorder": vs_format_reorder,
    "string_join_static": vs_string_join_static,
    "xor_key": vs_xor_key,
    "rot_shift": vs_rot_shift,
    "url_encoded": vs_url_encoded,
    "reversed_b64": vs_reversed_b64,
    "backtick_split": vs_backtick_split,
    "interp_subexpr": vs_interp_subexpr,
    "charcode_arith": vs_charcode_arith,
    "b64_whitespace": vs_b64_whitespace,
    # second harder tier
    "hex_split_join": vs_hex_split_join,
    "nested_format": vs_nested_format,
    "insert_remove": vs_insert_remove,
    "tochar_convert": vs_tochar_convert,
    "index_reorder": vs_index_reorder,
    "hexarray_join": vs_hexarray_join,
}

# Which audit finding each style exercises - reported per-style so a
# regression points straight at the responsible change.
STYLE_FINDING = {
    "literal": "baseline",
    "concat": "baseline",
    "charcodes": "A3 modulo / ForEach-Object alias",
    "format": "A6 -f operator",
    "replace_junk": "A4 -replace regex semantics",
    "reverse": "A8 descending range indexing",
    "substring": "A9 String method set",
    "b64_value": "B1 base64 decode",
    "hex_chars": "A1 hex literals",
    "convert_hex": "A7 [Convert] numeric family",
    "splitjoin": "-split / -join round trip",
    "array_reverse": "[Array]::Reverse",
    "encoded_command": "-EncodedCommand UTF-16LE",
    "gzip_b64": "gzip stage (MemoryStream/GzipStream)",
    "combo": "stacked techniques - the realistic case",
    "b64_concat": "base64 literal assembled by concatenation",
    "deflate_b64": "raw DeflateStream stage (no gzip header)",
    "replace_method": ".Replace() method vs -replace operator",
    "format_reorder": "-f with reordered/reused placeholders",
    "string_join_static": "[string]::Join static-method spelling",
    "xor_key": "single-byte XOR byte array",
    "rot_shift": "additive character shift",
    "url_encoded": "percent-encoding / UnescapeDataString",
    "reversed_b64": "reversed base64 blob",
    "backtick_split": "backticks inside type/method names",
    "interp_subexpr": "$() subexpressions inside a string",
    "charcode_arith": "code points written as arithmetic",
    "b64_whitespace": "base64 split across lines in a here-string",
    "hex_split_join": "hex table split and converted per byte",
    "nested_format": "-f nested inside -f",
    "insert_remove": ".Insert() restoring an excised chunk",
    "tochar_convert": "[Convert]::ToChar numeric spelling",
    "index_reorder": "pieces stored out of order, reassembled by index",
    "hexarray_join": "hex code points in a [char[]] cast",
}


def stage_wrap(script: str) -> str:
    """One Base64 staging layer around a whole script - audit finding B1."""
    return (f"$s = [Text.Encoding]::UTF8.GetString("
            f"[Convert]::FromBase64String(\"{_b64(script)}\"))\nWrite-Host $s")


@dataclass
class Sample:
    sample_id: str
    split: str
    config_id: str
    style: str
    stages: int
    script: str
    iocs: dict = field(default_factory=dict)   # type -> set of expected values
    finding: str = ""

    @property
    def all_iocs(self) -> set:
        out = set()
        for values in self.iocs.values():
            out |= values
        return out


def build(split: str, styles=None, depths=(0, 1, 2, 3)) -> list[Sample]:
    """Every (payload x style x depth) combination for one split."""
    p = PARAMS[split]
    styles = styles or list(VALUE_STYLES)
    samples: list[Sample] = []

    for ioc_type, value in PAYLOADS[split]:
        for style in styles:
            expr = VALUE_STYLES[style](value, p)
            # Two styles are whole-script wrappers rather than expressions,
            # because that is how they appear in the wild.
            if expr.startswith("__SCRIPT__"):
                base_script = expr[len("__SCRIPT__"):]
            elif expr.startswith("__ENCCMD__"):
                base_script = ("powershell.exe -NoP -W Hidden -EncodedCommand "
                               + expr[len("__ENCCMD__"):])
            elif expr.startswith(("__GZIP__", "__DEFLATE__")):
                marker = "__GZIP__" if expr.startswith("__GZIP__") else "__DEFLATE__"
                kind = "Gzip" if marker == "__GZIP__" else "Deflate"
                blob = expr[len(marker):]
                base_script = (
                    "$ms = New-Object IO.MemoryStream(,"
                    f"[Convert]::FromBase64String('{blob}'))\n"
                    f"$gz = New-Object IO.Compression.{kind}Stream("
                    "$ms,[IO.Compression.CompressionMode]::Decompress)\n"
                    "$sr = New-Object IO.StreamReader($gz)\n"
                    "Write-Host $sr.ReadToEnd()"
                )
            else:
                base_script = f"$d = {expr}\nWrite-Host $d"
            for depth in depths:
                script = base_script
                for _ in range(depth):
                    script = stage_wrap(script)
                cfg = f"{style}@{depth}"
                samples.append(Sample(
                    sample_id=f"{split}:{cfg}:{value}",
                    split=split,
                    config_id=cfg,
                    style=style,
                    stages=depth,
                    script=script,
                    iocs={ioc_type: {value}},
                    finding=STYLE_FINDING.get(style, ""),
                ))
    return samples


def corpus_fingerprint(samples: list[Sample]) -> str:
    """Stable hash of a split, so a frozen holdout can be proven unchanged."""
    import hashlib
    h = hashlib.sha256()
    for s in sorted(samples, key=lambda x: x.sample_id):
        h.update(s.sample_id.encode())
        h.update(s.script.encode())
    return h.hexdigest()[:16]


if __name__ == "__main__":
    for split in ("dev", "holdout"):
        rows = build(split)
        print(f"{split:8} {len(rows):4} samples  "
              f"{len(set(r.config_id for r in rows)):3} configs  "
              f"fingerprint={corpus_fingerprint(rows)}")
