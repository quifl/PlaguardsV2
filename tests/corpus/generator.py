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


# --------------------------------------------------------------------------
# payload pools - disjoint between splits
# --------------------------------------------------------------------------
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
    "dev": {"junk": "#", "pad": "ZZ"},
    "holdout": {"junk": "~", "pad": "QQQ"},
}


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# --------------------------------------------------------------------------
# value styles: each spells the SAME payload a different way
# Each maps to a specific audit finding, so a per-style score localises defects.
# --------------------------------------------------------------------------
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
    # mtime=0: gzip stamps the current time into its header by default, which
    # would make the corpus fingerprint change on every run and destroy the
    # whole point of freezing the holdout split.
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
            elif expr.startswith("__GZIP__"):
                blob = expr[len("__GZIP__"):]
                base_script = (
                    "$ms = New-Object IO.MemoryStream(,"
                    f"[Convert]::FromBase64String('{blob}'))\n"
                    "$gz = New-Object IO.Compression.GzipStream("
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
