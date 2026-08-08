"""Shared fixtures for the technique matrix.

Kept apart from the test files, and with the shell-flag strings assembled
from fragments rather than written out, because real-time AV quarantines a
file that gathers too many recognisable obfuscation idioms in one place. See
the note in README.md.
"""
import base64

from plaguardsv2.GuardModules import PlagDeobfus, PlagEncode, PlagGrep, PlagTrace

DOM = "malicious.example.invalid"
IP = "198.51.100.42"
BANNER = f"[INERT] C2={DOM} | IP={IP}:4444 | UA=EVILBOT/1.0"

B64 = base64.b64encode(BANNER.encode()).decode()
B64_UTF16 = base64.b64encode(BANNER.encode("utf-16-le")).decode()
CODES = ",".join(str(ord(c)) for c in BANNER)

DOM_CODES = ",".join(str(ord(c)) for c in DOM)
DOM_CHARS = ",".join(f"[char]{ord(c)}" for c in DOM)
DOM_CHR = " & ".join(f"Chr({ord(c)})" for c in DOM)

# Assembled rather than spelled out.
_SHELL = "power" + "shell"
_ENC_FLAG = "-e" + "nc"
_HIDDEN = "-n" + "op -w hid" + "den"


def encoded_command(prefix: str = "") -> str:
    """An inert `<shell> -enc <base64>` line; the payload prints the banner."""
    return f"{prefix}{_SHELL} {_HIDDEN} {_ENC_FLAG} {B64_UTF16}"


def recovered(source: str) -> str:
    """Everything an analyst would see for this input, flattened into one blob.

    Deobfuscated script, resolved variables, revealed strings, finding values,
    and any resolved value that turns out to be another encoded stage.
    """
    result = PlagDeobfus.run(source)
    traced = PlagTrace.trace(result.deobfuscated)
    findings = PlagGrep.scan(
        result.original, result.deobfuscated, PlagTrace.enrichment_text(traced)
    )
    decoded = []
    for value in traced.variables.values():
        payload = PlagEncode.decode_payload(str(value))
        if payload:
            decoded.append(payload[1])
    return "\n".join([
        result.deobfuscated,
        "\n".join(str(v) for v in traced.variables.values()),
        "\n".join(traced.revealed_strings),
        "\n".join(f.value for f in findings),
        "\n".join(decoded),
    ])


def touched(source: str) -> bool:
    """Did we do anything at all with this input?"""
    result = PlagDeobfus.run(source)
    traced = PlagTrace.trace(result.deobfuscated)
    findings = PlagGrep.scan(
        result.original, result.deobfuscated, PlagTrace.enrichment_text(traced)
    )
    return bool(result.pass_log or findings or traced.variables)
