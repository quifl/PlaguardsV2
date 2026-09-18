"""Technique matrix: VBScript, JScript, batch/cmd, and raw data.

Companion to test_deob_matrix_ps.py - kept in a separate file so neither
gathers enough obfuscation idioms in one place to trip real-time AV.
"""
import pytest

from deob_cases import (B64, CODES, DOM, DOM_CHR, DOM_CODES, IP, BANNER,
                        encoded_command, recovered, touched)
from plaguardsv2.GuardModules import PlagEncode

CASES = [
    # --- VBScript --------------------------------------------------------
    ("vbs-chr-concat", f"Dim s\ns = {DOM_CHR}\nWScript.Echo s", DOM),
    ("vbs-strreverse", 'Dim s\ns = StrReverse("dilavni.elpmaxe.suoicilam")\nWScript.Echo s', DOM),
    ("vbs-replace", 'Dim s\ns = Replace("maliciousXexampleXinvalid", "X", ".")\nWScript.Echo s', DOM),
    ("vbs-base64-literal", f'Dim s\ns = "{B64}"\nWScript.Echo s', DOM),
    ("vbs-variable", 'Dim d\nd = "malicious.example.invalid"\nWScript.Echo d', DOM),
    ("vbs-mixed", 'Dim s\ns = Chr(109) & "alicious" & Chr(46) & "example.invalid"\nWScript.Echo s', DOM),

    # --- JScript ---------------------------------------------------------
    ("js-charcode", f"var d = String.fromCharCode({DOM_CODES});\nWScript.Echo(d);", DOM),
    ("js-concat", 'var d = "mal" + "icious" + "." + "example" + ".invalid";\nWScript.Echo(d);', DOM),
    ("js-reverse-chain", 'var d = "dilavni.elpmaxe.suoicilam".split("").reverse().join("");\nWScript.Echo(d);', DOM),
    ("js-split-join", 'var d = "malicious#example#invalid".split("#").join(".");\nWScript.Echo(d);', DOM),
    ("js-hex-escapes", 'var d = "\\x6d\\x61licious.example.invalid";\nWScript.Echo(d);', DOM),
    ("js-unicode-escapes", 'var d = "\\u006d\\u0061licious.example.invalid";\nWScript.Echo(d);', DOM),
    ("js-decode-call", 'var d = ato' + f'b("{B64}");\nWScript.Echo(d);', DOM),
    ("js-percent", 'var d = unes' + 'cape("%6d%61licious.example.invalid");\nWScript.Echo(d);', DOM),
    ("js-base64-literal", f'var d = "{B64}";\nWScript.Echo(d);', DOM),
    ("js-variable", 'var dom = "malicious.example.invalid";\nfunction f(){}\nWScript.Echo(dom);', DOM),

    # --- batch / cmd -----------------------------------------------------
    ("bat-set-concat", "@echo off\nset a=malicious\nset b=.example\nset c=.invalid\nset d=%a%%b%%c%\necho %d%", DOM),
    ("bat-substring", "@echo off\nset pool=ZZmaliciousZZexampleZZinvalidZZ\nset x=%pool:~2,9%\necho %x%", "malicious"),
    ("bat-replace", "@echo off\nset s=maliciousXexampleXinvalid\nset d=%s:X=.%\necho %d%", DOM),
    ("bat-caret", "@echo off\nset d=malicious.example.invalid\necho C2^=%d% ^| IP^=198.51.100.42", DOM),
    ("cmd-delayed", "@echo off\nsetlocal enabledelayedexpansion\nset d=malicious.example.invalid\necho !d!\nendlocal", DOM),

    # --- data / logs -----------------------------------------------------
    ("txt-bare-base64", B64, DOM),
    ("txt-char-codes", CODES, DOM),
    ("log-proxy", f"2026-08-08 09:14:01 10.0.0.5 GET {DOM} /payload.ps1 404 EVILBOT/1.0", DOM),
    ("log-embedded-enc", encoded_command("CommandLine: "), DOM),
]


@pytest.mark.parametrize("name,source,want", CASES, ids=[c[0] for c in CASES])
def test_technique_is_resolved(name, source, want):
    assert want in recovered(source), f"{name} did not reveal {want!r}"


@pytest.mark.parametrize("name,source,_want", CASES, ids=[c[0] for c in CASES])
def test_nothing_passes_straight_through(name, source, _want):
    assert touched(source)


def test_a_resolved_value_that_is_still_encoded_gets_decoded():
    """A variable holding a character-code list is a stage, not the payload -
    the table has to say what it contains rather than show a wall of digits."""
    assert PlagEncode.decode_payload(CODES) == ("character codes", BANNER)
    assert PlagEncode.decode_payload(B64) == ("base64", BANNER)


def test_ordinary_values_are_not_mistaken_for_payloads():
    """An address, a port or a short word must not be 'decoded' into noise."""
    for value in (IP, "4444", DOM, "1,2", "EVILBOT/1.0", "", "Global\\ABAD-IDEA-123"):
        assert PlagEncode.decode_payload(value) is None
