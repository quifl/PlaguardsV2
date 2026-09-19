"""Technique matrix: PowerShell.

One small case per technique, so a regression names the exact trick that
broke rather than "sample 07 failed". Every case is inert - the payload is
always the same benign, non-routable banner, and nothing is ever invoked.
"""
import pytest

from deob_cases import (B64, DOM, DOM_CHARS, DOM_CODES, encoded_command,
                        recovered, touched)

CASES = [
    ("concat", "$d = 'malicious.' + 'example' + '.invalid'; Write-Host $d", DOM),
    ("reassign-chain", "$d='example.invalid'; $d='malicious.'+$d; Write-Host $d", DOM),
    ("base64", f"$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{B64}')); Write-Host $s", DOM),
    ("base64-system-prefix", f"$s=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{B64}')); Write-Host $s", DOM),
    ("encoded-command", encoded_command(), DOM),
    ("char-join", f"$d = ({DOM_CHARS}) -join ''; Write-Host $d", DOM),
    ("byte-array", f"$d=[Text.Encoding]::ASCII.GetString([byte[]]({DOM_CODES})); Write-Host $d", DOM),
    ("split-join", "$d = ('malicious#example#invalid' -split '#') -join '.'; Write-Host $d", DOM),
    # The separator must not occur in the payload in EITHER case. 'X' used to
    # sit here and the expected value was 'malicious.example.invalid', which no
    # real host produces: -replace is case-insensitive by default, so the
    # lowercase 'x' in "example" matched too and the answer was
    # 'malicious.e.ample.invalid'. The fixture had been written from the
    # engine's own output back when -replace was a literal str.replace, so it
    # asserted the bug. 'Q' appears in neither case.
    ("replace", "$d = 'maliciousQexampleQinvalid' -replace 'Q','.'; Write-Host $d", DOM),
    # Pins the semantics the old fixture silently assumed: -creplace IS
    # case-sensitive, so the lowercase 'x' survives.
    ("creplace-case-sensitive",
     "$d = 'maliciousXexampleXinvalid' -creplace 'X','.'; Write-Host $d",
     "malicious.example.invalid"),
    # ...and the case-insensitive default does not.
    ("replace-is-case-insensitive",
     "$d = 'BOOK' -replace 'b','C'; Write-Host $d", "COOK"),
    ("format-operator", "$d = '{0}.{1}.{2}' -f 'malicious','example','invalid'; Write-Host $d", DOM),
    ("backticks", "W`r`i`te-H`o`st 'malicious.example.invalid'", DOM),
    ("subexpression", '$d = "$([char]109)alicious.example.invalid"; Write-Host $d', DOM),
    ("string-cast", "$d = [string]'malicious.example.invalid'; Write-Host $d", DOM),
    ("char-arithmetic", "$c = [char](50+2); Write-Host $c", "4"),
    ("bxor", "$c = [char](109 -bxor 0); Write-Host $c", "m"),
    ("nested-parens", "$d = (('mal'+'icious') + '.' + ('exam'+'ple') + '.invalid'); Write-Host $d", DOM),
    ("trim", "$d = ('  malicious.example.invalid  ').Trim(); Write-Host $d", DOM),
    ("substring", "$d = 'ZZmalicious.example.invalidZZ'.Substring(2,25); Write-Host $d", DOM),
    ("array-reverse", "$c='dilavni.elpmaxe.suoicilam'.ToCharArray(); [Array]::Reverse($c); $d=(-join $c); Write-Host $d", DOM),
    ("interpolation", '$a=\'malicious\'; $b=\'example.invalid\'; Write-Host "C2=$a.$b"', DOM),
]


@pytest.mark.parametrize("name,source,want", CASES, ids=[c[0] for c in CASES])
def test_technique_is_resolved(name, source, want):
    assert want in recovered(source), f"{name} did not reveal {want!r}"


@pytest.mark.parametrize("name,source,_want", CASES, ids=[c[0] for c in CASES])
def test_nothing_passes_straight_through(name, source, _want):
    """A case producing no transform, no finding and no resolved value slipped
    past us entirely."""
    assert touched(source)
