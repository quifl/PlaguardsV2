"""Tests for multi-stage peeling: base64 -> reverse + -replace -> base64 ->
-split/[char] cast/-join, plus the defang helper used by reports."""
import base64

from plaguardsv2.GuardModules import PlagGrep, PlagTrace
from plaguardsv2.GuardModules.PlagEval import evaluate


def resolve(source: str) -> dict:
    return PlagTrace.trace(source).variables


def test_tochararray_and_array_reverse():
    resolved = resolve('$s = "abc"\n$c = $s.ToCharArray()\n[Array]::Reverse($c)\n$r = -join $c\n')
    assert resolved["r"] == "cba"


def test_int_cast():
    assert evaluate('[int]"65"', {}) == 65


def test_char_of_int_cast():
    assert evaluate('[char][int]"65"', {}) == "A"


def test_foreach_pipeline_char_codes():
    assert evaluate('("72,105" -split "," | %{[char][int]$_}) -join ""', {}) == "Hi"


def test_foreach_object_long_form():
    assert evaluate('("72,105" -split "," | ForEach-Object {[char][int]$_}) -join ""', {}) == "Hi"


def test_full_four_stage_peel():
    """Same shape as the real sample: b64 -> reverse+replace -> b64 -> codes."""
    plaintext = "IP=198.51.100.42"
    codes = ",".join(str(ord(ch)) for ch in plaintext)
    inner = base64.b64encode(codes.encode()).decode()
    outer = base64.b64encode(inner.replace("=", "_")[::-1].encode()).decode()

    src = (
        f'$L0="{outer}"\n'
        "$L1=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($L0))\n"
        "$c=$L1.ToCharArray()\n"
        "[Array]::Reverse($c)\n"
        '$L2b64=(-join $c) -replace "_","="\n'
        "$L2=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($L2b64))\n"
        '$L3=($L2 -split "," | %{[char][int]$_}) -join ""\n'
    )
    assert resolve(src)["L3"] == plaintext


def test_multistage_result_feeds_ioc_extraction():
    plaintext = "C2=malicious.example.invalid"
    codes = ",".join(str(ord(ch)) for ch in plaintext)
    inner = base64.b64encode(codes.encode()).decode()
    src = (
        f'$a="{inner}"\n'
        "$b=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($a))\n"
        '$c=($b -split "," | %{[char][int]$_}) -join ""\n'
    )
    resolved = PlagTrace.trace(src)
    findings = PlagGrep.scan("", src, PlagTrace.enrichment_text(resolved))
    assert any(f.type == "domain" and f.value == "malicious.example.invalid" for f in findings)


def test_defang_network_indicators():
    assert PlagGrep.defang("1.2.3.4", "ip") == "1[.]2[.]3[.]4"
    assert PlagGrep.defang("http://bad.example.invalid/x", "url").startswith("hxxp://")
    assert PlagGrep.defang("a@b.com", "email") == "a[@]b[.]com"


def test_defang_leaves_non_network_types_alone():
    assert PlagGrep.defang("Global\\ABAD-IDEA-123", "mutex") == "Global\\ABAD-IDEA-123"
    assert PlagGrep.defang("EVILBOT/1.0", "user_agent") == "EVILBOT/1.0"


def test_bare_product_token_detected_as_user_agent():
    findings = PlagGrep.scan("", "UA=EVILBOT/1.0")
    assert any(f.type == "user_agent" and f.value == "EVILBOT/1.0" for f in findings)
