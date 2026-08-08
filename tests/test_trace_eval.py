"""Tests for the static expression evaluator and sequential variable
tracker (PlagEval / PlagTrace)."""
from plaguardsv2.GuardModules import PlagTrace
from plaguardsv2.GuardModules.PlagEval import UNKNOWN, evaluate


def resolve(source: str) -> dict:
    return PlagTrace.trace(source).variables


def test_literal_concatenation():
    assert evaluate("'a' + 'b' + 'c'", {}) == "abc"


def test_variable_reference():
    assert evaluate("'x' + $v", {"v": "y"}) == "xy"


def test_unknown_variable_yields_unknown():
    assert evaluate("'x' + $missing", {}) is UNKNOWN


def test_char_from_arithmetic():
    assert evaluate("[char](50+2)", {}) == "4"


def test_join_operator():
    assert evaluate('("a","b","c") -join "-"', {}) == "a-b-c"


def test_split_then_join():
    assert evaluate('("a,b,c" -split ",") -join ""', {}) == "abc"


def test_replace_operator():
    assert evaluate('"a__b" -replace "__","-"', {}) == "a-b"


def test_dot_replace_method():
    assert evaluate('"a_b".Replace("_","-")', {}) == "a-b"


def test_base64_via_encoding_without_system_prefix():
    # [Text.Encoding] rather than [System.Text.Encoding]
    expr = '[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("aGVsbG8="))'
    assert evaluate(expr, {}) == "hello"


def test_byte_array_to_string():
    assert evaluate("[Text.Encoding]::ASCII.GetString([byte[]](77,85,84,69,88))", {}) == "MUTEX"


def test_format_operator():
    assert evaluate("'{0}-{1}' -f 'a','b'", {}) == "a-b"


def test_sequential_reassignment_is_tracked():
    resolved = resolve('$d = "example.invalid"\n$d = "malicious." + $d\n')
    assert resolved["d"] == "malicious.example.invalid"


def test_multiple_statements_on_one_line():
    resolved = resolve('$a="1";$b=$a+"2";$c=$b+"3"')
    assert resolved["c"] == "123"


def test_unresolvable_reassignment_forgets_stale_value():
    resolved = resolve('$a = "safe"\n$a = Get-Something\n')
    assert "a" not in resolved


def test_interpolated_string_is_revealed():
    result = PlagTrace.trace('$h="10.0.0.1"\nWrite-Host "HOST=$h"\n')
    assert any("HOST=10.0.0.1" in s for s in result.revealed_strings)


def test_semicolons_inside_quotes_do_not_split():
    resolved = resolve('$a = "x;y"\n')
    assert resolved["a"] == "x;y"
