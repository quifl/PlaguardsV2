"""Semantic guards for the static expression evaluator (PlagTokens/PlagEval).

The defect class this module exists to catch is *silent corruption*: an
expression the evaluator answers confidently and wrongly, rather than
refusing with UNKNOWN. A missed construct only loses an indicator; a wrong
one invents indicators that were never in the sample, and those flow straight
into IOC extraction and the analyst report.

So most assertions here come in pairs - one pinning a newly supported
construct, one pinning the refusal or the regression that the new support
could plausibly break. Everything evaluated is a literal fold; nothing is
executed, and no script here does anything but terminate.
"""
import time

from plaguardsv2.GuardModules import PlagTokens
from plaguardsv2.GuardModules.PlagEval import UNKNOWN, evaluate

DOMAIN = "malicious.example.invalid"
IP = "198.51.100.24"


# -- A1: hex / binary literals ------------------------------------------------

def test_hex_literal_is_not_truncated_to_zero():
    # `\d+` matched only the "0" of 0x41, so the byte silently became NUL.
    assert evaluate("[char]0x41", {}) == "A"
    assert evaluate("0x40 + 1", {}) == 65


def test_binary_literal_and_multiplier_suffix():
    assert evaluate("0b1010", {}) == 10
    assert evaluate("1kb", {}) == 1024


def test_number_suffix_does_not_swallow_an_identifier():
    # `10tbsp` is a number then a name - not 10 terabytes.
    tokens = PlagTokens.tokenize("10tbsp")
    assert [(t.kind, t.value) for t in tokens] == [("num", "10"), ("name", "tbsp")]


# -- A2: shl / shr / bnot -----------------------------------------------------

def test_shift_operators_resolve():
    assert evaluate("1 -shl 8", {}) == 256
    assert evaluate("1024 -shr 4", {}) == 64


def test_shift_wraps_at_the_powershell_int_width():
    # PowerShell shifts an [int] in 32 bits, so this overflows to negative
    # rather than growing without bound the way a Python int would.
    assert evaluate("255 -shl 24", {}) == -16777216


def test_bnot_is_unary():
    assert evaluate("-bnot 5", {}) == -6
    # Dispatched from the binary path it would have eaten the left operand.
    assert evaluate("7 + (-bnot 0)", {}) == 6


# -- A3: modulo, disambiguated from the ForEach-Object alias ------------------

def test_modulo_resolves():
    assert evaluate("65 % 10", {}) == 5
    assert evaluate("-7 % 3", {}) == -1   # sign follows the dividend


def test_multiplicative_binds_tighter_than_additive():
    assert evaluate("2 + 3 * 4", {}) == 14


def test_foreach_object_pipeline_still_parses():
    # REGRESSION GUARD. Treating '%' as an operator everywhere broke every
    # `| %{ ... }` pipeline in the corpus; it is only modulo after a value.
    assert evaluate('((109,97,108) | %{[char][int]$_}) -join ""', {}) == "mal"
    assert evaluate('("72,105" -split "," | %{[char][int]$_}) -join ""', {}) == "Hi"


def test_percent_after_a_pipe_lexes_as_punctuation():
    kinds = {(t.kind, t.value) for t in PlagTokens.tokenize("$a | %{$_}")}
    assert ("punct", "%") in kinds
    assert ("op", "%") in {(t.kind, t.value) for t in PlagTokens.tokenize("$a % 3")}


# -- A4: -replace is a regex, and case-insensitive by default -----------------

def test_replace_operator_uses_regex():
    assert evaluate("'a1b2c3' -replace '[0-9]',''", {}) == "abc"
    # '.' is regex ANY, so every character is replaced - not just the dot.
    assert evaluate("'a.b' -replace '.','X'", {}) == "XXX"


def test_replace_documented_expectations():
    # The three examples from about_Comparison_Operators (PowerShell 7.6).
    assert evaluate("'5.72' -replace '(.+)','$$$1'", {}) == "$5.72"
    assert evaluate("'book' -ireplace 'B','C'", {}) == "Cook"
    assert evaluate("'book' -creplace 'B','C'", {}) == "book"


def test_replace_is_case_insensitive_by_default():
    assert evaluate("'ABC' -replace 'abc','z'", {}) == "z"


def test_replace_backreference_forms():
    assert evaluate("'a-b' -replace '(\\w)-(\\w)','${2}-${1}'", {}) == "b-a"
    assert evaluate("'ab' -replace 'a','[$&]'", {}) == "[a]b"


def test_malformed_pattern_yields_unknown_not_a_literal_fallback():
    # PowerShell throws here. A literal replace would invent a value it would
    # never have produced, which is worse than refusing.
    assert evaluate("'abc' -replace '[','x'", {}) is UNKNOWN
    assert evaluate("'abc' -replace '(unclosed','x'", {}) is UNKNOWN


def test_replace_folds_a_defanged_indicator():
    assert evaluate("'malicious[.]example[.]invalid' -replace '\\[\\.\\]','.'", {}) == DOMAIN


# -- A5: ReDoS structural guards ---------------------------------------------

def test_nested_quantifier_pattern_returns_unknown_quickly():
    target = "a" * 40 + "!"
    started = time.monotonic()
    result = evaluate(f"'{target}' -replace '(a+)+$','X'", {})
    assert result is UNKNOWN
    assert time.monotonic() - started < 1.0


def test_split_shares_the_same_guard():
    target = "b" * 40 + "!"
    started = time.monotonic()
    assert evaluate(f"'{target}' -split '(b*)*$'", {}) is UNKNOWN
    assert time.monotonic() - started < 1.0


def test_oversized_pattern_is_refused():
    assert evaluate("'abc' -replace '%s','x'" % ("a" * 300), {}) is UNKNOWN


def test_ordinary_grouped_pattern_is_not_refused():
    # The guard must not be so broad that normal patterns stop resolving.
    assert evaluate("'2026-09-18' -replace '(\\d+)-(\\d+)-(\\d+)','$3'", {}) == "18"


# -- A6: -f format specifiers -------------------------------------------------

def test_format_specifiers_resolve():
    assert evaluate('"{0:X2}" -f 65', {}) == "41"
    assert evaluate('"{0:x2}" -f 255', {}) == "ff"
    assert evaluate('"{0:D3}" -f 7', {}) == "007"
    assert evaluate('"{0:N2}" -f 1234', {}) == "1,234.00"


def test_format_alignment():
    assert evaluate('"{0,-4}|" -f "ab"', {}) == "ab  |"
    assert evaluate('"{0,6}|" -f "ab"', {}) == "    ab|"


def test_format_escaped_braces():
    assert evaluate('"{{0}}" -f "a"', {}) == "{0}"


def test_unfillable_index_yields_unknown_not_a_leaked_template():
    # Handing "{5}" downstream as a resolved value is the corruption case.
    assert evaluate('"{0}-{5}" -f "a","b"', {}) is UNKNOWN
    assert evaluate('"{0:Q9}" -f 5', {}) is UNKNOWN


def test_malformed_template_yields_unknown():
    assert evaluate('"{0:X2" -f 65', {}) is UNKNOWN


# -- A7: [Convert] beyond FromBase64String ------------------------------------

def test_convert_toint32_with_base():
    assert evaluate('[char][Convert]::ToInt32("41",16)', {}) == "A"
    assert evaluate('[Convert]::ToInt32("1010",2)', {}) == 10


def test_convert_toint32_reads_a_non_decimal_string_as_twos_complement():
    # .NET semantics: the digits are the bit pattern, so this is -1, not 2**32-1.
    assert evaluate('[Convert]::ToInt32("FFFFFFFF",16)', {}) == -1
    assert evaluate('[Convert]::ToInt16("FFFFFFFF",16)', {}) is UNKNOWN


def test_convert_tochar_tobyte_tostring_tobase64():
    assert evaluate("[Convert]::ToChar(65)", {}) == "A"
    assert evaluate('[Convert]::ToByte("FF",16)', {}) == 255
    assert evaluate("[Convert]::ToString(65,16)", {}) == "41"
    assert evaluate("[Convert]::ToBase64String([byte[]](104,105))", {}) == "aGk="


def test_convert_rejects_an_unsupported_base():
    assert evaluate('[Convert]::ToInt32("77",7)', {}) is UNKNOWN


# -- A8: postfix indexing -----------------------------------------------------

def test_single_index_returns_one_character():
    # This used to return the whole string, unindexed.
    assert evaluate('"ABC"[0]', {}) == "A"
    assert evaluate('"ABCDE"[-1]', {}) == "E"


def test_ascending_and_descending_ranges():
    assert evaluate('("ABCDEF"[1..3] -join "")', {}) == "BCD"
    # A descending range is how a script reverses a string.
    assert evaluate('("DCBA"[3..0] -join "")', {}) == "ABCD"


def test_multi_index_yields_an_array():
    assert evaluate('("ABCDEF"[0,2,4] -join "")', {}) == "ACE"


def test_out_of_range_index_is_unknown_not_an_invented_character():
    assert evaluate('"ABC"[9]', {}) is UNKNOWN
    assert evaluate('("ABC"[0..9] -join "")', {}) is UNKNOWN


def test_indexing_reverses_a_domain_written_backwards():
    reversed_domain = DOMAIN[::-1]
    expr = "('%s'[%d..0] -join '')" % (reversed_domain, len(DOMAIN) - 1)
    assert evaluate(expr, {}) == DOMAIN


def test_indexing_a_list_variable():
    assert evaluate("$parts[1]", {"parts": ["a", IP, "c"]}) == IP


# -- A9: the string method set, and the -replace / .Replace distinction -------

def test_replace_method_stays_literal():
    # String.Replace is ordinal; only the -replace OPERATOR is a regex. A
    # future change that unified them would be caught right here.
    assert evaluate('"a.b".Replace(".","X")', {}) == "aXb"
    assert evaluate('"a.b" -replace ".","X"', {}) == "XXX"


def test_replace_method_is_case_sensitive_unlike_the_operator():
    assert evaluate('"book".Replace("B","C")', {}) == "book"
    assert evaluate('"book" -replace "B","C"', {}) == "Cook"


def test_insert_remove_pad():
    assert evaluate('"abc".Insert(1,"Z")', {}) == "aZbc"
    assert evaluate('"abcdef".Remove(2,2)', {}) == "abef"
    assert evaluate('"7".PadLeft(3,"0")', {}) == "007"
    assert evaluate('"7".PadRight(3,"-")', {}) == "7--"


def test_indexof_lastindexof_and_predicates():
    assert evaluate('"abcab".IndexOf("b")', {}) == 1
    assert evaluate('"abcab".LastIndexOf("b")', {}) == 4
    assert evaluate('"abcab".IndexOf("z")', {}) == -1
    assert evaluate('"abc".Contains("b")', {}) is True
    assert evaluate('"abc".StartsWith("a")', {}) is True
    assert evaluate('"abc".EndsWith("z")', {}) is False


def test_trimstart_and_trimend():
    assert evaluate('"xxabcxx".TrimStart("x")', {}) == "abcxx"
    assert evaluate('"xxabcxx".TrimEnd("x")', {}) == "xxabc"
    assert evaluate('"  abc  ".Trim()', {}) == "abc"


def test_substring_out_of_range_is_unknown():
    # .NET throws; Python slicing would quietly hand back a short string that
    # looks like a resolved value.
    assert evaluate('"abc".Substring(5)', {}) is UNKNOWN
    assert evaluate('"abc".Substring(1,10)', {}) is UNKNOWN


def test_method_chain_on_a_decoded_byte_array():
    expr = '[Text.Encoding]::ASCII.GetString([byte[]](32,65,66,67,32)).Trim()'
    assert evaluate(expr, {}) == "ABC"


# -- end-to-end idioms the fixes exist to resolve -----------------------------

def test_hex_pair_decoder_resolves_to_a_domain():
    pairs = ",".join(f"{ord(c):02X}" for c in DOMAIN)
    expr = '("%s" -split "," | %%{[char][Convert]::ToInt32($_,16)}) -join ""' % pairs
    assert evaluate(expr, {}) == DOMAIN


def test_format_built_indicator_resolves():
    assert evaluate('"{0}.{1}.{2}" -f "malicious","example","invalid"', {}) == DOMAIN
