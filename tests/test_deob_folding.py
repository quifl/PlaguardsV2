from plaguardsv2.GuardModules import PlagDeobfus as deobfuscate


def test_string_concatenation_folds():
    result = deobfuscate.run("$x = 'foo' + 'bar' + 'baz'")
    assert "'foobarbaz'" in result.deobfuscated
    assert result.pass_log


def test_char_code_resolution():
    # Resolves [char] code points, then the concatenation-folding pass joins
    # the two resulting literals into a single string.
    result = deobfuscate.run("[char]72 + [char]105")
    assert "'Hi'" in result.deobfuscated


def test_char_array_join():
    result = deobfuscate.run("[char[]](72,101,108,108,111) -join ''")
    assert "'Hello'" in result.deobfuscated


def test_bxor_char_resolution():
    # 'A' (65) xor 0x01 -> chr(64) = '@'
    result = deobfuscate.run("[char](65 -bxor 0x01)")
    assert "'@'" in result.deobfuscated


def test_format_operator_folds_literal_placeholders():
    result = deobfuscate.run("'{0}-{1}' -f 'foo','bar'")
    assert "'foo-bar'" in result.deobfuscated


def test_format_operator_leaves_out_of_range_placeholder():
    result = deobfuscate.run("'{0}-{5}' -f 'foo','bar'")
    assert "foo" in result.deobfuscated
    assert "{5}" in result.deobfuscated


def test_junk_backticks_stripped_outside_strings():
    result = deobfuscate.run("I`E`X (Get-Content 'file.txt')")
    assert "IEX" in result.deobfuscated
    assert "`" not in result.deobfuscated.split("(")[0]


def test_backticks_inside_strings_preserved():
    source = "$x = \"line1`nline2\""
    result = deobfuscate.run(source)
    assert "`n" in result.deobfuscated


def test_plaintext_input_passes_through_unchanged():
    source = "Write-Host 'nothing obfuscated here'"
    result = deobfuscate.run(source)
    assert result.deobfuscated == source
    assert result.pass_log == []
