from plaguardsv2.GuardModules import PlagDeobfus as deobfuscate


def test_shellid_resolves_to_default_value():
    result = deobfuscate.run("$ShellId[1]")
    assert "'i'" in result.deobfuscated


def test_string_literal_indexing():
    result = deobfuscate.run("'Hello'[1]")
    assert "'e'" in result.deobfuscated


def test_string_literal_negative_indexing():
    result = deobfuscate.run("'Hello'[-1]")
    assert "'o'" in result.deobfuscated


def test_literal_variable_propagation():
    result = deobfuscate.run("$x = 'secret-value'\nWrite-Host $x")
    assert "'secret-value'" in result.deobfuscated.split("\n")[-1]


def test_reassigned_variable_not_propagated():
    source = "$v = 'first'\n$v = 'second'\nWrite-Host $v"
    result = deobfuscate.run(source)
    assert "$v" in result.deobfuscated.split("\n")[-1]


def test_accumulator_variable_not_propagated():
    source = '$buf = ""\n$buf += "x"\nWrite-Host $buf'
    result = deobfuscate.run(source)
    assert "$buf" in result.deobfuscated.split("\n")[-1]


def test_parenthesized_arithmetic_char_resolves():
    result = deobfuscate.run("[char](70 + 2)")
    assert "'H'" in result.deobfuscated


def test_bxor_still_resolves_alongside_paren_arith():
    result = deobfuscate.run("[char](97 -bxor 8)")
    assert "'i'" in result.deobfuscated


def test_xor_byte_array_gets_annotated():
    # 'H'=72, 'i'=105; key=1 -> bytes 73,104
    source = (
        "$Data = [byte[]]@(73,104)\n"
        "$Key = 1\n"
        "for($i=0;$i -lt $Data.Length;$i++){$Data[$i] = $Data[$i] -bxor $Key}\n"
    )
    result = deobfuscate.run(source)
    assert "PlaguardsV2" in result.deobfuscated
    assert "'Hi'" in result.deobfuscated


def test_numeric_array_char_loop_gets_annotated():
    source = (
        "$Codes = @(72, 105)\n"
        "$Out = ''\n"
        "foreach ($n in $Codes) {\n"
        "    $Out += [char]$n\n"
        "}\n"
    )
    result = deobfuscate.run(source)
    assert "PlaguardsV2" in result.deobfuscated
    assert "'Hi'" in result.deobfuscated


def test_annotation_passes_are_idempotent():
    source = (
        "$Data = [byte[]]@(73,104)\n"
        "$Key = 1\n"
        "for($i=0;$i -lt $Data.Length;$i++){$Data[$i] = $Data[$i] -bxor $Key}\n"
    )
    result = deobfuscate.run(source)
    assert result.deobfuscated.count("PlaguardsV2") == 1
