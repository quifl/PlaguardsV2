"""Regression tests for a real corruption bug found during manual testing:
a quote character inside a comment (e.g. `# -> "value"`) could pair with an
unrelated quote elsewhere in the code, causing folding passes to treat real
code in between as part of a bogus string literal and delete/mangle it.
Fixed by masking comments before any pass runs and validating that folded
spans correspond to genuine string literals."""
from plaguardsv2.GuardModules import PlagDeobfus as deobfuscate


def test_quoted_text_in_comment_does_not_corrupt_following_code():
    source = (
        '$join1 = $parts -join ""                # -> "Obfuscated"\n'
        '$join2 = [string]::Join("+", $parts)     # -> "Ob+fus+cated"\n'
    )
    result = deobfuscate.run(source)
    assert '[string]::Join("+", $parts)' in result.deobfuscated
    assert '# -> "Obfuscated"' in result.deobfuscated
    assert '# -> "Ob+fus+cated"' in result.deobfuscated


def test_comment_with_quotes_is_preserved_verbatim():
    source = 'Write-Host "hi"   # a "quoted" aside, and another "one"\n'
    result = deobfuscate.run(source)
    assert '# a "quoted" aside, and another "one"' in result.deobfuscated


def test_block_comment_with_quotes_is_preserved():
    source = '<# note: "value" appears here #>\nWrite-Host "hi"\n'
    result = deobfuscate.run(source)
    assert '<# note: "value" appears here #>' in result.deobfuscated
    assert 'Write-Host "hi"' in result.deobfuscated


def test_quote_inside_string_literal_is_not_treated_as_comment():
    source = "$x = 'contains # not a comment'\nWrite-Host $x\n"
    result = deobfuscate.run(source)
    assert "contains # not a comment" in result.deobfuscated


def test_real_adjacent_literals_still_fold_despite_nearby_comment_quotes():
    source = (
        "$greeting = 'Hello, ' + 'World!'   # -> \"Hello, World!\"\n"
    )
    result = deobfuscate.run(source)
    assert "'Hello, World!'" in result.deobfuscated
