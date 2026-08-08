"""The IOC Checker's type selection.

The original Plaguards asked for a query type up front - hash, signature,
domain or ip. Auto-detection covers three of those from the value's shape,
but a malware signature has no shape, so the type still has to be choosable.
"""
from plaguardsv2.GuardModules import PlagEncode, PlagGrep, PlagJs, PlagLinks, PlagVbs


def test_auto_detects_from_the_shape_of_the_value():
    for value, expected in [
        ("198.51.100.42", "ip"),
        ("example.com", "domain"),
        ("http://example.com/a", "url"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash_md5"),
        ("a" * 40, "hash_sha1"),
        ("a" * 64, "hash_sha256"),
    ]:
        found, note = PlagGrep.resolve_lookup_type(value, "auto")
        assert (found, note) == (expected, "")


def test_a_signature_can_only_be_reached_by_choosing_the_type():
    """"AgentTesla" is not an indicator shape, so auto-detect cannot find it."""
    assert PlagGrep.resolve_lookup_type("AgentTesla", "auto")[0] is None
    assert PlagGrep.resolve_lookup_type("AgentTesla", "signature") == ("signature", "")


def test_auto_explains_itself_when_it_cannot_tell():
    found, note = PlagGrep.resolve_lookup_type("not an ioc", "auto")
    assert found is None
    assert "malware signature" in note


def test_hash_length_decides_the_digest():
    assert PlagGrep.resolve_lookup_type("a" * 32, "hash")[0] == "hash_md5"
    assert PlagGrep.resolve_lookup_type("a" * 64, "hash")[0] == "hash_sha256"
    found, note = PlagGrep.resolve_lookup_type("nope", "hash")
    assert found is None and "32, 40 or 64" in note


def test_an_explicit_choice_is_honoured_but_flagged():
    """Forcing a type still runs the lookup - it just says the value looks
    wrong, rather than silently checking something else."""
    found, note = PlagGrep.resolve_lookup_type("not-an-ip", "ip")
    assert found == "ip"
    assert "doesn't look like" in note


def test_the_signature_lookup_links_to_malwarebazaar():
    assert PlagLinks.reference_url("abusech", "signature", "AgentTesla") == \
        "https://bazaar.abuse.ch/browse/signature/AgentTesla/"
    # Providers with no notion of a family get no link.
    assert PlagLinks.reference_url("shodan", "signature", "AgentTesla") is None
    assert PlagLinks.reference_url("pulsedive", "signature", "AgentTesla") is None


def test_abusech_accepts_the_signature_type():
    from plaguardsv2.GuardModules.PlagProviders import abusech

    assert "signature" in abusech.SUPPORTS
    # Without a key nothing is attempted, so this makes no network call.
    assert abusech.lookup("signature", "AgentTesla", None)["verdict"] == "not_checked"


def test_shared_decoders_only_accept_readable_output():
    assert PlagEncode.decode_escapes(r"\x48\x69") == "Hi"
    assert PlagEncode.decode_percent("%48%69") == "Hi"
    assert PlagEncode.decode_base64("W0lORVJUXSBkZW1vIGJhbm5lciB0ZXh0") == "[INERT] demo banner text"
    # Too short to be a payload, and binary that merely parses as base64.
    assert PlagEncode.decode_base64("YWJj") is None
    assert PlagEncode.decode_base64("//////////////////////8=") is None


def test_jscript_decodes_atob_unescape_and_escapes():
    text, changed, _ = PlagJs.decode_encodings(
        'var a = atob("W0lORVJUXSBkZW1vIGJhbm5lciB0ZXh0");'
    )
    assert changed and "[INERT] demo banner text" in text

    text, changed, _ = PlagJs.decode_encodings('var b = unescape("%48%69");')
    assert changed and '"Hi"' in text

    text, changed, _ = PlagJs.decode_encodings(r'var c = "\x48\x69";')
    assert changed and '"Hi"' in text


def test_jscript_propagates_single_assignment_literals():
    src = 'var dom = "malicious.example.invalid";\nWScript.Echo(dom);'
    text, changed, _ = PlagJs.track_variables(src)
    assert changed
    assert 'WScript.Echo("malicious.example.invalid")' in text


def test_a_reassigned_jscript_variable_is_left_alone():
    """Which value applies at a given line is exactly what a static pass
    cannot know, so it must not guess."""
    src = 'var x = "one";\nvar x = "two";\nWScript.Echo(x);'
    _text, changed, _ = PlagJs.track_variables(src)
    assert not changed


def test_vbscript_decodes_base64_and_propagates_literals():
    text, changed, _ = PlagVbs.decode_base64_literals(
        's = "W0lORVJUXSBkZW1vIGJhbm5lciB0ZXh0"'
    )
    assert changed and "[INERT] demo banner text" in text

    src = 'dom = "malicious.example.invalid"\nWScript.Echo dom'
    text, changed, _ = PlagVbs.track_variables(src)
    assert changed
    assert 'WScript.Echo "malicious.example.invalid"' in text


def test_powershell_string_casts_go_but_static_calls_stay():
    from plaguardsv2.GuardModules import PlagDeobfus

    result = PlagDeobfus.run('$a = [string]$env:temp\n$b = [string]::Join("+", $parts)')
    assert "[string]$env:temp" not in result.deobfuscated
    # A static method call on the String type is not a cast.
    assert '[string]::Join("+", $parts)' in result.deobfuscated
