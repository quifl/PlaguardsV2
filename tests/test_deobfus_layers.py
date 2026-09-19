"""Guards the deobfuscation pass orchestrator itself.

Three classes of defect live here.

The first is silent payload destruction. `_decode_frombase64_literals` used to
run its second substitution over text its first had already rewritten, so a
second Base64 layer was quoted *inside* the literal the first layer had just
produced. The unescaped quotes fragmented that literal, the assignment folder
kept only the first fragment, and the pass log still reported a successful
decode. The analyst saw a truncated stub presented as a finished result.

The second is that a half-peeled script and a fully resolved one used to be
presented identically: nothing in the result said whether the pass loop
converged or ran out of budget, and nothing named the blobs that survived it.

The third is honesty about provenance - a value this engine supplied from an
assumed Windows default is weaker evidence than one folded out of the sample,
and the pass log has to say which it was.

Every script below is inert: it terminates in Write-Host, uses RFC 2606
reserved domains and RFC 5737 documentation addresses, and does nothing.
"""
import base64
import hashlib

from plaguardsv2.GuardModules import PlagDeobfus

MARKER_DOMAIN = "malicious.example.invalid"
MARKER_SCRIPT = f'Write-Host "{MARKER_DOMAIN}"'


def _wrap_base64(text: str) -> str:
    """One Base64 layer, in the [Text.Encoding]::UTF8.GetString(...) shape."""
    b64 = base64.b64encode(text.encode("utf-8")).decode()
    return f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}'))"


def _nest(payload: str, depth: int) -> str:
    text = payload
    for _ in range(depth):
        text = _wrap_base64(text)
    return text


def _opaque_stage_b64() -> str:
    """A Base64 blob whose bytes are not text and do not inflate.

    Every byte has its high bit set, so it can never be valid UTF-8 - the
    engine must leave it alone rather than mangle it into latin-1 mojibake.
    """
    digest = hashlib.sha512(b"plaguards-residual-blob").digest()
    return base64.b64encode(bytes(b | 0x80 for b in digest)).decode()


# --- B1: nested Base64 must not be destroyed ------------------------------

def test_nested_base64_recovers_marker_at_every_depth():
    for depth in range(1, 6):
        result = PlagDeobfus.run("$x = " + _nest(MARKER_SCRIPT, depth))
        assert MARKER_DOMAIN in result.deobfuscated, f"lost the payload at depth {depth}"
        assert "FromBase64String" not in result.deobfuscated, (
            f"depth {depth} left an undecoded layer behind"
        )


def test_nested_base64_does_not_truncate_at_the_first_quote():
    payload = (
        "Write-Host 'single-quoted-marker'; "
        f'Write-Host "double-quoted-{MARKER_DOMAIN}"'
    )
    result = PlagDeobfus.run("$x = " + _nest(payload, 3))
    assert "single-quoted-marker" in result.deobfuscated
    # The tail is the part that used to disappear: the literal fragmented at
    # the payload's own first quote and everything after it was discarded.
    assert f"double-quoted-{MARKER_DOMAIN}" in result.deobfuscated


def test_decoder_call_quoted_as_script_text_is_left_alone():
    # The call is data here, not code - it sits inside a literal the author
    # wrote. Rewriting it would corrupt the surrounding string.
    b64 = base64.b64encode(MARKER_SCRIPT.encode("utf-8")).decode()
    source = (
        f"$t = 'run [Convert]::FromBase64String(\"{b64}\") later'\n"
        "Write-Host 'done'"
    )
    result = PlagDeobfus.run(source)
    assert "FromBase64String" in result.deobfuscated


def test_pass_log_does_not_claim_a_decode_that_did_not_happen():
    source = (
        f"$s = [Convert]::FromBase64String('{_opaque_stage_b64()}')\n"
        "Write-Host 'done'"
    )
    result = PlagDeobfus.run(source)
    assert not any("literal(s)" in entry and "FromBase64String" in entry
                   for entry in result.pass_log), result.pass_log
    # The undecodable bytes stay exactly as submitted - a later pass may need
    # them, and mojibake would destroy them.
    assert _opaque_stage_b64() in result.deobfuscated


# --- B2: converged vs. gave up --------------------------------------------

def test_clean_script_converges():
    result = PlagDeobfus.run(f'Write-Host "{MARKER_DOMAIN}"\nWrite-Host "done"')
    assert result.converged is True
    assert not any("Fixed point not reached" in entry for entry in result.pass_log)


def test_nested_payload_converges_well_inside_the_pass_budget():
    result = PlagDeobfus.run("$x = " + _nest(MARKER_SCRIPT, 5))
    assert result.converged is True
    assert result.iterations < PlagDeobfus.MAX_PASSES


def test_exhausting_the_pass_budget_is_reported_as_not_converged(monkeypatch):
    # Squeezing the budget to a single round is the only deterministic way to
    # reach this path: on real input the loop stops because no pass can make
    # further progress, never because it runs out of iterations.
    monkeypatch.setattr(PlagDeobfus, "MAX_PASSES", 1)
    result = PlagDeobfus.run("$x = " + _nest(MARKER_SCRIPT, 2))
    assert result.converged is False
    assert any("Fixed point not reached" in entry for entry in result.pass_log)


# --- B3: residual high-entropy blobs --------------------------------------

def test_clean_script_reports_no_residual_blobs():
    source = (
        f'$target = "{MARKER_DOMAIN}"\n'
        '$port = 8080\n'
        'Write-Host "connecting to $target on $port"\n'
    )
    result = PlagDeobfus.run(source)
    assert result.residual_blobs == []


def test_unresolvable_stage_is_reported_as_a_residual_blob():
    blob = _opaque_stage_b64()
    source = (
        f"$s = [Convert]::FromBase64String('{blob}')\n"
        "Write-Host 'done'"
    )
    result = PlagDeobfus.run(source)
    assert result.residual_blobs, "an opaque encoded stage was reported as nothing"

    found = result.residual_blobs[0]
    assert found.length == len(blob)
    assert result.deobfuscated[found.offset:found.offset + found.length] == blob
    assert found.entropy > PlagDeobfus.RESIDUAL_ENTROPY_MIN
    assert found.reason
    assert any("high-entropy blob" in entry for entry in result.pass_log)


def test_a_recovered_payload_leaves_no_residual_blob_behind():
    result = PlagDeobfus.run("$x = " + _nest(MARKER_SCRIPT, 4))
    assert result.residual_blobs == []


# --- B4: assumed $env: defaults -------------------------------------------

def test_env_comspec_resolves_and_the_log_marks_it_assumed():
    result = PlagDeobfus.run("$c = $env:ComSpec\nWrite-Host $c")
    assert "cmd.exe" in result.deobfuscated
    entries = [e for e in result.pass_log if "$env:" in e]
    assert entries, result.pass_log
    assert all("assumed" in entry.lower() for entry in entries)


def test_env_character_slicing_spells_the_hidden_command():
    # The classic way to write IEX without the letters appearing anywhere.
    source = (
        "$a = $env:ComSpec[4]+$env:ComSpec[15]+$env:ComSpec[25]\n"
        "Write-Host $a"
    )
    result = PlagDeobfus.run(source)
    assert "iex" in result.deobfuscated.lower()


def test_an_env_variable_with_no_deterministic_value_is_left_unresolved():
    result = PlagDeobfus.run("Write-Host $env:USERNAME")
    assert "$env:USERNAME" in result.deobfuscated


def test_an_env_assignment_target_is_not_rewritten_into_a_literal():
    result = PlagDeobfus.run("$env:TEMP = 'staging'\nWrite-Host 'done'")
    assert "$env:TEMP =" in result.deobfuscated


# --- B5: structured transform provenance ----------------------------------

def test_transforms_record_previews_and_flag_assumed_values():
    result = PlagDeobfus.run("$c = $env:ComSpec\nWrite-Host $c")
    assumed = [t for t in result.transforms if t.assumed]
    assert assumed, result.transforms
    record = assumed[0]
    assert "$env:ComSpec" in record.before
    assert "cmd.exe" in record.after
    assert record.iteration >= 1


def test_a_derived_transform_is_not_flagged_as_assumed():
    result = PlagDeobfus.run("$x = " + _nest(MARKER_SCRIPT, 2))
    decodes = [t for t in result.transforms if "FromBase64String" in t.name]
    assert decodes, result.transforms
    assert all(t.assumed is False for t in decodes)
    assert MARKER_DOMAIN in decodes[0].after


def test_transforms_run_parallel_to_the_pass_log_without_changing_its_shape():
    result = PlagDeobfus.run("$c = $env:ComSpec\nWrite-Host $c")
    assert all(isinstance(entry, str) for entry in result.pass_log)
    # Every structured record has a pass_log line; the log may carry extra
    # summary lines (truncation, non-convergence, residual blobs) of its own.
    assert len(result.transforms) <= len(result.pass_log)
