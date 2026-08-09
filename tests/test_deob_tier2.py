"""Tier-2 cases: the ones that need more than one trick undone at a time.

Each of these came from a real failure where the tool showed a resolved value
but reported no findings, or resolved nothing at all. Sources are built from
fragments rather than written out, so real-time AV leaves the file alone.
"""
import base64
import gzip

from plaguardsv2.GuardModules import PlagDeobfus, PlagEval, PlagGrep, PlagTrace

DOM = "cdn.malicious.example.invalid"
BANNER = (f"[INERT] tier2 | C2={DOM} | IP=198.51.100.42:4444 | UA=EVILBOT/1.0")

KEY = bytes([90, 55, 193, 158])
PAYLOAD = (
    f"domain={DOM}\n"
    f"url=http://{DOM}/stage2.bin\n"
    "ipport=198.51.100.42:4444\n"
    "ua=EVILBOT/1.0\n"
    "mutex=Global\\ABAD-IDEA-123\n"
    "sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
)


def recovered(source: str) -> str:
    """Everything an analyst would see, flattened."""
    result = PlagDeobfus.run(source)
    traced = PlagTrace.trace(result.deobfuscated)
    findings = PlagGrep.scan(
        result.original, result.deobfuscated, PlagTrace.enrichment_text(traced)
    )
    return "\n".join([
        result.deobfuscated,
        "\n".join(str(v) for v in traced.variables.values()),
        "\n".join(traced.revealed_strings),
        "\n".join(f.value for f in findings),
    ])


def findings_for(source: str):
    result = PlagDeobfus.run(source)
    traced = PlagTrace.trace(result.deobfuscated)
    return PlagGrep.scan(
        result.original, result.deobfuscated, PlagTrace.enrichment_text(traced)
    )


def test_a_variable_holding_an_encoded_stage_still_produces_findings():
    """The dashboard showed the decoded banner while Findings said zero: the
    decoded stage was rendered but never handed to the scanner."""
    blob = base64.b64encode(BANNER.encode()).decode()
    source = (
        f"$b = '{blob}'\n"
        '$out = "$([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))"'
    )
    values = [f.value for f in findings_for(source)]
    assert DOM in values
    assert "198.51.100.42:4444" in values


def test_split_treats_its_separator_as_a_regex():
    """`-split "\\|"` means a literal pipe. Splitting on the two characters
    returns the whole string and the payload never resolves."""
    assert PlagEval.evaluate(r'"a|b|c" -split "\|"', {}) == ["a", "b", "c"]
    # A plain separator is still a plain separator.
    assert PlagEval.evaluate('"a,b,c" -split ","', {}) == ["a", "b", "c"]


def test_a_pipe_separated_char_code_list_resolves():
    codes = "|".join(str(ord(c)) for c in BANNER)
    source = (
        f"$c = '{codes}'\n"
        '$d = ($c -split "\\|" | %{[char][int]$_}) -join ""\n'
    )
    assert DOM in recovered(source)


def test_bitwise_operators_fold():
    assert PlagEval.evaluate("65 -bxor 42", {}) == 107
    assert PlagEval.evaluate("12 -band 10", {}) == 8
    assert PlagEval.evaluate("12 -bor 3", {}) == 15
    # And with the key held in a variable, as a real sample would.
    assert PlagEval.evaluate("$k -bxor 42", {"k": 65}) == 107


def test_an_xor_pipeline_with_a_variable_key_resolves():
    codes = ",".join(str(ord(c) ^ 42) for c in BANNER)
    source = (
        "$k = 42\n"
        f"$c = '{codes}'\n"
        '$d = ($c -split "," | %{[char]([int]$_ -bxor $k)}) -join ""\n'
    )
    assert DOM in recovered(source)


def _loader_source() -> str:
    """base64 -> XOR against a repeating key -> gzip, the standard shape."""
    packed = gzip.compress(PAYLOAD.encode())
    encoded = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(packed))
    blob = base64.b64encode(encoded).decode()
    return (
        "$K = [byte[]](90,55,193,158)\n"
        f'$b = [Convert]::FromBase64String("{blob}")\n'
        "$x = New-Object byte[] $b.Length\n"
        "for ($i=0; $i -lt $b.Length; $i++) "
        "{ $x[$i] = $b[$i] -bxor $K[$i % $K.Length] }\n"
        "$ms = New-Object IO.MemoryStream(,$x)\n"
        "$gz = New-Object IO.Compression.GzipStream"
        "($ms,[IO.Compression.CompressionMode]::Decompress)\n"
        "$rec = (New-Object IO.StreamReader($gz)).ReadToEnd()\n"
    )


def test_the_xor_plus_gzip_loader_gives_up_its_payload():
    blob = recovered(_loader_source())
    for want in (
        DOM,
        f"http://{DOM}/stage2.bin",
        "198.51.100.42:4444",
        "EVILBOT/1.0",
        "Global\\ABAD-IDEA-123",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ):
        assert want in blob, f"loader did not reveal {want!r}"


def test_the_loader_payload_is_recovered_exactly_once():
    """The loader stays in the script, so the pass has to be idempotent or it
    appends the payload again on every round."""
    result = PlagDeobfus.run(_loader_source())
    recoveries = [e for e in result.pass_log if "XOR-decoded byte-array" in e]
    assert len(recoveries) == 1
    assert result.deobfuscated.count("# [recovered payload:") == 1


def test_a_binary_base64_stage_is_left_as_bytes():
    """Rendering an encrypted stage as latin-1 mojibake destroys the bytes a
    later pass needs, so a blob that is not text stays encoded."""
    encrypted = bytes(b ^ 0x5A for b in gzip.compress(b"x" * 200))
    blob = base64.b64encode(encrypted).decode()
    source = f'$b = [Convert]::FromBase64String("{blob}")'
    result = PlagDeobfus.run(source)
    assert "FromBase64String" in result.deobfuscated
