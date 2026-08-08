import base64
import gzip

from plaguardsv2.GuardModules import PlagDeobfus as deobfuscate


def test_encoded_command_decodes_utf16le():
    payload = "Write-Host 'hello world'"
    b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
    source = f"powershell.exe -NoP -W Hidden -Enc {b64}"
    result = deobfuscate.run(source)
    assert "Write-Host 'hello world'" in result.deobfuscated
    assert any("EncodedCommand" in entry for entry in result.pass_log)


def test_frombase64string_literal_decodes():
    payload = "decoded-text-marker"
    b64 = base64.b64encode(payload.encode("utf-8")).decode()
    source = f"[Convert]::FromBase64String('{b64}')"
    result = deobfuscate.run(source)
    assert "decoded-text-marker" in result.deobfuscated


def test_frombase64string_with_encoding_wrapper_decodes():
    payload = "other-text-marker"
    b64 = base64.b64encode(payload.encode("utf-8")).decode()
    source = f"[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}'))"
    result = deobfuscate.run(source)
    assert "other-text-marker" in result.deobfuscated


def test_large_input_is_truncated_not_crashed():
    huge = "a" * (deobfuscate.MAX_INPUT_SIZE + 1000)
    result = deobfuscate.run(huge)
    assert result.truncated is True
    assert len(result.deobfuscated) <= deobfuscate.MAX_INPUT_SIZE


def test_gzip_compressed_base64_literal_auto_inflates():
    # A base64 blob that decodes to gzip-compressed bytes rather than plain
    # text (a common way to shrink/obscure a staged payload) should be
    # transparently inflated as part of the normal FromBase64String pass.
    payload = "stage2-payload-marker"
    compressed = gzip.compress(payload.encode("utf-8"))
    b64 = base64.b64encode(compressed).decode()
    source = f"[Convert]::FromBase64String('{b64}')"
    result = deobfuscate.run(source)
    assert "stage2-payload-marker" in result.deobfuscated


def test_utf32_encoding_wrapper_decodes():
    payload = "utf32-marker"
    b64 = base64.b64encode(payload.encode("utf-32-le")).decode()
    source = f"[System.Text.Encoding]::UTF32.GetString([Convert]::FromBase64String('{b64}'))"
    result = deobfuscate.run(source)
    assert "utf32-marker" in result.deobfuscated


def test_nested_obfuscation_resolves_across_passes():
    inner = "[char[]](72,105) -join ''"
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
    source = f"-EncodedCommand {b64}"
    result = deobfuscate.run(source)
    assert "'Hi'" in result.deobfuscated
    assert result.iterations >= 2
