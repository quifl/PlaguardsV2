"""The byte-array loader recogniser, tested for generality rather than shape.

Every case is generated: the payload text, the key, its length, the variable
names, the index arithmetic, the operator and the compression all vary, and
the expected answer is whatever the generator encoded. A recogniser matching
one hard-coded shape - or echoing a remembered string - fails these.

The scripts themselves are assembled in loader_cases.py; see the note there.
"""
import base64
import os

import pytest
from loader_cases import build, deflate, encode

from plaguardsv2.GuardModules import PlagDeobfus, PlagGrep, PlagLoader, PlagTrace


def recovered(source: str) -> str:
    result = PlagDeobfus.run(source)
    traced = PlagTrace.trace(result.deobfuscated)
    findings = PlagGrep.scan(
        result.original, result.deobfuscated, PlagTrace.enrichment_text(traced)
    )
    return result.deobfuscated + "\n" + "\n".join(f.value for f in findings)


# Each case carries its own payload, so a remembered answer cannot satisfy it.
CASES = [
    ("four-byte key", b"domain=alpha.example.invalid\nip=203.0.113.9\n",
     bytes([90, 55, 193, 158]), {}),
    ("three-byte key", b"domain=bravo.example.invalid\nip=203.0.113.10\n",
     bytes([1, 2, 3]), {}),
    ("seven-byte key", b"domain=charlie.example.invalid\nip=203.0.113.11\n",
     bytes([9, 8, 7, 6, 5, 4, 3]), {}),
    ("single-byte key", b"domain=delta.example.invalid\nip=203.0.113.12\n",
     bytes([0x5A]), {}),
    ("renamed variables", b"domain=echo.example.invalid\nip=203.0.113.13\n",
     bytes([11, 22, 33, 44]),
     {"names": ("rollKey", "payload", "stage", "n")}),
    ("length held in a variable", b"domain=foxtrot.example.invalid\nip=203.0.113.14\n",
     bytes([5, 6, 7, 8]),
     {"names": ("rollKey", "payload", "stage", "n"),
      "length_var": "kLen", "keyidx": "$n % $kLen"}),
    ("literal key length", b"domain=golf.example.invalid\nip=203.0.113.15\n",
     bytes([2, 4, 6, 8]), {"keyidx": "$i % 4"}),
    ("backtick inside the operator", b"domain=hotel.example.invalid\nip=203.0.113.16\n",
     bytes([90, 55, 193, 158]), {"tick_in_op": True}),
    ("offset index arithmetic", b"domain=india.example.invalid\nip=203.0.113.17\n",
     bytes([3, 1, 4, 1, 5]), {"keyidx": "($i + 0) % $K.Length"}),
]


@pytest.mark.parametrize("name,payload,key,shape", CASES, ids=[c[0] for c in CASES])
def test_loader_shape_is_recovered(name, payload, key, shape):
    source = build(encode(payload, key), key, **shape)
    output = recovered(source)
    for line in payload.decode().strip().split("\n"):
        want = line.split("=", 1)[1]
        assert want in output, f"{name}: did not recover {want!r}"


def test_deflate_as_well_as_gzip():
    payload = b"domain=juliet.example.invalid\nip=203.0.113.18\n"
    key = bytes([3, 1, 4, 1, 5])
    source = build(encode(payload, key, compress=deflate), key, decompress="Deflate")
    assert "juliet.example.invalid" in recovered(source)


@pytest.mark.parametrize("op", ["+", "-"])
def test_addition_and_subtraction_loops(op):
    """Not every loader uses XOR."""
    payload = b"domain=kilo.example.invalid\n"
    key = bytes([17, 34, 51, 68])
    source = build(encode(payload, key, op=op), key, op=op)
    assert "kilo.example.invalid" in recovered(source)


def test_uncompressed_payload_is_recovered():
    payload = b"domain=lima.example.invalid\nip=203.0.113.20\n"
    key = bytes([200, 100, 50])
    source = build(encode(payload, key, compress=None), key, decompress=None)
    assert "lima.example.invalid" in recovered(source)


def test_the_payload_is_computed_not_remembered():
    """The same blob read with the wrong key must not yield the payload."""
    payload = b"domain=mike.example.invalid\n"
    right, wrong = bytes([1, 2, 3, 4]), bytes([9, 9, 9, 9])

    assert "mike.example.invalid" in recovered(build(encode(payload, right), right))
    assert "mike.example.invalid" in recovered(build(encode(payload, wrong), wrong))
    # Encoded with one key, declared with another.
    assert "mike.example.invalid" not in recovered(build(encode(payload, right), wrong))


def test_an_unresolvable_index_is_left_alone():
    """An index depending on something we cannot see must not be guessed at -
    better no answer than a wrong one."""
    key = bytes([1, 2, 3, 4])
    source = build(encode(b"domain=november.example.invalid\n", key), key,
                   keyidx="$i % $somethingWeCannotSee")
    _text, changed, _detail = PlagLoader.recover_xor_loop(source)
    assert not changed


def test_a_key_index_out_of_range_is_refused():
    key = bytes([1, 2, 3, 4])
    source = build(encode(b"domain=oscar.example.invalid\n", key), key,
                   keyidx="$i + 9999")
    _text, changed, _detail = PlagLoader.recover_xor_loop(source)
    assert not changed


def test_output_that_is_not_text_is_refused():
    """Random bytes combined with a key are still random bytes; presenting
    them as a payload would be worse than saying nothing."""
    key = bytes([1, 2, 3, 4])
    blob = base64.b64encode(os.urandom(400)).decode()
    source = build(blob, key, decompress=None)
    _text, changed, _detail = PlagLoader.recover_xor_loop(source)
    assert not changed


def test_recovery_happens_exactly_once():
    """The loader stays in the script, so the pass has to be idempotent."""
    key = bytes([90, 55, 193, 158])
    result = PlagDeobfus.run(build(encode(b"domain=papa.example.invalid\n", key), key))
    recoveries = [e for e in result.pass_log if "byte-array" in e]
    assert len(recoveries) == 1
    assert result.deobfuscated.count(PlagLoader.MARKER) == 1
