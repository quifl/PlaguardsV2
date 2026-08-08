"""The multi-language corpus in deobf_testcases.zip.

Every file there is benign and inert by construction; each hides the same
banner behind a different technique and reveals it via echo/print. These
tests assert we actually get the cleartext back rather than just not
crashing on the input.
"""
import zipfile
from pathlib import Path

import pytest

from plaguardsv2.GuardModules import PlagDeobfus, PlagGrep, PlagTrace

CORPUS = Path(__file__).with_name("deobf_testcases.zip")

DOMAIN = "malicious.example.invalid"
IP = "198.51.100.42"

# What each case must yield once deobfuscated. Files that legitimately do not
# contain a value are simply not listed for it.
EXPECTED = {
    "01_ps1_techniques.ps1": ["Hello, World!", "Obfuscated", "a_b_c"],
    "02_ps1_layered.ps1": [DOMAIN, IP],
    "03_txt_encoded_blobs.txt": [DOMAIN, IP],
    "04_txt_encoded_command.txt": [DOMAIN, IP],
    "05_vbs_chr_concat.vbs": ["[INERT]", DOMAIN, IP],
    "06_vbs_strreverse.vbs": ["[INERT", DOMAIN, IP],
    "07_js_fromcharcode.js": ["[INERT]", DOMAIN, IP],
    "08_js_reverse_split.js": [DOMAIN, IP],
    "09_bat_set_concat.bat": ["[INERT]", DOMAIN, IP],
    "10_bat_substring.bat": ["[INERT]", DOMAIN, IP],
    "11_cmd_delayed_expansion.cmd": ["[INERT]", DOMAIN, IP],
    "12_cmd_for_tokens.cmd": ["[INERT]", IP],
    "13_log_sysmon_encoded.log": [DOMAIN, IP],
    "14_log_proxy_iocs.log": [DOMAIN, IP],
}


def _cases():
    if not CORPUS.exists():
        return []
    with zipfile.ZipFile(CORPUS) as archive:
        return [
            (name, archive.read(name).decode("utf-8", "replace"))
            for name in sorted(archive.namelist())
            if name in EXPECTED
        ]


CASES = _cases()


@pytest.mark.skipif(not CASES, reason="corpus archive not present")
@pytest.mark.parametrize("name,source", CASES, ids=[c[0] for c in CASES])
def test_corpus_case_reveals_its_cleartext(name, source):
    result = PlagDeobfus.run(source)
    traced = PlagTrace.trace(result.deobfuscated)
    # An analyst sees the script, the resolved variables and the findings, so
    # recovering a value into any of them counts.
    findings = PlagGrep.scan(
        result.original, result.deobfuscated, PlagTrace.enrichment_text(traced)
    )
    haystack = "\n".join([
        result.deobfuscated,
        "\n".join(traced.variables.values()),
        "\n".join(traced.revealed_strings),
        "\n".join(f.value for f in findings),
    ])

    missing = [want for want in EXPECTED[name] if want not in haystack]
    assert not missing, f"{name} did not reveal {missing}"


@pytest.mark.skipif(not CASES, reason="corpus archive not present")
def test_nothing_in_the_corpus_is_left_untouched_and_unexplained():
    """Every case should either be rewritten or produce findings - a file that
    yields neither means the technique passed straight through us."""
    barren = []
    for name, source in CASES:
        result = PlagDeobfus.run(source)
        traced = PlagTrace.trace(result.deobfuscated)
        findings = PlagGrep.scan(
            result.original, result.deobfuscated, PlagTrace.enrichment_text(traced)
        )
        if not result.pass_log and not findings:
            barren.append(name)
    assert not barren
