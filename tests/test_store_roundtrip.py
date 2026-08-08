"""Regression tests for a bug where a stored analysis reloaded from the
database exposed only `original_text` / `deobfuscated_text`, while the web
templates and the PDF report read `original` / `deobfuscated`. Stored
analyses therefore rendered empty script bodies and empty PDF appendices,
and the report's SHA-256 was the hash of an empty string. The CLI hid the
problem because it renders the in-memory result dict instead."""
from plaguardsv2.GuardModules import PlagEngine, PlagStore

SCRIPT = "$a = 'hello'\nWrite-Host $a\n"


def _stored():
    conn = PlagStore.get_conn(":memory:")
    result = PlagEngine.run_analysis(SCRIPT, filename="demo.ps1", skip_intel=True, conn=conn)
    return conn, PlagStore.get_analysis(conn, result["id"])


def test_stored_analysis_exposes_canonical_text_keys():
    _, stored = _stored()
    assert stored["original"], "reloaded analysis must expose non-empty 'original'"
    assert stored["deobfuscated"], "reloaded analysis must expose non-empty 'deobfuscated'"


def test_stored_text_matches_source():
    _, stored = _stored()
    assert "hello" in stored["original"]
    assert stored["original"] == stored["original_text"]
    assert stored["deobfuscated"] == stored["deobfuscated_text"]


def test_stored_analysis_records_source_kind():
    conn = PlagStore.get_conn(":memory:")
    pasted = PlagEngine.run_analysis(SCRIPT, skip_intel=True, conn=conn, source_kind="pasted")
    uploaded = PlagEngine.run_analysis(SCRIPT, filename="x.ps1", skip_intel=True,
                                        conn=conn, source_kind="file")
    assert PlagStore.get_analysis(conn, pasted["id"])["source_kind"] == "pasted"
    assert PlagStore.get_analysis(conn, uploaded["id"])["source_kind"] == "file"


def test_stored_analysis_keeps_resolved_vars():
    conn = PlagStore.get_conn(":memory:")
    result = PlagEngine.run_analysis("$x = 'a' + 'b'\n", skip_intel=True, conn=conn)
    stored = PlagStore.get_analysis(conn, result["id"])
    assert stored["resolved_vars"].get("x") == "ab"


def test_report_hashes_real_input_not_empty_string():
    import hashlib
    from plaguardsv2.GuardModules import PlagReport

    _, stored = _stored()
    ctx = PlagReport.build_report_context(stored)
    empty_hash = hashlib.sha256(b"").hexdigest()
    assert ctx["original_sha256"] != empty_hash
    assert ctx["deobfuscated_lines"], "appendix A must not be empty"
    assert ctx["original_lines"], "appendix B must not be empty"
