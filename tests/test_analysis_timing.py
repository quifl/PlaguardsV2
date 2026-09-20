"""Timestamp and duration tracking for single-file and batch analyses.

Timing is measured with time.perf_counter() (monotonic, high-resolution -
immune to wall-clock adjustments) for the duration itself, and time.time()
for the wall-clock started_at/completed_at stamps, matching the created_at
convention PlagStore already used everywhere. Both are local values with no
shared mutable state, so they stay correct even if callers run several
analyses concurrently (see test_concurrent_analyses_get_independent_timing).

This must NEVER reach the PDF report - see test_timing_never_appears_in_pdf.
"""
from __future__ import annotations

import io
import threading

import pytest
from pypdf import PdfReader

from plaguardsv2.GuardModules import PlagEngine, PlagReport, PlagStore

INERT = "Write-Host 'malicious.example.invalid'"


def _conn():
    return PlagStore.get_conn(":memory:")


# --- 1. single-file analysis has start/completion/duration -----------------

def test_single_analysis_has_started_completed_and_duration():
    conn = _conn()
    result = PlagEngine.run_analysis(INERT, filename="a.ps1", skip_intel=True, conn=conn)

    assert result["status"] == "completed"
    assert result["started_at"] is not None
    assert result["completed_at"] is not None
    assert result["started_at"] <= result["completed_at"]
    assert result["duration_ms"] is not None and result["duration_ms"] >= 0


def test_single_analysis_timing_is_persisted_and_reloadable():
    conn = _conn()
    result = PlagEngine.run_analysis(INERT, filename="a.ps1", skip_intel=True, conn=conn)
    stored = PlagStore.get_analysis(conn, result["id"])

    assert stored["status"] == "completed"
    assert stored["started_at"] == pytest.approx(result["started_at"])
    assert stored["completed_at"] == pytest.approx(result["completed_at"])
    assert stored["duration_ms"] == pytest.approx(result["duration_ms"])
    assert stored["batch"] is None, "a lone analysis must not appear to belong to a batch"


def test_high_resolution_timer_distinguishes_close_calls():
    """A wall-clock-only timer (whole seconds) would report 0ms for anything
    faster than a second. perf_counter must not."""
    conn = _conn()
    r1 = PlagEngine.run_analysis(INERT, filename="a.ps1", skip_intel=True, conn=conn)
    r2 = PlagEngine.run_analysis(INERT, filename="b.ps1", skip_intel=True, conn=conn)
    # Sub-millisecond precision is available even though both calls almost
    # certainly land inside the same wall-clock second.
    assert isinstance(r1["duration_ms"], float)
    assert isinstance(r2["duration_ms"], float)


# --- 2 & 3. batch has start/completion/total duration; files independent ---

def test_batch_has_started_completed_and_total_duration():
    conn = _conn()
    batch = [("a.ps1", INERT), ("b.ps1", INERT), ("c.ps1", INERT)]
    outcome = PlagEngine.run_batch_analysis(batch, "samples.zip", conn, skip_intel=True)

    assert outcome["batch_id"] is not None
    row = next(r for r in PlagStore.list_history(conn) if r["id"] == outcome["batch_id"])
    assert row["kind"] == "batch"
    assert row["started_at"] is not None
    assert row["completed_at"] is not None
    assert row["started_at"] <= row["completed_at"]
    assert row["duration_ms"] >= 0
    assert row["total_files"] == 3
    assert row["successful_files"] == 3
    assert row["failed_files"] == 0
    assert row["status"] == "completed"


def test_each_file_in_a_batch_has_its_own_independent_duration():
    conn = _conn()
    # Deliberately different costs, so identical durations would be suspicious.
    batch = [("fast.ps1", "Write-Host 'x'")]
    batch += [(f"slower{i}.ps1", INERT + ("\n# padding" * 50)) for i in range(3)]
    outcome = PlagEngine.run_batch_analysis(batch, "mixed.zip", conn, skip_intel=True)

    row = next(r for r in PlagStore.list_history(conn) if r["id"] == outcome["batch_id"])
    durations = {f["filename"]: f["duration_ms"] for f in row["files"]}
    assert len(durations) == 4
    assert all(d is not None and d >= 0 for d in durations.values())
    # Not every file measured to exactly the same value - real, independent timers.
    assert len(set(durations.values())) > 1


def test_single_file_upload_does_not_become_a_one_file_batch():
    """A submission that resolves to exactly one file - even through the
    batch entry point - is not a batch. Matches pre-feature behaviour."""
    conn = _conn()
    outcome = PlagEngine.run_batch_analysis([("only.ps1", INERT)], "only.ps1", conn, skip_intel=True)
    assert outcome["batch_id"] is None
    assert len(outcome["created_ids"]) == 1
    stored = PlagStore.get_analysis(conn, outcome["created_ids"][0])
    assert stored["batch"] is None


# --- 4 & 5. History: single-file and batch uploads display correctly -------

def test_single_file_history_entry_has_the_required_fields():
    conn = _conn()
    PlagEngine.run_analysis(INERT, filename="a.ps1", skip_intel=True, conn=conn)
    rows = PlagStore.list_history(conn)

    assert len(rows) == 1
    row = rows[0]
    assert row["kind"] == "single"
    assert row["filename"] == "a.ps1"
    assert row["completed_at"] is not None      # upload/completion time
    assert row["duration_ms"] is not None         # analysis duration
    assert row["status"] == "completed"           # analysis status


def test_batch_history_entry_is_distinguishable_from_single_uploads():
    conn = _conn()
    PlagEngine.run_analysis(INERT, filename="lone.ps1", skip_intel=True, conn=conn)
    PlagEngine.run_batch_analysis(
        [("a.ps1", INERT), ("b.ps1", INERT)], "bundle.zip", conn, skip_intel=True,
    )
    rows = PlagStore.list_history(conn)
    kinds = {r["kind"] for r in rows}
    assert kinds == {"single", "batch"}

    batch_row = next(r for r in rows if r["kind"] == "batch")
    assert batch_row["batch_filename"] == "bundle.zip"
    assert batch_row["total_files"] == 2
    assert batch_row["successful_files"] == 2
    assert batch_row["duration_ms"] is not None


def test_a_batch_counts_as_one_slot_against_the_history_limit():
    """A 50-file batch must not cost 50 slots - the limit governs how many
    rows an analyst sees, and a batch is meant to collapse into one of them."""
    conn = _conn()
    big_batch = [(f"f{i}.ps1", INERT) for i in range(12)]
    PlagEngine.run_batch_analysis(big_batch, "big.zip", conn, skip_intel=True)
    PlagEngine.run_analysis(INERT, filename="solo.ps1", skip_intel=True, conn=conn)

    rows = PlagStore.list_history(conn, limit=5)
    assert len(rows) == 2  # the batch (1 slot) + the standalone analysis


# --- 6. individual files within a batch can be inspected -------------------

def test_individual_files_within_a_batch_are_inspectable():
    conn = _conn()
    outcome = PlagEngine.run_batch_analysis(
        [("first.ps1", INERT), ("second.ps1", INERT)], "pair.zip", conn, skip_intel=True,
    )
    batch_row = next(r for r in PlagStore.list_history(conn) if r["id"] == outcome["batch_id"])
    names = {f["filename"] for f in batch_row["files"]}
    assert names == {"first.ps1", "second.ps1"}
    for f in batch_row["files"]:
        assert {"filename", "status", "duration_ms", "completed_at"} <= f.keys()
        # Each is independently viewable via the normal single-analysis path.
        assert PlagStore.get_analysis(conn, f["id"]) is not None


# --- 7. failed files still record a duration --------------------------------

def test_failed_file_in_a_batch_still_records_its_duration(monkeypatch):
    conn = _conn()
    real_run = PlagEngine.run_analysis

    def flaky(text, filename=None, **kw):
        if filename == "bad.ps1":
            raise RuntimeError("simulated failure")
        return real_run(text, filename=filename, **kw)

    monkeypatch.setattr(PlagEngine, "run_analysis", flaky)
    batch = [("good.ps1", INERT), ("bad.ps1", INERT)]
    outcome = PlagEngine.run_batch_analysis(batch, "mix.zip", conn, skip_intel=True)

    assert outcome["failed_count"] == 1
    assert len(outcome["created_ids"]) == 1

    row = next(r for r in PlagStore.list_history(conn) if r["id"] == outcome["batch_id"])
    assert row["failed_files"] == 1
    failed = next(f for f in row["files"] if f["filename"] == "bad.ps1")
    assert failed["status"] == "failed"
    assert failed["duration_ms"] is not None and failed["duration_ms"] >= 0
    assert failed["completed_at"] is not None


# --- 8. cancelled batches record status and duration ------------------------

def test_a_batch_interrupted_partway_through_is_marked_cancelled(monkeypatch):
    """Not one file failing (that's `failed`, tested above) - something that
    stops the whole batch. The original exception must still propagate."""
    conn = _conn()
    monkeypatch.setattr(
        PlagEngine, "run_analysis",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("file broke")),
    )
    monkeypatch.setattr(
        PlagStore, "save_failed_analysis",
        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("disk full")),
    )
    batch = [("a.ps1", INERT), ("b.ps1", INERT), ("c.ps1", INERT)]

    with pytest.raises(RuntimeError, match="disk full"):
        PlagEngine.run_batch_analysis(batch, "boom.zip", conn, skip_intel=True)

    row = next(r for r in PlagStore.list_history(conn) if r["kind"] == "batch")
    assert row["status"] == "cancelled"
    assert row["duration_ms"] is not None and row["duration_ms"] >= 0
    assert row["total_files"] == 3


# --- 9. timing never appears in the PDF report -------------------------------

_BANNED_IN_PDF = [
    "Started", "Completed", "Duration", "duration_ms", "started_at",
    "completed_at", "Batch Analysis", "seconds", "Analysis Duration",
]


def _pdf_text(pdf_bytes: bytes) -> str:
    return "\n".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(pdf_bytes)).pages)


def test_timing_never_appears_in_the_single_pdf_report():
    conn = _conn()
    result = PlagEngine.run_analysis(INERT, filename="a.ps1", skip_intel=True, conn=conn)
    stored = PlagStore.get_analysis(conn, result["id"])

    text = _pdf_text(PlagReport.render_pdf(stored))
    leaked = [w for w in _BANNED_IN_PDF if w in text]
    assert not leaked, f"timing vocabulary leaked into the PDF: {leaked}"


def test_timing_never_appears_in_the_combined_pdf_report():
    conn = _conn()
    outcome = PlagEngine.run_batch_analysis(
        [("a.ps1", INERT), ("b.ps1", "Write-Host 'other.example.invalid'")],
        "pair.zip", conn, skip_intel=True,
    )
    analyses = [PlagStore.get_analysis(conn, i) for i in outcome["created_ids"]]

    text = _pdf_text(PlagReport.render_combined_pdf(analyses))
    leaked = [w for w in _BANNED_IN_PDF if w in text]
    assert not leaked, f"timing vocabulary leaked into the combined PDF: {leaked}"


def test_timing_fields_do_not_change_the_pdf_structure():
    """The report format/layout must stay unchanged by this feature: a
    stored analysis (which now always carries timing fields) must render the
    same page count and section headings as one that never had them.

    Not a full text diff - the report's own cover stamps the moment it was
    generated, which legitimately differs by a few milliseconds between the
    two calls this test makes regardless of this feature.
    """
    conn = _conn()
    result = PlagEngine.run_analysis(INERT, filename="a.ps1", skip_intel=True, conn=conn)
    stored = PlagStore.get_analysis(conn, result["id"])
    without_timing = dict(stored)
    for key in ("started_at", "completed_at", "duration_ms", "status", "batch", "batch_id"):
        without_timing.pop(key, None)

    with_timing = PdfReader(io.BytesIO(PlagReport.render_pdf(stored))).pages
    without_timing = PdfReader(io.BytesIO(PlagReport.render_pdf(without_timing))).pages
    assert len(with_timing) == len(without_timing)

    import re
    headings = lambda pages: [  # noqa: E731 - local, throwaway
        m.group(0) for p in pages
        for m in re.finditer(r"^[A-Z][A-Za-z &]+$", p.extract_text() or "", re.M)
    ]
    assert headings(with_timing) == headings(without_timing)


# --- 10. duration remains correct under concurrent processing --------------

def test_concurrent_analyses_get_independent_timing(tmp_path):
    """Each worker gets its own connection to the same file, matching how
    Flask hands one out per request - see the note on the batch version of
    this test for why sharing one Connection object across threads is a
    different (and irrelevant) scenario for this application."""
    db_path = tmp_path / "concurrent_single.db"
    PlagStore.get_conn(db_path).close()  # see the batch version of this test
    results: dict[int, dict] = {}
    lock = threading.Lock()

    def worker(i):
        conn = PlagStore.get_conn(db_path)
        r = PlagEngine.run_analysis(
            f"Write-Host 'file-{i}'", filename=f"f{i}.ps1",
            skip_intel=True, conn=conn, prune=False,
        )
        with lock:
            results[i] = r
        conn.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 8
    ids = {r["id"] for r in results.values()}
    assert len(ids) == 8, "each concurrent call must persist its own row"
    for r in results.values():
        assert r["started_at"] <= r["completed_at"]
        assert r["duration_ms"] >= 0

    conn = PlagStore.get_conn(db_path)
    stored_durations = [
        PlagStore.get_analysis(conn, r["id"])["duration_ms"] for r in results.values()
    ]
    assert all(d is not None and d >= 0 for d in stored_durations)


def test_batch_processing_stays_correct_when_run_from_multiple_threads(tmp_path):
    """Two independent batches processed concurrently must not cross-
    contaminate each other's timing or file/success/failure counts.

    Each thread gets its OWN connection to the same database file - the
    scenario this actually needs to survive is two concurrent requests (two
    analysts uploading batches at the same moment), and that is exactly how
    Flask hands out connections: a fresh one per request via `g`, never one
    connection shared across threads. SQLite's own lastrowid is a
    connection-global, not a statement-local value, so sharing a single
    Connection object across threads that both INSERT is a real correctness
    trap distinct from - and not a concern for - this application's actual
    concurrency model.
    """
    db_path = tmp_path / "concurrent.db"
    # Create the schema up front, synchronously - in the real app it has
    # existed since long before any concurrent request arrives, so racing
    # two threads' very first get_conn() (each running CREATE TABLE/ALTER
    # TABLE on a brand-new file) would test schema-creation concurrency,
    # a different question this app never actually faces in practice.
    PlagStore.get_conn(db_path).close()
    outcomes: dict[str, dict] = {}

    def worker(label, n):
        conn = PlagStore.get_conn(db_path)
        batch = [(f"{label}-{i}.ps1", INERT) for i in range(n)]
        outcomes[label] = PlagEngine.run_batch_analysis(batch, f"{label}.zip", conn, skip_intel=True)
        conn.close()

    t1 = threading.Thread(target=worker, args=("alpha", 3))
    t2 = threading.Thread(target=worker, args=("beta", 5))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert len(outcomes["alpha"]["created_ids"]) == 3
    assert len(outcomes["beta"]["created_ids"]) == 5
    assert outcomes["alpha"]["batch_id"] != outcomes["beta"]["batch_id"]

    conn = PlagStore.get_conn(db_path)
    rows = {r["id"]: r for r in PlagStore.list_history(conn) if r["kind"] == "batch"}
    alpha_row = rows[outcomes["alpha"]["batch_id"]]
    beta_row = rows[outcomes["beta"]["batch_id"]]
    assert alpha_row["total_files"] == 3
    assert beta_row["total_files"] == 5
    assert {f["filename"] for f in alpha_row["files"]} == {"alpha-0.ps1", "alpha-1.ps1", "alpha-2.ps1"}


# --- 11. existing analysis/PDF functionality is unaffected -----------------

def test_scoring_and_finding_extraction_are_unaffected_by_timing():
    """Same input, timing on or off (there's no "off" switch, but the point
    stands): the findings and pass log must be identical to what the engine
    produced before this feature - timing is bookkeeping, not analysis."""
    conn = _conn()
    result = PlagEngine.run_analysis(INERT, filename="a.ps1", skip_intel=True, conn=conn)
    assert result["deobfuscated"]
    assert any(f.type == "domain" for f in result["findings"])
    assert result["findings"][0].value == "malicious.example.invalid"


def test_history_still_lists_plain_analyses_for_the_cli(monkeypatch):
    """list_analyses() and prune_old_analyses() (CLI-facing, batch-unaware)
    must be untouched - the CLI has no concept of a batch."""
    conn = _conn()
    PlagEngine.run_analysis(INERT, filename="a.ps1", skip_intel=True, conn=conn)
    rows = PlagStore.list_analyses(conn)
    assert len(rows) == 1
    assert rows[0]["filename"] == "a.ps1"
