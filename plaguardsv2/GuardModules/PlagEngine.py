"""Orchestrates the full triage pipeline: deobfuscate -> resolve variables
-> extract IOCs -> enrich with threat intel -> persist. Shared by both the
CLI and the web app so behavior never drifts between the two front ends.
"""
from __future__ import annotations

import sqlite3
import time

from . import PlagConfig, PlagDeobfus, PlagGeo, PlagGrep, PlagIntel, PlagTrace
from . import PlagStore


def run_analysis(
    text: str,
    filename: str | None = None,
    skip_intel: bool = False,
    conn: sqlite3.Connection | None = None,
    use_cache: bool = True,
    source_kind: str = "pasted",
    batch_id: int | None = None,
    prune: bool = True,
) -> dict:
    # perf_counter is monotonic and high-resolution - immune to wall-clock
    # adjustments - so it is what measures the duration. time.time() is
    # wall-clock and unrelated to it; it only stamps when things happened,
    # matching the created_at convention already used everywhere else in
    # PlagStore. Both are local to this call, so nothing here is shared
    # mutable state - independently correct even if a future caller runs
    # several of these concurrently (see PlagEngine.run_batch_analysis).
    perf_start = time.perf_counter()
    started_at = time.time()

    deob = PlagDeobfus.run(text)

    # Statically resolve variable values so IOCs assembled at runtime
    # (concatenation, base64, -join/-split/-replace) become visible.
    traced = PlagTrace.trace(deob.deobfuscated)
    resolved_text = PlagTrace.enrichment_text(traced)

    findings = PlagGrep.scan(deob.original, deob.deobfuscated, resolved_text)

    pass_log = list(deob.pass_log)
    if traced.variables:
        pass_log.append(
            f"Variable tracing: statically resolved {len(traced.variables)} variable "
            f"value(s) by folding literals through concatenation/encoding operations"
        )
    if traced.revealed_strings:
        pass_log.append(
            f"Variable tracing: reconstructed {len(traced.revealed_strings)} interpolated "
            f"string(s) once their variables were known"
        )

    # The IOC check is part of analysis, not a separate errand: every
    # extracted indicator is looked up unless the analyst explicitly opted
    # out for an offline run.
    geo: dict = {}
    if skip_intel:
        pass_log.append("Threat-intel and geolocation lookups skipped at your request")
    else:
        PlagIntel.enrich(findings, conn=conn, use_cache=use_cache)
        checked = sum(1 for f in findings if getattr(f, "intel", None))
        pass_log.append(
            f"IOC check: {checked} of {len(findings)} indicator(s) queried against "
            f"the configured threat-intel providers"
        )
        geo = PlagGeo.enrich(findings, conn=conn)
        located = sum(1 for r in geo.values() if r.get("country") or r.get("city"))
        if geo:
            pass_log.append(
                f"Geolocation: {located} of {len(geo)} address(es) located"
            )

    # Stops here, not after the database write below: persistence is
    # bookkeeping, not analysis, and its time depends on unrelated things
    # (disk I/O, WAL checkpoints) that would make the measurement noisy and
    # dishonest about what the engine itself actually cost.
    duration_ms = (time.perf_counter() - perf_start) * 1000
    completed_at = time.time()

    analysis_id = None
    if conn is not None:
        analysis_id = PlagStore.save_analysis(
            conn,
            filename or "pasted-script",
            deob.original,
            deob.deobfuscated,
            pass_log,
            deob.truncated,
            findings,
            source_kind=source_kind,
            resolved_vars=traced.variables,
            deobfuscated_raw=deob.deobfuscated_raw,
            batch_id=batch_id,
            status="completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
        )
        if prune:
            PlagStore.prune_old_history(conn, PlagConfig.get_history_limit(conn))

    return {
        "id": analysis_id,
        "filename": filename or "pasted-script",
        "source_kind": source_kind,
        "original": deob.original,
        "deobfuscated": deob.deobfuscated,
        "deobfuscated_raw": deob.deobfuscated_raw,
        "pass_log": pass_log,
        "resolved_vars": traced.variables,
        "revealed_strings": traced.revealed_strings,
        "geo": geo,
        "truncated": deob.truncated,
        "findings": findings,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "status": "completed",
    }


def run_batch_analysis(
    batch: list[tuple[str, str]],
    batch_label: str,
    conn: sqlite3.Connection,
    skip_intel: bool = False,
    use_cache: bool = True,
) -> dict:
    """Analyze several files as one batch, tracking batch- and file-level
    timing throughout. Returns {"batch_id", "created_ids", "failed_count"}.

    A submission that resolves to exactly one file is not actually a batch -
    it is analyzed the ordinary way and `batch_id` comes back None, so a
    single-file upload stays indistinguishable in storage from before this
    function existed, and shows up in History as a normal row rather than a
    one-file "batch".

    One file failing does not abort the rest: each is isolated in its own
    try/except so a bad file still gets a row recording its filename, status
    and the duration up to the point of failure, instead of taking the whole
    submission down with it. If something OTHER than a single file's analysis
    goes wrong - interrupting the loop itself - the batch is finalized as
    "cancelled" with whatever completed so far, and the original exception is
    still raised.
    """
    if len(batch) <= 1:
        created = [
            run_analysis(text, filename=name, skip_intel=skip_intel, conn=conn,
                        use_cache=use_cache, source_kind="file")["id"]
            for name, text in batch
        ]
        return {"batch_id": None, "created_ids": created, "failed_count": 0}

    perf_start = time.perf_counter()
    batch_id = PlagStore.create_batch(conn, batch_label, time.time())

    created_ids: list[int] = []
    failed_count = 0
    cancelled = False
    try:
        for name, text in batch:
            file_perf_start = time.perf_counter()
            file_started_at = time.time()
            try:
                result = run_analysis(
                    text, filename=name, skip_intel=skip_intel, conn=conn,
                    use_cache=use_cache, source_kind="file",
                    batch_id=batch_id, prune=False,
                )
                created_ids.append(result["id"])
            except Exception as exc:  # noqa: BLE001 - isolates one bad file
                failed_count += 1
                PlagStore.save_failed_analysis(
                    conn, filename=name, error=str(exc), source_kind="file",
                    batch_id=batch_id, started_at=file_started_at,
                    completed_at=time.time(),
                    duration_ms=(time.perf_counter() - file_perf_start) * 1000,
                )
    except BaseException:
        cancelled = True
        raise
    finally:
        PlagStore.finish_batch(
            conn, batch_id, completed_at=time.time(),
            duration_ms=(time.perf_counter() - perf_start) * 1000,
            total_files=len(batch), successful_files=len(created_ids),
            failed_files=failed_count,
            status="cancelled" if cancelled else "completed",
        )

    PlagStore.prune_old_history(conn, PlagConfig.get_history_limit(conn))
    return {"batch_id": batch_id, "created_ids": created_ids, "failed_count": failed_count}
