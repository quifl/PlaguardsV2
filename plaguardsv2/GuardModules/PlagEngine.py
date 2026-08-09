"""Orchestrates the full triage pipeline: deobfuscate -> resolve variables
-> extract IOCs -> enrich with threat intel -> persist. Shared by both the
CLI and the web app so behavior never drifts between the two front ends.
"""
from __future__ import annotations

import sqlite3

from . import PlagConfig, PlagDeobfus, PlagGeo, PlagGrep, PlagIntel, PlagTrace
from . import PlagStore


def run_analysis(
    text: str,
    filename: str | None = None,
    skip_intel: bool = False,
    conn: sqlite3.Connection | None = None,
    use_cache: bool = True,
    source_kind: str = "pasted",
) -> dict:
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
        )
        PlagStore.prune_old_analyses(conn, PlagConfig.get_history_limit(conn))

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
    }
