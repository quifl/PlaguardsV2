"""Orchestrates the full triage pipeline: deobfuscate -> resolve variables
-> extract IOCs -> enrich with threat intel -> persist. Shared by both the
CLI and the web app so behavior never drifts between the two front ends.
"""
from __future__ import annotations

import dataclasses
import json
import re
import sqlite3
import time

from . import PlagConfig, PlagDeobfus, PlagEncode, PlagGeo, PlagGrep, PlagIntel, PlagLayered, PlagTrace
from . import PlagStore
from .PlagArtifact import DEFAULT_LIMITS, Lang

PIPELINES = ("layered", "legacy")
# Layered since its Phase 1 exit criteria passed; "legacy" remains selectable
# (CLI --legacy-pipeline) and reproduces the pre-layering engine byte for byte.
DEFAULT_PIPELINE = "layered"


@dataclasses.dataclass
class Extracted:
    findings: list
    variables: dict
    revealed: list


def deobfuscate(text: str, pipeline: str | None = None, max_depth: int | None = None):
    """(DeobfuscationResult, LayeredResult or None) for the chosen pipeline.

    "legacy" is exactly PlagDeobfus.run; "layered" builds the artifact tree,
    and its DeobfuscationResult is the tree rendered as one text.
    """
    pipeline = pipeline or DEFAULT_PIPELINE
    if pipeline not in PIPELINES:
        raise ValueError(f"unknown pipeline {pipeline!r}")
    if pipeline == "legacy":
        return PlagDeobfus.run(text), None
    limits = DEFAULT_LIMITS
    if max_depth is not None:
        limits = dataclasses.replace(limits, max_layer_depth=max_depth)
    layered = PlagLayered.run(text, mode="layered", limits=limits)
    return layered.view, layered


# Stages that start a new process and so do not see the parent's variables.
_NEW_PROCESS_EDGES = ("-EncodedCommand", "-Command")
_MARKER_RE = re.compile(r"<<layer (\d+)>>")


def _scope_states(layered) -> dict[int, dict]:
    """The variables each in-process PowerShell stage starts from: its
    parent's, as they stand at the statement that runs it (`iex` of a literal,
    a decoded script). A nested powershell -enc / -Command starts empty."""
    states: dict[int, dict] = {}
    by_parent: dict[int, list] = {}
    for art in layered.artifacts[1:]:
        by_parent.setdefault(art.parent_id, []).append(art)
    for parent in layered.artifacts:
        children = [c for c in by_parent.get(parent.id, ())
                    if parent.language in Lang.PS_LIKE and c.language in Lang.PS_LIKE
                    and c.edge_detail not in _NEW_PROCESS_EDGES and isinstance(parent.final, str)]
        if not children:
            continue
        wanted = {c.id for c in children}
        before = dict(states.get(parent.id, {}))
        for statement, _name, _value, variables, _sep in PlagTrace.walk(parent.final, states.get(parent.id)):
            for m in _MARKER_RE.finditer(statement):
                child_id = int(m.group(1))
                if child_id in wanted and child_id not in states:
                    states[child_id] = dict(before)
            before = dict(variables)
    return states


def extract(deob, layered=None) -> Extracted:
    """Trace variables and scan for indicators: once for the legacy result,
    once per layer for a layered one. An indicator belongs to the layer whose
    scan produced it, the deepest whose own text holds it when several did;
    a stage run in its parent's scope is traced with the parent's variables."""
    if layered is None:
        traced = PlagTrace.trace(deob.deobfuscated)
        findings = PlagGrep.scan(deob.original, deob.deobfuscated, PlagTrace.enrichment_text(traced))
        return Extracted(findings, traced.variables, list(traced.revealed_strings))

    states = _scope_states(layered)
    groups, variables, revealed = [], {}, []
    producers: dict[tuple[str, str], list] = {}
    for art in layered.artifacts:
        if isinstance(art.content, bytes):
            continue
        inherited = states.get(art.id)
        traced = PlagTrace.trace(art.final, inherited)
        if inherited:
            # The parent's values were scanned with the parent; keep what this layer made.
            traced.variables = {k: v for k, v in traced.variables.items() if inherited.get(k) != v}
        group = PlagGrep.scan(art.content, art.final, PlagTrace.enrichment_text(traced))
        groups.append(group)
        for f in group:
            producers.setdefault((f.type, f.value.lower()), []).append(art)
        for name, value in traced.variables.items():
            key = name if name not in variables or variables[name] == value else f"{name}@layer{art.id}"
            variables.setdefault(key, value)
        revealed += [s for s in traced.revealed_strings if s not in revealed]
    findings = PlagGrep.merge(groups)
    for f in findings:
        arts = producers.get((f.type, f.value.lower())) or [layered.root]
        needles = {f.value.lower(), PlagGrep.refang(f.value).lower()}
        holding = [a for a in arts if any(n in a.final.lower() for n in needles)]
        chosen = max(holding, key=lambda a: (a.depth, a.id)) if holding else min(arts, key=lambda a: (a.depth, a.id))
        f.layer = layered.layer_path(chosen.id)
    return Extracted(findings, variables, revealed)


def deobfuscate_view(text: str, pipeline: str | None = None) -> dict:
    """Everything an analyst would see for `text`, flattened for tools/eval.py
    and tools/coverage.py: never stored, never sent anywhere."""
    deob, layered = deobfuscate(text, pipeline)
    found = extract(deob, layered)
    decoded = []
    for value in found.variables.values():
        payload = PlagEncode.decode_payload(str(value))
        if payload:
            decoded.append(payload[1])
    recovered = "\n".join([
        deob.deobfuscated,
        "\n".join(str(v) for v in found.variables.values()),
        "\n".join(found.revealed),
        "\n".join(f.value for f in found.findings),
        "\n".join(decoded),
    ])
    artifacts = layered.artifacts if layered else []
    deepest = max(artifacts, key=lambda a: (a.depth, a.id)) if artifacts else None
    return {
        "recovered": recovered,
        "finding_values": {f.value for f in found.findings},
        "findings": found.findings,
        "artifact_count": len(artifacts) or 1,
        "final_language": deepest.language if deepest else "",
        "assumed": any(t.assumed for t in deob.transforms),
        "deob": deob,
        "layered": layered,
    }


def run_analysis(
    text: str,
    filename: str | None = None,
    skip_intel: bool = False,
    conn: sqlite3.Connection | None = None,
    use_cache: bool = True,
    source_kind: str = "pasted",
    batch_id: int | None = None,
    prune: bool = True,
    pipeline: str | None = None,
    max_depth: int | None = None,
) -> dict:
    # perf_counter times the run (monotonic, immune to clock changes); time.time()
    # stamps when, as PlagStore does. Both are call-local, so safe under concurrency.
    perf_start = time.perf_counter()
    started_at = time.time()
    pipeline = pipeline or DEFAULT_PIPELINE

    deob, layered = deobfuscate(text, pipeline, max_depth)

    # Statically resolve variable values so IOCs assembled at runtime
    # (concatenation, base64, -join/-split/-replace) become visible.
    found = extract(deob, layered)
    findings = found.findings

    pass_log = list(deob.pass_log)
    if found.variables:
        pass_log.append(
            f"Variable tracing: statically resolved {len(found.variables)} variable "
            f"value(s) by folding literals through concatenation/encoding operations"
        )
    if found.revealed:
        pass_log.append(
            f"Variable tracing: reconstructed {len(found.revealed)} interpolated "
            f"string(s) once their variables were known"
        )
    layers = PlagLayered.canonical(layered, findings) if layered is not None else None

    # The IOC check is part of the analysis: every indicator is looked up unless
    # the analyst opted out for an offline run.
    geo: dict = {}
    if skip_intel:
        pass_log.append("Threat-intel and geolocation lookups skipped at your request")
    else:
        PlagIntel.enrich(findings, conn=conn, use_cache=use_cache)
        # "scope" is written when an indicator is ruled out before any
        # provider is called, so it must not count as queried.
        checked = sum(
            1 for f in findings
            if any(k != "scope" for k in (getattr(f, "intel", None) or {}))
        )
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

    # Stops before the database write: persistence time (disk I/O, WAL
    # checkpoints) would make the engine's own cost noisy.
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
            resolved_vars=found.variables,
            deobfuscated_raw=deob.deobfuscated_raw,
            batch_id=batch_id,
            status="completed",
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            pipeline=pipeline,
            layers_json=json.dumps(layers) if layers else "",
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
        "resolved_vars": found.variables,
        "revealed_strings": found.revealed,
        "geo": geo,
        "truncated": deob.truncated,
        "findings": findings,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "status": "completed",
        "pipeline": pipeline,
        "layers": layers,
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
