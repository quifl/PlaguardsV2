"""Threat-intel orchestrator: for each finding, fans out to every configured
provider that supports its type (mirrors Plaguards' own gather_ioc_data
fan-out in PlagParser.py), checking/populating the local cache first so
repeat views don't re-burn API quota."""
from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor

from . import PlagConfig, PlagScope, PlagStore
from .PlagProviders import REGISTRY

CACHEABLE_VERDICTS = {"malicious", "suspicious", "clean", "unknown"}


def enrich(findings: list, conn: sqlite3.Connection | None, use_cache: bool = True) -> list:
    keys = {provider_id: PlagConfig.get_api_key(conn, provider_id) for provider_id in REGISTRY}
    pending: dict[str, list] = {}

    for f in findings:
        # Values providers reject (reserved TLDs, truncated hashes) are answered once
        # rather than as a wall of HTTP 400s.
        skip = PlagScope.skip_reason(f.type, f.value)
        if skip:
            f.intel["scope"] = {"verdict": "not_applicable", "detail": skip}
            continue

        # Reserved IP ranges still get looked up - providers answer for them
        # - but the analyst is told the reputation won't mean much.
        note = PlagScope.advisory(f.type, f.value)
        if note:
            f.intel["scope"] = {"verdict": "info", "detail": note}

        for provider_id, module in REGISTRY.items():
            if f.type not in module.SUPPORTS:
                continue
            hit = None
            if use_cache and conn is not None:
                hit = PlagStore.cache_get(conn, provider_id, f.type, f.value)
            if hit is not None:
                f.intel[provider_id] = hit
            else:
                pending.setdefault(provider_id, []).append(f)

    # One worker per provider: each provider still sees one request at a time, so its
    # rate limit is spent exactly as before, while different providers answer in parallel.
    if pending:
        with ThreadPoolExecutor(max_workers=len(pending), thread_name_prefix="plaguards-intel") as pool:
            answered = pool.map(lambda pid: (pid, _lookup_all(pid, pending[pid], keys[pid])),
                                list(pending))
            # Cache writes stay on this thread; the connection belongs to the caller.
            for provider_id, results in answered:
                for f, result in results:
                    f.intel[provider_id] = result
                    if (use_cache and conn is not None
                            and result.get("verdict") in CACHEABLE_VERDICTS):
                        PlagStore.cache_set(conn, provider_id, f.type, f.value,
                                            result.get("verdict", "unknown"), result.get("detail", ""))

    # Same key order as a sequential run, so JSON output and the CLI listing stay stable.
    order = {key: rank for rank, key in enumerate(["scope", *REGISTRY])}
    for f in findings:
        if f.intel:
            f.intel = {k: f.intel[k] for k in sorted(f.intel, key=lambda k: order.get(k, len(order)))}
    return findings


def _lookup_all(provider_id: str, findings: list, api_key) -> list:
    module = REGISTRY[provider_id]
    results = []
    for f in findings:
        try:
            result = module.lookup(f.type, f.value, api_key)
        except Exception:
            # A response shape the parser did not expect must cost one row, not the analysis.
            result = {"verdict": "error", "detail": "unexpected response from the provider; could not be read"}
        results.append((f, result))
    return results
