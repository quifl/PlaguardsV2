"""Threat-intel orchestrator: for each finding, fans out to every configured
provider that supports its type (mirrors Plaguards' own gather_ioc_data
fan-out in PlagParser.py), checking/populating the local cache first so
repeat views don't re-burn API quota."""
from __future__ import annotations

import sqlite3

from . import PlagConfig, PlagScope, PlagStore
from .PlagProviders import REGISTRY

CACHEABLE_VERDICTS = {"malicious", "suspicious", "clean", "unknown"}


def enrich(findings: list, conn: sqlite3.Connection | None, use_cache: bool = True) -> list:
    for f in findings:
        # Values providers genuinely reject (reserved TLDs, truncated
        # hashes) are answered once instead of producing a wall of HTTP
        # 400s across every provider.
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
            api_key = PlagConfig.get_api_key(conn, provider_id)
            result = _cached_or_call(conn, provider_id, module, f.type, f.value, api_key, use_cache)
            f.intel[provider_id] = result
    return findings


def _cached_or_call(conn, provider_id, module, finding_type, value, api_key, use_cache) -> dict:
    if use_cache and conn is not None:
        hit = PlagStore.cache_get(conn, provider_id, finding_type, value)
        if hit is not None:
            return hit

    result = module.lookup(finding_type, value, api_key)

    if use_cache and conn is not None and result.get("verdict") in CACHEABLE_VERDICTS:
        PlagStore.cache_set(conn, provider_id, finding_type, value,
                             result.get("verdict", "unknown"), result.get("detail", ""))
    return result
