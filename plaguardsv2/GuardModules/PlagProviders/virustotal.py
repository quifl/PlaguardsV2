"""VirusTotal API v3 client. Public tier: 4 requests/min."""
from __future__ import annotations

import base64
import os

from .. import PlagConfig  # noqa: F401  (loads .env before the limit below is read)
from .base import RateLimiter, brief, compose, http_verdict, path_segment, safe_json_request

SUPPORTS = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"}
BASE_URL = "https://www.virustotal.com/api/v3"
PUBLIC_TIER_PER_MINUTE = 4


def _requests_per_minute() -> int:
    """VT_REQUESTS_PER_MINUTE raises the pace for a premium key; the public tier is 4."""
    try:
        return max(1, int(os.environ.get("VT_REQUESTS_PER_MINUTE") or PUBLIC_TIER_PER_MINUTE))
    except ValueError:
        return PUBLIC_TIER_PER_MINUTE


_limiter = RateLimiter(max_calls=_requests_per_minute(), period_seconds=60)


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}

    if finding_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        path = f"/files/{path_segment(value)}"
    elif finding_type == "ip":
        path = f"/ip_addresses/{path_segment(value)}"
    elif finding_type == "domain":
        path = f"/domains/{path_segment(value)}"
    elif finding_type == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        path = f"/urls/{url_id}"
    else:
        return {"verdict": "not_checked", "detail": "Unsupported finding type"}

    _limiter.wait()
    status, body, err = safe_json_request("GET", f"{BASE_URL}{path}", headers={"x-apikey": api_key})
    if err:
        return {"verdict": "error", "detail": f"VirusTotal request failed: {err}"}
    if status == 404:
        return {"verdict": "unknown", "detail": "Not found in VirusTotal"}
    if status == 429:
        return {"verdict": "error", "detail": "VirusTotal rate limit exceeded"}
    if status == 401:
        return {"verdict": "error", "detail": "VirusTotal API key rejected (401)"}
    if status != 200 or body is None:
        return http_verdict("VirusTotal", status)

    attributes = body.get("data", {}).get("attributes", {}) or {}
    stats = attributes.get("last_analysis_stats", {}) or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    elif total > 0:
        verdict = "clean"
    else:
        verdict = "unknown"

    return {"verdict": verdict, "detail": compose(
        f"{malicious} malicious / {suspicious} suspicious / "
        f"{harmless} harmless / {undetected} undetected (of {total} engines)",
        _detections(attributes),
        _identity(attributes),
        _standing(attributes),
    )}


def _detections(attributes: dict) -> str:
    """What the engines actually called it.

    The ratio says how many vendors agree; the family name says what they
    agree it *is*, and is the part an analyst can pivot on. Both ship in the
    same response, so naming them costs nothing extra.
    """
    results = attributes.get("last_analysis_results") or {}
    named = [
        f"{r.get('result')} ({engine})"
        for engine, r in results.items()
        if isinstance(r, dict) and r.get("category") in ("malicious", "suspicious")
        and r.get("result")
    ]
    return f"detections: {brief(sorted(named), limit=3)}" if named else ""


def _identity(attributes: dict) -> str:
    """Whatever names the object: the operator for an address, the file name
    and type for a sample."""
    parts = [
        attributes.get("as_owner") or "",
        attributes.get("meaningful_name") or "",
        attributes.get("type_description") or "",
    ]
    return brief([p for p in parts if p], limit=3)


def _standing(attributes: dict) -> str:
    """Community reputation, and whether this is a site the whole world
    already visits - a domain inside the global top ranks is overwhelmingly
    more likely to be a false positive than a live C2."""
    out = []
    reputation = attributes.get("reputation")
    if isinstance(reputation, int) and reputation != 0:
        out.append(f"reputation {reputation:+d}")
    ranks = attributes.get("popularity_ranks") or {}
    best = [r.get("rank") for r in ranks.values()
            if isinstance(r, dict) and isinstance(r.get("rank"), int)]
    if best:
        out.append(f"popularity rank {min(best)}")
    tags = attributes.get("tags") or []
    if tags:
        out.append(f"tags: {brief(tags, limit=3)}")
    return ", ".join(out)
