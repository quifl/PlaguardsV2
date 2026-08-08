"""VirusTotal API v3 client. Public tier: 4 requests/min."""
from __future__ import annotations

import base64

from .base import RateLimiter, explain_http, safe_json_request

SUPPORTS = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"}
BASE_URL = "https://www.virustotal.com/api/v3"
_limiter = RateLimiter(max_calls=4, period_seconds=60)


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}

    if finding_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        path = f"/files/{value}"
    elif finding_type == "ip":
        path = f"/ip_addresses/{value}"
    elif finding_type == "domain":
        path = f"/domains/{value}"
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
        return {"verdict": "error", "detail": explain_http("VirusTotal", status)}

    stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
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

    detail = (
        f"{malicious} malicious / {suspicious} suspicious / "
        f"{harmless} harmless / {undetected} undetected (of {total} engines)"
    )
    return {"verdict": verdict, "detail": detail}
