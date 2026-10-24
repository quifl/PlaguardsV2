"""AbuseIPDB API v2 client - IP reputation only."""
from __future__ import annotations

from .base import brief, compose, http_verdict, safe_json_request

SUPPORTS = {"ip"}
_URL = "https://api.abuseipdb.com/api/v2/check"


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}
    if finding_type not in SUPPORTS:
        return {"verdict": "not_checked", "detail": "Unsupported finding type"}

    status, body, err = safe_json_request(
        "GET", _URL,
        params={"ipAddress": value, "maxAgeInDays": "90"},
        headers={"Key": api_key, "Accept": "application/json"},
    )
    if err:
        return {"verdict": "error", "detail": f"AbuseIPDB request failed: {err}"}
    if status != 200 or body is None:
        return http_verdict("AbuseIPDB", status)

    data = body.get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    total_reports = data.get("totalReports", 0)
    country = data.get("countryCode", "?")

    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    elif total_reports > 0:
        verdict = "clean"
    else:
        verdict = "unknown"

    # All of this is already in the /check response the score came from.
    # Usage type, reporter count and date are what the score cannot say.
    reporters = data.get("numDistinctUsers") or 0
    reports = f"{total_reports} report(s)"
    if reporters > 1:
        reports += f" from {reporters} reporters"
    last_seen = (data.get("lastReportedAt") or "")[:10]

    return {"verdict": verdict, "detail": compose(
        f"Abuse confidence {score}%",
        reports,
        f"last reported {last_seen}" if last_seen else "",
        f"country {country}",
        data.get("usageType") or "",
        f"ISP: {data['isp']}" if data.get("isp") else "",
        brief(data.get("hostnames") or [], limit=2),
        "Tor exit node" if data.get("isTor") else "",
        "whitelisted by AbuseIPDB" if data.get("isWhitelisted") else "",
    )}
