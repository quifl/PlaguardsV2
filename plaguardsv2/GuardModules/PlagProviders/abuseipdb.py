"""AbuseIPDB API v2 client - IP reputation only."""
from __future__ import annotations

from .base import explain_http, safe_json_request

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
        return {"verdict": "error", "detail": explain_http("AbuseIPDB", status)}

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

    detail = f"Abuse confidence {score}%, {total_reports} report(s), country {country}"
    return {"verdict": verdict, "detail": detail}
