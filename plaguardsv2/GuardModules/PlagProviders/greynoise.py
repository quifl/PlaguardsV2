"""GreyNoise Community API client - IP scanning-noise classification."""
from __future__ import annotations

from .base import explain_http, safe_json_request

SUPPORTS = {"ip"}
_URL = "https://api.greynoise.io/v3/community/{ip}"


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}
    if finding_type not in SUPPORTS:
        return {"verdict": "not_checked", "detail": "Unsupported finding type"}

    status, body, err = safe_json_request(
        "GET", _URL.format(ip=value),
        headers={"key": api_key, "Accept": "application/json"},
    )
    if err:
        return {"verdict": "error", "detail": f"GreyNoise request failed: {err}"}
    if status == 404:
        return {"verdict": "unknown", "detail": "No GreyNoise data for this IP"}
    if status != 200 or body is None:
        return {"verdict": "error", "detail": explain_http("GreyNoise", status)}

    classification = (body.get("classification") or "unknown").lower()
    name = body.get("name", "")
    verdict_map = {"malicious": "malicious", "suspicious": "suspicious", "benign": "clean"}
    verdict = verdict_map.get(classification, "unknown")

    detail = f"GreyNoise classification: {classification}"
    if name and name.lower() != "unknown":
        detail += f" ({name})"
    return {"verdict": verdict, "detail": detail}
