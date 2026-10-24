"""GreyNoise Community API client - IP scanning-noise classification."""
from __future__ import annotations

from .base import compose, http_verdict, path_segment, safe_json_request

SUPPORTS = {"ip"}
_URL = "https://api.greynoise.io/v3/community/{ip}"


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}
    if finding_type not in SUPPORTS:
        return {"verdict": "not_checked", "detail": "Unsupported finding type"}

    status, body, err = safe_json_request(
        "GET", _URL.format(ip=path_segment(value)),
        headers={"key": api_key, "Accept": "application/json"},
    )
    if err:
        return {"verdict": "error", "detail": f"GreyNoise request failed: {err}"}
    if status == 404:
        return {"verdict": "unknown", "detail": "No GreyNoise data for this IP"}
    if status != 200 or body is None:
        return http_verdict("GreyNoise", status)

    classification = (body.get("classification") or "unknown").lower()
    name = body.get("name", "")
    verdict_map = {"malicious": "malicious", "suspicious": "suspicious", "benign": "clean"}
    verdict = verdict_map.get(classification, "unknown")

    # RIOT ("common business service") and noise ("sweeps everyone, not
    # you") are what GreyNoise is for, and the classification alone omits.
    return {"verdict": verdict, "detail": compose(
        f"GreyNoise classification: {classification}"
        + (f" ({name})" if name and name.lower() != "unknown" else ""),
        "known benign service (RIOT)" if body.get("riot") else "",
        "internet-wide scanner traffic" if body.get("noise") else "",
        f"last seen {str(body['last_seen'])[:10]}" if body.get("last_seen") else "",
    )}
