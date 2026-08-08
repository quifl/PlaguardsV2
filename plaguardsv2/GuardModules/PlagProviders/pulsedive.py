"""Pulsedive client - IP/domain/hash risk lookup."""
from __future__ import annotations

from .base import explain_http, safe_json_request

SUPPORTS = {"ip", "domain", "hash_md5", "hash_sha1", "hash_sha256"}
_URL = "https://pulsedive.com/api/info.php"

_RISK_MAP = {
    "critical": "malicious",
    "high": "malicious",
    "medium": "suspicious",
    "low": "clean",
    "none": "clean",
    "unknown": "unknown",
}


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}
    if finding_type not in SUPPORTS:
        return {"verdict": "not_checked", "detail": "Unsupported finding type"}

    status, body, err = safe_json_request(
        "GET", _URL, params={"indicator": value, "key": api_key},
    )
    if err:
        return {"verdict": "error", "detail": f"Pulsedive request failed: {err}"}
    if status != 200 or body is None:
        return {"verdict": "error", "detail": explain_http("Pulsedive", status)}
    if body.get("error"):
        return {"verdict": "unknown", "detail": "Not found in Pulsedive"}

    risk = (body.get("risk") or "unknown").lower()
    threats = body.get("threats") or []
    verdict = _RISK_MAP.get(risk, "unknown")

    detail = f"Pulsedive risk: {risk}"
    if threats:
        names = ", ".join(t.get("name", "?") for t in threats[:3])
        detail += f", threats: {names}"
    return {"verdict": verdict, "detail": detail}
