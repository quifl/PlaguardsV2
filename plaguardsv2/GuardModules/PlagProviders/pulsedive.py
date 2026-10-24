"""Pulsedive client - IP/domain/hash risk lookup."""
from __future__ import annotations

from .base import brief, compose, http_verdict, safe_json_request

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
        return http_verdict("Pulsedive", status)
    if body.get("error"):
        return {"verdict": "unknown", "detail": "Not found in Pulsedive"}

    risk = (body.get("risk") or "unknown").lower()
    threats = body.get("threats") or []
    verdict = _RISK_MAP.get(risk, "unknown")

    # riskfactors explains the score; without it the number is taken on trust.
    # The feed names say who is making the claim.
    factors = [f.get("description") for f in (body.get("riskfactors") or [])
               if isinstance(f, dict) and f.get("description")]
    feeds = [f.get("name") for f in (body.get("feeds") or [])
             if isinstance(f, dict) and f.get("name")]
    return {"verdict": verdict, "detail": compose(
        f"Pulsedive risk: {risk}",
        f"threats: {brief([t.get('name', '?') for t in threats], limit=3)}" if threats else "",
        f"because: {brief(factors, limit=2)}" if factors else "",
        f"feeds: {brief(feeds, limit=2)}" if feeds else "",
        f"last seen {str(body['stamp_seen'])[:10]}" if body.get("stamp_seen") else "",
    )}
