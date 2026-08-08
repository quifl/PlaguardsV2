"""AlienVault OTX client - IP/domain/URL/hash pulse lookup."""
from __future__ import annotations

from .base import explain_http, safe_json_request

SUPPORTS = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"}
_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

_SECTION_MAP = {
    "ip": "IPv4",
    "domain": "domain",
    "url": "url",
    "hash_md5": "file",
    "hash_sha1": "file",
    "hash_sha256": "file",
}


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}
    section = _SECTION_MAP.get(finding_type)
    if section is None:
        return {"verdict": "not_checked", "detail": "Unsupported finding type"}

    status, body, err = safe_json_request(
        "GET", f"{_BASE_URL}/{section}/{value}/general",
        headers={"X-OTX-API-KEY": api_key},
    )
    if err:
        return {"verdict": "error", "detail": f"OTX request failed: {err}"}
    if status == 404:
        return {"verdict": "unknown", "detail": "Not found in OTX"}
    if status != 200 or body is None:
        return {"verdict": "error", "detail": explain_http("OTX", status)}

    pulse_count = body.get("pulse_info", {}).get("count", 0)
    if pulse_count >= 3:
        verdict = "malicious"
    elif pulse_count >= 1:
        verdict = "suspicious"
    else:
        verdict = "unknown"

    detail = f"Referenced in {pulse_count} OTX threat pulse(s)"
    return {"verdict": verdict, "detail": detail}
