"""AlienVault OTX client - IP/domain/URL/hash pulse lookup."""
from __future__ import annotations

from .base import brief, compose, http_verdict, path_segment, safe_json_request

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
        "GET", f"{_BASE_URL}/{section}/{path_segment(value)}/general",
        headers={"X-OTX-API-KEY": api_key},
    )
    if err:
        return {"verdict": "error", "detail": f"OTX request failed: {err}"}
    if status == 404:
        return {"verdict": "unknown", "detail": "Not found in OTX"}
    if status != 200 or body is None:
        return http_verdict("OTX", status)

    pulse_info = body.get("pulse_info") or {}
    pulse_count = pulse_info.get("count", 0)
    if pulse_count >= 3:
        verdict = "malicious"
    elif pulse_count >= 1:
        verdict = "suspicious"
    else:
        verdict = "unknown"

    # The pulses are already in this response. A count says an indicator is
    # known without saying what for, which is the reason to ask OTX.
    pulses = pulse_info.get("pulses") or []
    families: list[str] = []
    adversaries: list[str] = []
    for pulse in pulses:
        for family in pulse.get("malware_families") or []:
            name = family.get("display_name") if isinstance(family, dict) else family
            if name and name not in families:
                families.append(str(name))
        actor = pulse.get("adversary")
        if actor and actor not in adversaries:
            adversaries.append(str(actor))

    # Pulse names are free text and contain their own commas, so an
    # unquoted list hides where one ends.
    names = [f'"{p["name"]}"' for p in pulses if p.get("name")]
    return {"verdict": verdict, "detail": compose(
        f"Referenced in {pulse_count} OTX threat pulse(s)",
        f"pulses: {brief(names, limit=3)}" if names else "",
        f"malware: {brief(families, limit=3)}" if families else "",
        f"actor: {brief(adversaries, limit=2)}" if adversaries else "",
    )}
