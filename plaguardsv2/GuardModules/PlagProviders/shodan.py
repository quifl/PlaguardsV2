"""Shodan client - IP exposure info (open ports, tags), not a pure verdict
service, but useful triage context."""
from __future__ import annotations

from .base import explain_http, safe_json_request

SUPPORTS = {"ip"}
_URL = "https://api.shodan.io/shodan/host/{ip}"


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}
    if finding_type not in SUPPORTS:
        return {"verdict": "not_checked", "detail": "Unsupported finding type"}

    status, body, err = safe_json_request(
        "GET", _URL.format(ip=value), params={"key": api_key},
    )
    if err:
        return {"verdict": "error", "detail": f"Shodan request failed: {err}"}
    if status == 404:
        return {"verdict": "unknown", "detail": "No Shodan data for this IP"}
    if status != 200 or body is None:
        return {"verdict": "error", "detail": explain_http("Shodan", status)}

    ports = body.get("ports") or []
    tags = body.get("tags") or []
    vulns = body.get("vulns") or []
    org = body.get("org") or "unknown org"

    if tags or vulns:
        verdict = "suspicious"
    elif ports:
        verdict = "clean"
    else:
        verdict = "unknown"

    detail = f"{org}, {len(ports)} open port(s)"
    if tags:
        detail += f", tags: {', '.join(tags)}"
    if vulns:
        detail += f", {len(vulns)} known vuln(s)"
    return {"verdict": verdict, "detail": detail}
