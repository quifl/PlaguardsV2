"""Shodan client - IP exposure info (open ports, tags), not a pure verdict
service, but useful triage context."""
from __future__ import annotations

from .base import brief, compose, http_verdict, path_segment, safe_json_request

SUPPORTS = {"ip"}
_URL = "https://api.shodan.io/shodan/host/{ip}"


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}
    if finding_type not in SUPPORTS:
        return {"verdict": "not_checked", "detail": "Unsupported finding type"}

    status, body, err = safe_json_request(
        "GET", _URL.format(ip=path_segment(value)), params={"key": api_key},
    )
    if err:
        return {"verdict": "error", "detail": f"Shodan request failed: {err}"}
    if status == 404:
        return {"verdict": "unknown", "detail": "No Shodan data for this IP"}
    if status != 200 or body is None:
        return http_verdict("Shodan", status)

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

    # Which ports and CVEs, not how many: "4444, 8080" separates a web server from
    # a listener, and a named CVE can be looked up.
    return {"verdict": verdict, "detail": compose(
        org,
        f"{len(ports)} open port(s): {brief(sorted(ports), limit=8)}" if ports
        else "no open ports",
        f"OS: {body['os']}" if body.get("os") else "",
        brief(body.get("hostnames") or [], limit=2),
        f"tags: {brief(tags)}" if tags else "",
        f"{len(vulns)} known vuln(s): {brief(sorted(vulns), limit=5)}" if vulns else "",
        f"last seen {str(body['last_update'])[:10]}" if body.get("last_update") else "",
    )}
