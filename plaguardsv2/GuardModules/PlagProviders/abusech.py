"""abuse.ch client: MalwareBazaar for hashes and malware-family signatures,
URLhaus for URLs, ThreatFox for IP/domain IOC search. All use the same
unified Auth-Key from auth.abuse.ch."""
from __future__ import annotations

from .base import explain_http, safe_json_request

SUPPORTS = {"hash_md5", "hash_sha1", "hash_sha256", "ip", "domain", "url", "signature"}

_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def lookup(finding_type: str, value: str, api_key: str | None) -> dict:
    if not api_key:
        return {"verdict": "not_checked", "detail": "No API key configured"}
    if finding_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        return _malwarebazaar_hash(value, api_key)
    if finding_type == "signature":
        return _malwarebazaar_signature(value, api_key)
    if finding_type == "url":
        # URLhaus indexes whole URLs; ThreatFox is the fallback for the rest.
        result = _urlhaus_url(value, api_key)
        if result["verdict"] in ("malicious", "error"):
            return result
        return _threatfox_ioc(value, api_key)
    if finding_type in ("ip", "domain"):
        return _threatfox_ioc(value, api_key)
    return {"verdict": "not_checked", "detail": "Unsupported finding type"}


def _malwarebazaar_signature(value: str, api_key: str) -> dict:
    """Look a malware family name up as a signature, the way the original
    Plaguards' `signature` query type did."""
    status, body, err = safe_json_request(
        "POST", _BAZAAR_URL,
        data={"query": "get_siginfo", "signature": value, "limit": 5},
        headers={"Auth-Key": api_key},
    )
    if err:
        return {"verdict": "error", "detail": f"MalwareBazaar request failed: {err}"}
    if status != 200 or body is None:
        return {"verdict": "error", "detail": explain_http("MalwareBazaar", status)}

    qstatus = body.get("query_status")
    if qstatus in ("signature_not_found", "no_results"):
        return {"verdict": "unknown", "detail": f"No samples tagged '{value}'"}
    if qstatus != "ok":
        return {"verdict": "error", "detail": f"MalwareBazaar query_status: {qstatus}"}

    entries = body.get("data") or []
    if not entries:
        return {"verdict": "unknown", "detail": f"No samples tagged '{value}'"}
    types = sorted({e.get("file_type") for e in entries if e.get("file_type")})
    detail = f"Known malware family - {len(entries)} recent sample(s)"
    if types:
        detail += f" ({', '.join(types[:4])})"
    return {"verdict": "malicious", "detail": detail}


def _urlhaus_url(value: str, api_key: str) -> dict:
    status, body, err = safe_json_request(
        "POST", _URLHAUS_URL,
        data={"url": value},
        headers={"Auth-Key": api_key},
    )
    if err:
        return {"verdict": "error", "detail": f"URLhaus request failed: {err}"}
    if status != 200 or body is None:
        return {"verdict": "error", "detail": explain_http("URLhaus", status)}

    if body.get("query_status") != "ok":
        return {"verdict": "unknown", "detail": "Not found in URLhaus"}
    threat = body.get("threat") or "malware URL"
    url_status = body.get("url_status") or "unknown"
    tags = ", ".join(body.get("tags") or [])
    detail = f"Listed in URLhaus as {threat} ({url_status})"
    if tags:
        detail += f" (tags: {tags})"
    return {"verdict": "malicious", "detail": detail}


def _malwarebazaar_hash(value: str, api_key: str) -> dict:
    status, body, err = safe_json_request(
        "POST", _BAZAAR_URL,
        data={"query": "get_info", "hash": value},
        headers={"Auth-Key": api_key},
    )
    if err:
        return {"verdict": "error", "detail": f"MalwareBazaar request failed: {err}"}
    if status != 200 or body is None:
        return {"verdict": "error", "detail": explain_http("MalwareBazaar", status)}

    qstatus = body.get("query_status")
    if qstatus == "hash_not_found":
        return {"verdict": "unknown", "detail": "Not found in MalwareBazaar"}
    if qstatus != "ok":
        return {"verdict": "error", "detail": f"MalwareBazaar query_status: {qstatus}"}

    entries = body.get("data") or []
    if not entries:
        return {"verdict": "unknown", "detail": "Not found in MalwareBazaar"}
    entry = entries[0]
    sig = entry.get("signature") or "unspecified malware family"
    tags = ", ".join(entry.get("tags") or [])
    file_type = entry.get("file_type") or "unknown type"
    detail = f"Known malware sample ({file_type}): {sig}"
    if tags:
        detail += f" (tags: {tags})"
    return {"verdict": "malicious", "detail": detail}


def _threatfox_ioc(value: str, api_key: str) -> dict:
    status, body, err = safe_json_request(
        "POST", _THREATFOX_URL,
        json={"query": "search_ioc", "search_term": value},
        headers={"Auth-Key": api_key},
    )
    if err:
        return {"verdict": "error", "detail": f"ThreatFox request failed: {err}"}
    if status != 200 or body is None:
        return {"verdict": "error", "detail": explain_http("ThreatFox", status)}

    qstatus = body.get("query_status")
    if qstatus in ("no_result", "illegal_search_term"):
        return {"verdict": "unknown", "detail": "Not found in ThreatFox"}
    if qstatus != "ok":
        return {"verdict": "error", "detail": f"ThreatFox query_status: {qstatus}"}

    entries = body.get("data") or []
    if not entries:
        return {"verdict": "unknown", "detail": "Not found in ThreatFox"}
    entry = entries[0]
    malware = entry.get("malware_printable") or entry.get("malware") or "unspecified"
    threat_type = entry.get("threat_type_desc") or entry.get("threat_type") or "IOC"
    confidence = entry.get("confidence_level")
    detail = f"{threat_type} associated with {malware}"
    if confidence is not None:
        detail += f" (confidence {confidence}%)"
    return {"verdict": "malicious", "detail": detail}
