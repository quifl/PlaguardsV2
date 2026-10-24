"""Shared helpers for provider modules: a small sliding-window rate limiter
and a "never raise" JSON request wrapper (mirrors the defensive pattern
used by Plaguards' own PlagParser.py - a failed lookup should degrade to an
'error' verdict, never crash the analysis)."""
from __future__ import annotations

import threading
import time
from collections import deque
from urllib.parse import quote

import requests


class RateLimiter:
    def __init__(self, max_calls: int, period_seconds: float):
        self.max_calls = max(1, max_calls)
        self.period = period_seconds
        self._calls: deque[float] = deque()
        # Held through the sleep: two analyses running at once must queue for the
        # quota, not both read a free slot and spend the same one.
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            while self._calls and now - self._calls[0] > self.period:
                self._calls.popleft()
            if len(self._calls) >= self.max_calls:
                sleep_for = self.period - (now - self._calls[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
            self._calls.append(time.monotonic())


def path_segment(value: str) -> str:
    """Percent-encode an indicator for use inside a URL path.

    Interpolated raw, "http://a.invalid/../../../v1/pulses" collapses to a
    different endpoint, letting the sample's author choose the URL this tool
    calls with the analyst's key.
    """
    return quote(str(value), safe="")


def explain_http(provider: str, status: int | None) -> str:
    """Turn a bare status code into something an analyst can act on.
    "OTX HTTP 400" tells you nothing; "the provider rejected this value"
    tells you not to bother re-running it."""
    messages = {
        400: "provider rejected this value as not queryable",
        401: "API key rejected; check it in Settings",
        403: "not permitted on your API plan",
        404: "no record for this indicator",
        429: "rate limit reached; try again later",
        500: "provider had a server error",
        502: "provider gateway error",
        503: "provider temporarily unavailable",
    }
    detail = messages.get(status or 0, f"unexpected HTTP {status}")
    return f"{provider}: {detail}"


def http_verdict(provider: str, status: int | None) -> dict:
    """The result row for a response that carried no usable answer.

    A 404 is the provider saying it has no record: that is an answer
    ("unknown", and cacheable), not a failure to be retried on every run.
    """
    return {"verdict": "unknown" if status == 404 else "error",
            "detail": explain_http(provider, status)}


# A provider answer is one table cell, so this caps the context at enough
# for the CVEs or pulse names that make a verdict actionable.
MAX_DETAIL = 320


def brief(items, limit: int = 4) -> str:
    """Join a few values for a one-line summary.

    The count of what was dropped is kept: "3 more" is the difference between
    a host with four open ports and one with forty, and silently truncating
    loses exactly the signal that mattered.
    """
    values = [str(i).strip() for i in items if str(i) and str(i).strip()]
    if not values:
        return ""
    shown = ", ".join(values[:limit])
    if len(values) > limit:
        shown += f" (+{len(values) - limit} more)"
    return shown


def compose(*parts: str) -> str:
    """Join the non-empty pieces of a detail string, trimmed to one cell."""
    text = ", ".join(p for p in parts if p)
    return text if len(text) <= MAX_DETAIL else text[: MAX_DETAIL - 1] + "…"


def explain_exception(exc: Exception, timeout: float) -> str:
    """Why the call never reached the provider, in words that belong in a
    report.

    str(exc) is a urllib3 repr that lands verbatim in a shared PDF and says
    nothing the exception type does not.
    """
    if isinstance(exc, requests.Timeout):
        return f"no response within {timeout:g}s"
    # SSLError lives only under requests.exceptions, and subclasses ConnectionError.
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS handshake failed"
    if isinstance(exc, requests.ConnectionError):
        return "could not be reached; check the network connection"
    if isinstance(exc, requests.TooManyRedirects):
        return "redirected too many times"
    return "the request could not be completed"


def safe_json_request(method: str, url: str, **kwargs) -> tuple[int | None, dict | None, str | None]:
    """Returns (status_code, json_body, error_message). Never raises."""
    timeout = kwargs.pop("timeout", 15)
    try:
        resp = requests.request(method, url, timeout=timeout, **kwargs)
    except requests.RequestException as exc:
        return None, None, explain_exception(exc, timeout)
    try:
        body = resp.json()
    except ValueError:
        body = None
    return resp.status_code, body, None
