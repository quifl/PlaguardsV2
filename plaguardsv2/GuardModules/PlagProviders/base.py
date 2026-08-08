"""Shared helpers for provider modules: a small sliding-window rate limiter
and a "never raise" JSON request wrapper (mirrors the defensive pattern
used by Plaguards' own PlagParser.py - a failed lookup should degrade to an
'error' verdict, never crash the analysis)."""
from __future__ import annotations

import time
from collections import deque

import requests


class RateLimiter:
    def __init__(self, max_calls: int, period_seconds: float):
        self.max_calls = max_calls
        self.period = period_seconds
        self._calls: deque[float] = deque()

    def wait(self) -> None:
        now = time.monotonic()
        while self._calls and now - self._calls[0] > self.period:
            self._calls.popleft()
        if len(self._calls) >= self.max_calls:
            sleep_for = self.period - (now - self._calls[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
        self._calls.append(time.monotonic())


def explain_http(provider: str, status: int | None) -> str:
    """Turn a bare status code into something an analyst can act on.
    "OTX HTTP 400" tells you nothing; "the provider rejected this value"
    tells you not to bother re-running it."""
    messages = {
        400: "provider rejected this value as not queryable",
        401: "API key rejected - check it in Settings",
        403: "not permitted on your API plan",
        404: "no record for this indicator",
        429: "rate limit reached - try again later",
        500: "provider had a server error",
        502: "provider gateway error",
        503: "provider temporarily unavailable",
    }
    detail = messages.get(status or 0, f"unexpected HTTP {status}")
    return f"{provider}: {detail}"


def safe_json_request(method: str, url: str, **kwargs) -> tuple[int | None, dict | None, str | None]:
    """Returns (status_code, json_body, error_message). Never raises."""
    try:
        resp = requests.request(method, url, timeout=kwargs.pop("timeout", 15), **kwargs)
    except requests.RequestException as exc:
        return None, None, str(exc)
    try:
        body = resp.json()
    except ValueError:
        body = None
    return resp.status_code, body, None
