"""Speed fixes that must not change what the tool reports.

Each change here was made to keep analyses and reports fast; these tests pin
both halves: the time it saves, and the output it must leave untouched.
"""
import random
import threading
import time
from pathlib import Path

from plaguardsv2.GuardModules import PlagDeobfus, PlagGeo, PlagGrep, PlagIntel, PlagReport, PlagTrace
from plaguardsv2.GuardModules.PlagProviders import REGISTRY, base

EXAMPLE = (Path(__file__).resolve().parents[1] / "samples" / "example-analysis.ps1").read_text(encoding="utf-8")


# Reverse DNS and geolocation

def test_a_slow_reverse_lookup_is_cut_off_and_its_late_answer_kept(monkeypatch):
    """gethostbyaddr ignores socket timeouts; a first lookup took 4.6 s here."""
    def slow(value):
        time.sleep(0.6)
        return ("late.example.invalid", [], [value])
    monkeypatch.setattr(PlagGeo.socket, "gethostbyaddr", slow)
    address = "192.0.2.201"
    start = time.perf_counter()
    assert PlagGeo.reverse_dns(address, timeout=0.1) == ""
    assert time.perf_counter() - start < 0.4
    deadline = time.monotonic() + 5     # polled, so a slow CI runner cannot flake it
    while (answer := PlagGeo.reverse_dns(address, timeout=0.1)) == "" and time.monotonic() < deadline:
        time.sleep(0.05)
    assert answer == "late.example.invalid"


def test_addresses_are_located_in_parallel(monkeypatch):
    monkeypatch.setattr(PlagGeo, "reverse_dns", lambda value, timeout=None: time.sleep(0.3) or "")
    monkeypatch.setattr(PlagGeo, "_sources", lambda conn: ({"city": "", "country": "", "asn": ""}, ""))
    addresses = [f"8.8.{i}.8" for i in range(6)]
    start = time.perf_counter()
    located = PlagGeo.locate_many(addresses + addresses[:2])
    assert time.perf_counter() - start < 1.2          # six lookups in a row would take 1.8 s
    assert list(located) == addresses                  # once each, in first-seen order


# Threat intel

class _Finding:
    def __init__(self, type_, value):
        self.type, self.value, self.intel = type_, value, {}


def test_providers_answer_in_parallel_but_each_one_request_at_a_time(monkeypatch):
    active, peak = {}, {}
    lock = threading.Lock()

    def fake(provider_id):
        def lookup(finding_type, value, api_key):
            with lock:
                active[provider_id] = active.get(provider_id, 0) + 1
                peak[provider_id] = max(peak.get(provider_id, 0), active[provider_id])
            time.sleep(0.15)
            with lock:
                active[provider_id] -= 1
            return {"verdict": "clean", "detail": provider_id}
        return lookup

    for provider_id, module in REGISTRY.items():
        monkeypatch.setattr(module, "lookup", fake(provider_id))
    findings = [_Finding("ip", f"8.8.{i}.8") for i in range(3)]
    start = time.perf_counter()
    PlagIntel.enrich(findings, conn=None, use_cache=False)
    elapsed = time.perf_counter() - start
    ip_providers = [pid for pid, m in REGISTRY.items() if "ip" in m.SUPPORTS]
    assert elapsed < 0.15 * 3 * len(ip_providers) / 2   # far below the sequential total
    assert max(peak.values()) == 1                      # never two calls to one provider at once
    order = [k for k in REGISTRY if k in findings[0].intel]
    assert list(findings[0].intel) == order             # same key order as a sequential run


def test_a_provider_that_raises_costs_one_row_not_the_analysis(monkeypatch):
    def broken(finding_type, value, api_key):
        raise KeyError("data")
    monkeypatch.setattr(REGISTRY["virustotal"], "lookup", broken)
    finding = _Finding("domain", "example.com")
    PlagIntel.enrich([finding], conn=None, use_cache=False)
    assert finding.intel["virustotal"]["verdict"] == "error"


def test_the_rate_limiter_is_shared_safely_between_threads():
    limiter = base.RateLimiter(max_calls=1, period_seconds=0.3)
    stamps = []
    threads = [threading.Thread(target=lambda: (limiter.wait(), stamps.append(time.monotonic())))
               for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert abs(stamps[1] - stamps[0]) >= 0.25


def test_no_record_is_an_answer_not_an_error():
    assert base.http_verdict("AbuseIPDB", 404)["verdict"] == "unknown"
    assert base.http_verdict("AbuseIPDB", 500)["verdict"] == "error"


# Extraction

def test_pieces_of_a_reported_hash_are_not_reported_again():
    script = ('$h = ("e3b0c44298fc1c149afbf4c8,996fb92427ae41e4649b,934ca495991b7852b855" '
              '-split ",") -join ""; Write-Host $h')
    result = PlagDeobfus.run(script)
    traced = PlagTrace.trace(result.deobfuscated)
    found = PlagGrep.scan(result.original, result.deobfuscated, PlagTrace.enrichment_text(traced))
    assert any(f.type == "hash_sha256" for f in found)
    assert not any(f.type == "hash_partial" for f in found)


def test_an_unrelated_partial_hash_is_still_reported():
    found = PlagGrep.scan("$p = 'ba7816bf8f01cfea'", "$p = 'ba7816bf8f01cfea'")
    assert [f.value for f in found if f.type == "hash_partial"] == ["ba7816bf8f01cfea"]


# Engine scanners

def _reference_spans(text):
    """The original per-character implementation, kept as the oracle."""
    spans, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in ("'", '"'):
            quote, j, terminated = c, i + 1, False
            while j < n:
                if quote == '"' and text[j] == "`" and j + 1 < n:
                    j += 2
                    continue
                if text[j] == quote:
                    if j + 1 < n and text[j + 1] == quote:
                        j += 2
                        continue
                    j += 1
                    terminated = True
                    break
                j += 1
            spans.append((i, j if terminated else n))
            i = j if terminated else n
        else:
            i += 1
    return spans


def test_string_spans_match_the_reference_scanner():
    rng = random.Random(7)
    for _ in range(20_000):
        text = "".join(rng.choice("ab '\"`;\n#(") for _ in range(rng.randint(0, 20)))
        assert PlagDeobfus._find_string_spans(text) == _reference_spans(text), repr(text)


def test_large_scripts_scale_linearly():
    """The span checks were quadratic: 718 KB took 10 s, now well under 2."""
    big = (EXAMPLE + "\n") * 200
    start = time.perf_counter()
    PlagDeobfus.run(big)
    assert time.perf_counter() - start < 6


# Reports

def test_the_cover_logo_is_embedded_at_print_size_not_full_size():
    uri = PlagReport._logo_data_uri()
    assert uri and len(uri) < 500_000   # the 2000 px original was over 1 MB
