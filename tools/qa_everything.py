"""End-to-end QA for PlaguardsV2.

Builds a set of inert dummy samples, drives every feature with them (engine,
recipe search, web dashboard, Quick IOC Lookup, triage, reports, exports,
History, Settings, CyberChef, CLI), checks each result, times each step, and
writes a QA report next to every file it produced.

    python tools/qa_everything.py              # writes qa-output/<timestamp>/
    python tools/qa_everything.py --out DIR

It runs offline on a throwaway database: the network is blocked inside this
process before anything is imported, provider keys are hidden from it, and
neither data/ nor .env is written. Threat-intel answers are simulated with
canned provider responses so that path is exercised too. Needs the dev
requirements (pytest), because the samples are built from the test fixtures.
Exit status is 1 when any check fails.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import platform
import re
import socket
import sys
import time
import zipfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.chdir(ROOT)


def _no_network(*_args, **_kwargs):
    raise OSError("network disabled by qa_everything")


# Before any project import: nothing below may reach a provider or a resolver.
socket.create_connection = _no_network
socket.socket.connect = lambda self, *a, **k: _no_network()
socket.gethostbyaddr = _no_network

import pypdfium2  # noqa: E402
from click.testing import CliRunner  # noqa: E402

from plaguardsv2.GuardModules import (  # noqa: E402
    PlagConfig, PlagDeobfus, PlagGrep, PlagMagic, PlagStore, PlagTrace,
)
from plaguardsv2.GuardModules.PlagProviders import base as provider_base  # noqa: E402
from plaguardsv2.GuardModules.PlagProviders import virustotal  # noqa: E402
from plaguardsv2.PlagCLI import cli  # noqa: E402
from plaguardsv2.PlagWeb import create_app, cyberchef  # noqa: E402

import deob_cases  # noqa: E402
import test_deob_matrix_other as matrix_other  # noqa: E402
import test_deob_matrix_ps as matrix_ps  # noqa: E402
import test_magic  # noqa: E402
from corpus import generator as corpus_gen  # noqa: E402
from corpus import metrics as corpus_metrics  # noqa: E402
from corpus.harness import run_engine as corpus_engine  # noqa: E402

# The keys in .env stay unread by this run; providers answer "not checked"
# unless the simulated-intel section sets fake ones in the throwaway database.
for _provider in PlagConfig.PROVIDERS:
    os.environ.pop(_provider["env_var"], None)

EXAMPLE = (ROOT / "samples" / "example-analysis.ps1").read_text(encoding="utf-8")
EXAMPLE_TYPES = {
    "crypto_wallet", "domain", "email", "file_path", "hash_md5", "hash_partial", "hash_sha1",
    "hash_sha256", "ip", "ip_port", "ipv6_port", "mutex", "registry_key", "scheduled_task",
    "service_name", "signature", "unc_path", "url", "user_agent",
}
REPORT_HEADINGS = ["Contents", "Disclaimer", "Analysis Summary", "Indicators at a glance",
                   "Finding details", "Deobfuscation", "Appendix A", "Appendix B"]
# Seconds. Exceeding one is a warning, not a failure: timings vary by machine.
BUDGET = {"analysis": 2.0, "page": 1.0, "pdf": 8.0, "large_input": 3.0, "corpus": 30.0}


class Results:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, section: str, name: str, status: str, detail: str = "", seconds: float | None = None):
        self.rows.append({"section": section, "name": name, "status": status,
                          "detail": detail, "seconds": seconds})
        mark = {"PASS": "ok  ", "FAIL": "FAIL", "WARN": "warn", "INFO": "info"}[status]
        took = f" ({seconds:.2f}s)" if seconds is not None else ""
        print(f"  [{mark}] {section}: {name}{took}{' - ' + detail if detail and status != 'PASS' else ''}")

    def check(self, section: str, name: str, ok: bool, detail: str = "", seconds: float | None = None):
        self.add(section, name, "PASS" if ok else "FAIL", detail, seconds)
        return ok

    def budget(self, section: str, name: str, seconds: float, limit: float):
        if seconds > limit:
            self.add(section, f"{name} within {limit:g}s", "WARN", f"took {seconds:.2f}s", seconds)

    def count(self, status: str) -> int:
        return sum(1 for r in self.rows if r["status"] == status)


R = Results()


@contextmanager
def stopwatch():
    box = {}
    start = time.perf_counter()
    yield box
    box["s"] = time.perf_counter() - start


def pdf_texts(data: bytes) -> list[str]:
    doc = pypdfium2.PdfDocument(data)
    try:
        texts = []
        for i in range(len(doc)):
            page = doc[i]
            textpage = page.get_textpage()
            texts.append(textpage.get_text_range())
            textpage.close()
            page.close()
        return texts
    finally:
        doc.close()


def flashes(html: str) -> list[str]:
    return re.findall(r'<div class="flash flash-\w+">(.*?)</div>', html, re.S)


def analysis_id_from(location: str) -> int:
    return int(location.rstrip("/").rsplit("/", 1)[1])


# Samples

def build_samples(out: Path) -> dict[str, str]:
    """The dummy samples: every one inert, built from the repository's own
    fixtures (non-routable names and addresses, an inert banner payload)."""
    samples = {"example-analysis.ps1": EXAMPLE, "encoded-stages.ps1": test_magic._script()}
    by_language: dict[str, list[str]] = {}
    for name, source, _want in matrix_other.CASES:
        by_language.setdefault(name.split("-", 1)[0], []).append(source)
    extensions = {"vbs": "vbs", "js": "js", "bat": "bat", "cmd": "cmd", "txt": "txt", "log": "log"}
    for language, sources in by_language.items():
        samples[f"techniques.{extensions[language]}"] = "\n\n".join(sources) + "\n"

    folder = out / "samples"
    folder.mkdir(parents=True, exist_ok=True)
    for name, text in samples.items():
        try:
            (folder / name).write_text(text, encoding="utf-8")
        except OSError as exc:  # antivirus can refuse a file; the run uses the text in memory
            R.add("samples", f"write {name}", "WARN", f"not written: {exc}")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in samples.items():
            zf.writestr(f"dummy/{name}", text)
    samples_zip = zip_buf.getvalue()
    (folder / "all-samples.zip").write_bytes(samples_zip)
    R.add("samples", f"{len(samples)} dummy samples and all-samples.zip written", "INFO", str(folder))
    return samples


# Engine

def engine_checks(samples: dict[str, str]) -> None:
    section = "engine"
    result = PlagDeobfus.run(EXAMPLE)
    traced = PlagTrace.trace(result.deobfuscated)
    findings = PlagGrep.scan(result.original, result.deobfuscated, PlagTrace.enrichment_text(traced))
    types = {f.type for f in findings}
    R.check(section, "example: every indicator type found", EXAMPLE_TYPES <= types,
            f"missing: {sorted(EXAMPLE_TYPES - types)}")
    R.check(section, "example: no encoded run left unresolved", not result.residual_blobs)
    R.check(section, "example: converged", result.converged)

    failed = [name for name, source, want in matrix_ps.CASES + matrix_other.CASES
              if want not in deob_cases.recovered(source)]
    total = len(matrix_ps.CASES) + len(matrix_other.CASES)
    R.check(section, f"technique matrix: {total - len(failed)}/{total} cases recovered", not failed,
            f"failed: {failed}")

    staged = PlagDeobfus.run(samples["encoded-stages.ps1"])
    recipes = [e for e in staged.pass_log if "CyberChef-style recipe" in e]
    stage_text = staged.deobfuscated
    wanted = ["stage-a.example.invalid", "198.51.100.77", "stage-c.example.invalid", "stage-d.example.invalid"]
    R.check(section, "encoded stages: all four recovered by recipe search",
            bool(recipes) and all(w in stage_text for w in wanted), "; ".join(recipes))
    R.check(section, "encoded stages: nothing left reported as still encoded", not staged.residual_blobs)

    wrong = []
    for name, encoded, recipe in test_magic.ENCODED:
        found = PlagMagic.magic(encoded)
        if found is None or found.label != recipe or test_magic.MARK not in found.output:
            wrong.append(name)
    R.check(section, f"recipe search: {len(test_magic.ENCODED) - len(wrong)}/{len(test_magic.ENCODED)} encodings",
            not wrong, f"wrong: {wrong}")
    noisy = [name for name, value in test_magic.NOT_ENCODED if PlagMagic.magic(value) is not None]
    R.check(section, "recipe search: ordinary values left alone", not noisy, f"decoded: {noisy}")

    for split in ("dev", "holdout"):
        with stopwatch() as t:
            scores = [corpus_metrics.score_sample(s, corpus_engine) for s in corpus_gen.build(split)]
            card = corpus_metrics.scorecard(scores)
        R.check(section, f"corpus {split}: completeness {card['sample_completeness']:.1%}, "
                         f"false indicators {card['false_indicators']} ({card['samples']} samples)",
                card["sample_completeness"] >= 0.95 and card["false_indicators"] == 0,
                seconds=t["s"])
        R.budget(section, f"corpus {split}", t["s"], BUDGET["corpus"])

    big = (EXAMPLE + "\n") * 200
    with stopwatch() as t:
        PlagDeobfus.run(big)
    R.check(section, f"large input ({len(big) // 1024} KB) processed", True, seconds=t["s"])
    R.budget(section, "large input", t["s"], BUDGET["large_input"])
    huge = PlagDeobfus.run("a" * (PlagDeobfus.MAX_INPUT_SIZE + 10))
    R.check(section, "oversized input truncated, not crashed", huge.truncated)


# Web

class Web:
    def __init__(self, out: Path):
        self.app = create_app(str(out / "qa.db"))
        self.app.config["TESTING"] = True
        self.c = self.app.test_client()
        self.out = out

    def get(self, url: str, section: str, name: str, status: int = 200, own_page: bool = True):
        with stopwatch() as t:
            resp = self.c.get(url)
        R.check(section, name, resp.status_code == status, f"HTTP {resp.status_code}", t["s"])
        if own_page and status == 200 and resp.mimetype == "text/html":
            R.budget(section, name, t["s"], BUDGET["page"])
            body = resp.get_data(as_text=True)
            leaks = [p for p in (">None<", "Traceback", "{{", "{%", "&amp;mdash;") if p in body]
            if leaks:
                R.add(section, f"{name}: rendering artefacts", "FAIL", str(leaks))
        return resp

    def upload(self, files: list[tuple[str, bytes]], **form):
        data = {"file": [(io.BytesIO(b), n) for n, b in files], "skip_intel": "on", **form}
        return self.c.post("/analyze", data=data, content_type="multipart/form-data")

    def save(self, name: str, data: bytes) -> Path:
        path = self.out / "outputs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path


def web_checks(web: Web, samples: dict[str, str]) -> dict:
    section = "pages"
    for url in ("/", "/history", "/tutorial", "/settings"):
        web.get(url, section, f"GET {url}")
    web.get("/no-such-page", section, "unknown page is a 404", 404)
    web.get("/analysis/999999", section, "missing analysis is a 404", 404)

    section = "analyze"
    with stopwatch() as t:
        resp = web.c.post("/analyze", data={"script_text": EXAMPLE, "skip_intel": "on"})
    ok = R.check(section, "paste the example script", resp.status_code == 302, seconds=t["s"])
    R.budget(section, "paste analysis", t["s"], BUDGET["analysis"])
    example_id = analysis_id_from(resp.headers["Location"]) if ok else None

    resp = web.c.post("/analyze", data={"script_text": "   "})
    R.check(section, "empty paste is refused with a message",
            "Paste a script" in " ".join(flashes(web.c.get("/").get_data(as_text=True))))

    with stopwatch() as t:
        resp = web.upload([("encoded-stages.ps1", samples["encoded-stages.ps1"].encode())])
    ok = R.check(section, "upload one file", resp.status_code == 302 and "/analysis/" in resp.headers["Location"],
                 seconds=t["s"])
    staged_id = analysis_id_from(resp.headers["Location"]) if ok else None

    language_files = [(n, t.encode()) for n, t in samples.items() if n.startswith("techniques.")]
    with stopwatch() as t:
        resp = web.upload(language_files, batch_report="separate")
    location = resp.headers.get("Location", "")
    R.check(section, f"upload {len(language_files)} files as separate reports", "/history?selected=" in location,
            location, t["s"])
    batch_ids = [int(i) for i in location.split("selected=")[-1].split(",") if i.isdigit()]
    R.check(section, "every file in the batch analyzed", len(batch_ids) == len(language_files),
            f"{len(batch_ids)} of {len(language_files)}")

    zip_bytes = (web.out / "samples" / "all-samples.zip").read_bytes()
    with stopwatch() as t:
        resp = web.upload([("all-samples.zip", zip_bytes)], batch_report="combined")
    R.check(section, "upload a zip and ask for one combined report",
            "/history/report/view?ids=" in resp.headers.get("Location", ""), seconds=t["s"])
    resp = web.upload([("tool.exe", b"MZ")])
    R.check(section, "unsupported file type is refused",
            "Nothing to analyze" in " ".join(flashes(web.c.get("/").get_data(as_text=True))))

    section = "result page"
    page = web.get(f"/analysis/{example_id}", section, "example result page").get_data(as_text=True)
    with web.app.app_context():
        conn = PlagStore.get_conn(web.app.config["DB_PATH"])
        stored = PlagStore.get_analysis(conn, example_id)
    R.check(section, "shows every stored finding", f"{len(stored['findings'])} findings" in page,
            f"{len(stored['findings'])} stored")
    R.check(section, "transform log and notes are shown", "deobfuscation transforms applied" in page)
    staged_page = web.get(f"/analysis/{staged_id}", section, "encoded-stages result page").get_data(as_text=True)
    R.check(section, "encoded runs listed with their recipes",
            "From Hex &gt; From Base64 &gt; Gunzip" in staged_page and "ROT13" in staged_page)
    if cyberchef.manifest():
        R.check(section, "CyberChef buttons carry the recipe", "/cyberchef/#recipe=" in staged_page)

    section = "triage"
    finding_id = stored["findings"][0]["id"]
    resp = web.c.post(f"/analysis/{example_id}/finding/{finding_id}/triage", json={"status": "confirmed_threat"})
    R.check(section, "mark one finding as a confirmed threat", resp.status_code == 200)
    resp = web.c.post(f"/analysis/{staged_id}/triage-all", json={"status": "false_positive"})
    R.check(section, "mark every finding at once", resp.status_code == 200 and resp.get_json().get("updated", 0) > 0)
    resp = web.c.post(f"/analysis/{example_id}/finding/{finding_id}/triage", json={"status": "nonsense"})
    R.check(section, "an unknown verdict is rejected", resp.status_code == 400)

    section = "lookup"
    for value, kind, expect in [
        ("8.8.8.8", "auto", "(IP address)"),
        ("host.example.invalid", "auto", "was not sent to any provider"),
        ("hxxp://evil[.]example[.]com/a", "auto", "(URL)"),
        ("d41d8cd98f00b204e9800998ecf8427e", "auto", "(MD5 hash)"),
        ("AgentTesla", "signature", "(Signature)"),
        ("AgentTesla", "auto", "doesn&#39;t look like"),
    ]:
        with stopwatch() as t:
            body = web.c.post("/lookup", data={"ioc_value": value, "ioc_type": kind}).get_data(as_text=True)
        R.check(section, f"{value} ({kind})", expect in body, f"expected {expect!r}", t["s"])

    return {"example": example_id, "staged": staged_id, "batch": batch_ids}


def report_checks(web: Web, ids: dict) -> None:
    section = "reports"
    example_id, staged_id, batch_ids = ids["example"], ids["staged"], ids["batch"]
    with web.app.app_context():
        conn = PlagStore.get_conn(web.app.config["DB_PATH"])
        stored = PlagStore.get_analysis(conn, example_id)

    web.get(f"/analysis/{example_id}/report/view", section, "report viewer page")
    with stopwatch() as t:
        resp = web.c.get(f"/analysis/{example_id}/report/pdf")
    R.check(section, "single PDF report renders", resp.mimetype == "application/pdf", seconds=t["s"])
    R.budget(section, "single PDF report", t["s"], BUDGET["pdf"])
    web.save("report-example.pdf", resp.data)
    texts = pdf_texts(resp.data)
    joined = "\n".join(texts)
    missing = [h for h in REPORT_HEADINGS if h not in joined]
    R.check(section, f"report has every section ({len(texts)} pages)", not missing, f"missing: {missing}")
    contents = texts[1] if len(texts) > 1 else ""
    numbered = re.findall(r"(Analysis Summary|Finding details|Deobfuscation|Appendix A: Deobfuscated script)\s+(\d+)",
                          contents)
    R.check(section, "contents page quotes page numbers", len(numbered) >= 4, str(numbered))
    # Long values wrap inside their cells, so compare with all whitespace removed.
    flat = re.sub(r"\s+", "", joined)
    absent = [f["value"] for f in stored["findings"] if f["type"] != "signature"
              and re.sub(r"\s+", "", PlagGrep.defang(f["value"], f["type"])) not in flat]
    R.check(section, "every finding appears in the report, defanged", not absent, f"absent: {absent[:5]}")
    R.check(section, "confirmed-threat verdict is in the report", "confirmed threat" in joined)
    R.check(section, "geolocation section present", "Geolocation" in joined)
    R.check(section, "URLs are defanged in the findings", "hxxp://malicious[.]example[.]invalid" in flat)

    resp = web.c.get(f"/analysis/{example_id}/report/download?redact=1")
    R.check(section, "redacted PDF downloads", resp.mimetype == "application/pdf"
            and "-redacted" in resp.headers.get("Content-Disposition", ""))
    web.save("report-example-redacted.pdf", resp.data)

    resp = web.c.get(f"/analysis/{staged_id}/report/pdf")
    staged_flat = re.sub(r"\s+", "", "\n".join(pdf_texts(resp.data)))
    web.save("report-encoded-stages.pdf", resp.data)
    R.check(section, "recipe-search transform and its recipes in the report",
            "CyberChef-stylerecipe" in staged_flat and "repeatedinCyberChef" in staged_flat
            and "FromHex>FromBase64>Gunzip" in staged_flat)
    R.check(section, "indicators from encoded stages reach the report",
            all(v in staged_flat for v in ("stage-a[.]example[.]invalid", "198[.]51[.]100[.]77")))

    with stopwatch() as t:
        resp = web.c.get("/history/report?ids=" + ",".join(map(str, batch_ids)))
    R.check(section, f"combined PDF of {len(batch_ids)} analyses", resp.mimetype == "application/pdf", seconds=t["s"])
    R.budget(section, "combined PDF", t["s"], BUDGET["pdf"] * max(1, len(batch_ids)) / 2)
    web.save("report-combined.pdf", resp.data)
    combined = "\n".join(pdf_texts(resp.data))
    R.check(section, "combined report has a section per analysis",
            all(f"{i}. " in combined for i in range(1, len(batch_ids) + 1)))

    with stopwatch() as t:
        resp = web.c.post("/history/bulk-export", data={"analysis_id": [str(example_id), str(staged_id)]})
    names = zipfile.ZipFile(io.BytesIO(resp.data)).namelist() if resp.mimetype == "application/zip" else []
    R.check(section, "History zip export holds one PDF per analysis", len(names) == 2, str(names), t["s"])
    web.save("reports.zip", resp.data)

    section = "exports"
    resp = web.c.get(f"/analysis/{example_id}/table.csv")
    web.save("findings-example.csv", resp.data)
    lines = resp.data.decode("utf-8-sig").splitlines()
    R.check(section, "CSV has a row per finding", len(lines) - 1 == len(stored["findings"]),
            f"{len(lines) - 1} rows for {len(stored['findings'])} findings")
    risky = [ln for ln in lines[1:] if re.match(r'^[^,]*,[^,]*,[^,]*,"?[=+@-]', ln)]
    R.check(section, "CSV values cannot start a spreadsheet formula", not risky, str(risky[:2]))
    resp = web.c.get(f"/analysis/{example_id}/table.xlsx")
    web.save("findings-example.xlsx", resp.data)
    try:
        import openpyxl
        sheet = openpyxl.load_workbook(io.BytesIO(resp.data)).active
        R.check(section, "Excel workbook has a row per finding", sheet.max_row - 1 == len(stored["findings"]))
    except ImportError:
        R.add(section, "Excel workbook", "WARN", "openpyxl not installed")


def simulated_intel(web: Web) -> None:
    """Fake keys in the throwaway database and canned provider answers: the
    lookup path, its parallel fan-out, caching and the report rows, offline."""
    section = "threat intel (simulated)"
    for provider in ("virustotal", "abuseipdb", "otx"):
        web.c.post("/settings", data={"form": "keys", provider: "qa-fake-key"})

    malicious = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 40, "undetected": 20},
        "last_analysis_results": {"EngineA": {"category": "malicious", "result": "Trojan.QA"}},
        "reputation": -12}}}

    class Canned:
        def __init__(self, status, body):
            self.status_code, self._body = status, body

        def json(self):
            return self._body

    calls = []

    def fake_request(method, url, timeout=None, **_kwargs):
        calls.append(url)
        if "virustotal.com" in url:
            return Canned(200, malicious)
        return Canned(404, {})

    original_request, original_limiter = provider_base.requests.request, virustotal._limiter
    provider_base.requests.request = fake_request
    virustotal._limiter = provider_base.RateLimiter(10_000, 60)
    try:
        with stopwatch() as t:
            resp = web.c.post("/analyze", data={"script_text": EXAMPLE})
        analysis_id = analysis_id_from(resp.headers["Location"])
        R.check(section, f"analysis with lookups ({len(calls)} simulated provider calls)", bool(calls),
                seconds=t["s"])
        page = web.c.get(f"/analysis/{analysis_id}").get_data(as_text=True)
        R.check(section, "provider verdicts shown on the result page", "VirusTotal: malicious" in page)
        # Only answers are cached; a provider error is retried next time by design.
        vt_before = sum("virustotal.com" in u for u in calls)
        web.c.post("/analyze", data={"script_text": EXAMPLE})
        vt_after = sum("virustotal.com" in u for u in calls)
        R.check(section, "a second run takes VirusTotal answers from the cache", vt_after == vt_before,
                f"{vt_after - vt_before} new VirusTotal calls")
        pdf = web.c.get(f"/analysis/{analysis_id}/report/pdf").data
        text = "\n".join(pdf_texts(pdf))
        web.save("report-with-intel.pdf", pdf)
        R.check(section, "report lists each provider's answer", "VirusTotal" in text and "Trojan.QA" in text)
    finally:
        provider_base.requests.request, virustotal._limiter = original_request, original_limiter
    for provider in ("virustotal", "abuseipdb", "otx"):
        web.c.post("/settings", data={"form": "keys", "remove_key": provider})
    page = web.c.get("/settings").get_data(as_text=True)
    R.check(section, "fake keys removed again, and never echoed into the page",
            "qa-fake-key" not in page and 'name="remove_key"' not in page)


def settings_checks(web: Web) -> None:
    section = "settings"

    def post(**form):
        resp = web.c.post("/settings", data=form)
        return " ".join(flashes(web.c.get(resp.headers["Location"]).get_data(as_text=True)))

    msg = post(form="general", history_limit="0", analyst_name="QA", utc_offset="abc")
    R.check(section, "bad values rejected, nothing claimed saved",
            "must be" in msg and "saved" not in msg, msg)
    msg = post(form="general", history_limit="50", analyst_name="QA Analyst", utc_offset="7")
    R.check(section, "valid general settings saved", "General settings saved" in msg, msg)
    msg = post(form="keys")
    R.check(section, "saving no keys says so", "No keys entered" in msg, msg)
    msg = post(form="geoip", geoip_city_db=str(web.out / "missing.mmdb"), geoip_country_db="", geoip_asn_db="")
    R.check(section, "a GeoLite2 path with no database is reported", "No GeoLite2 City database" in msg, msg)
    post(form="geoip", geoip_city_db="", geoip_country_db="", geoip_asn_db="")
    section = "cyberchef"
    if cyberchef.manifest():
        resp = web.get("/cyberchef/", section, "offline CyberChef is served", own_page=False)
        csp = resp.headers.get("Content-Security-Policy", "")
        R.check(section, "its page cannot reach other hosts", "connect-src 'self'" in csp)
        web.get("/cyberchef/plaguards-cyberchef.json", section, "install manifest is not served", 404)
    else:
        R.add(section, "offline CyberChef not installed (python tools/fetch_cyberchef.py)", "INFO")


def history_checks(web: Web, ids: dict) -> None:
    section = "history"
    page = web.get(f"/history?selected={','.join(map(str, ids['batch']))}", section, "History with a batch").get_data(as_text=True)
    R.check(section, "a batch shows as one entry", "batch-row" in page)
    resp = web.c.post("/history/bulk-delete", data={"analysis_id": [str(ids["batch"][0])]})
    msg = " ".join(flashes(web.c.get(resp.headers["Location"]).get_data(as_text=True)))
    R.check(section, "delete one analysis", "Deleted 1 analysis." in msg, msg)
    resp = web.c.post("/history/bulk-export", data={"analysis_id": ["junk"]})
    R.check(section, "junk ids are refused politely", resp.status_code == 302)


def cli_checks(out: Path) -> None:
    section = "cli"
    runner = CliRunner()
    db = out / "cli.db"
    sample = out / "samples" / "example-analysis.ps1"
    json_out, pdf_out = out / "outputs" / "cli-example.json", out / "outputs" / "cli-example.pdf"
    with stopwatch() as t:
        res = runner.invoke(cli, ["analyze", str(sample), "--no-intel", "--json", str(json_out),
                                  "--pdf", str(pdf_out), "--db-path", str(db)])
    R.check(section, "analyze a file to JSON and PDF", res.exit_code == 0, res.output[-300:], t["s"])
    if json_out.exists():
        data = json.loads(json_out.read_text(encoding="utf-8"))
        R.check(section, "JSON carries findings and the file name only",
                data["filename"] == "example-analysis.ps1" and len(data["findings"]) > 20)
    R.check(section, "PDF written", pdf_out.exists() and pdf_out.stat().st_size > 10_000)
    res = runner.invoke(cli, ["analyze", "--no-intel", "--no-store"], input="Write-Host ('ht'+'tp://cli.example.invalid/x')")
    R.check(section, "analyze from stdin", res.exit_code == 0 and "cli.example.invalid" in res.output)
    res = runner.invoke(cli, ["list", "--db-path", str(db)])
    R.check(section, "list past analyses", res.exit_code == 0 and "example-analysis.ps1" in res.output)
    res = runner.invoke(cli, ["analyze", str(sample), "--no-intel", "--triage", "--db-path", str(db)],
                        input="t\n" * 60)
    R.check(section, "interactive triage", res.exit_code == 0)


def write_report(out: Path, started: datetime, elapsed: float) -> Path:
    rows = R.rows
    lines = [
        "# PlaguardsV2 QA report", "",
        f"- Run: {started:%Y-%m-%d %H:%M:%S}, "
        f"Python {platform.python_version()}, {platform.system()} {platform.release()}",
        f"- Duration: {elapsed:.1f}s, offline (network blocked in-process), throwaway database",
        f"- GeoLite2: {'configured' if any(PlagConfig.get_geoip_db_paths(None).values()) else 'not configured'}; "
        f"offline CyberChef: {'installed ' + cyberchef.manifest()['version'] if cyberchef.manifest() else 'not installed'}",
        f"- Result: **{R.count('PASS')} passed, {R.count('FAIL')} failed, {R.count('WARN')} warnings**",
        "",
    ]
    section = None
    for row in rows:
        if row["section"] != section:
            section = row["section"]
            lines += ["", f"## {section}", "", "| Check | Result | Time | Detail |", "|---|---|---|---|"]
        took = f"{row['seconds']:.2f}s" if row["seconds"] is not None else ""
        detail = (row["detail"] if row["status"] != "PASS" else "").replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {row['name']} | {row['status']} | {took} | {detail[:240]} |")
    artefacts = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file() and p.suffix != ".db")
    lines += ["", "## Files produced", ""] + [f"- `{a}`" for a in artefacts]
    path = out / "QA-REPORT.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="End-to-end QA for PlaguardsV2 (offline).")
    parser.add_argument("--out", help="output folder (default: qa-output/<timestamp>)")
    args = parser.parse_args()
    started = datetime.now()
    out = Path(args.out) if args.out else ROOT / "qa-output" / started.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    print(f"PlaguardsV2 QA -> {out}")
    t0 = time.perf_counter()

    samples = build_samples(out)
    engine_checks(samples)
    web = Web(out)
    ids = web_checks(web, samples)
    report_checks(web, ids)
    simulated_intel(web)
    settings_checks(web)
    history_checks(web, ids)
    cli_checks(out)

    report = write_report(out, started, time.perf_counter() - t0)
    print(f"\n{R.count('PASS')} passed, {R.count('FAIL')} failed, {R.count('WARN')} warnings")
    print(f"QA report: {report}")
    return 1 if R.count("FAIL") else 0


if __name__ == "__main__":
    raise SystemExit(main())
