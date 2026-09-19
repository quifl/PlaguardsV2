"""Threat-intel completeness and geolocation in the generated report.

Two gaps in what the PDF told an analyst: a provider with no API key
configured simply vanished from a finding's detail instead of being listed
as unchecked, and geolocation - already computed for the CSV/XLSX export -
never made it into the report at all.
"""
from plaguardsv2.GuardModules import PlagGeo, PlagReport


def test_unchecked_providers_are_listed_not_hidden():
    """A provider with no key still supports the indicator type, so it
    belongs in the list - as 'not checked', not omitted entirely."""
    finding = {
        "type": "ip", "value": "198.51.100.42", "severity": "info",
        "intel": {
            "virustotal": {"verdict": "clean", "detail": "0 malicious"},
            "shodan": {"verdict": "not_checked", "detail": "No API key configured"},
        },
    }
    d = PlagReport._as_dict(finding, 1)
    labels = [r["label"] for r in d["intel_display"]]
    assert "VirusTotal" in labels
    assert "Shodan" in labels


def test_checked_providers_sort_before_unchecked_ones():
    finding = {
        "type": "ip", "value": "198.51.100.42", "severity": "info",
        "intel": {
            "abuseipdb": {"verdict": "not_checked", "detail": "No API key configured"},
            "virustotal": {"verdict": "clean", "detail": "0 malicious"},
        },
    }
    d = PlagReport._as_dict(finding, 1)
    verdicts = [r["verdict"] for r in d["intel_display"]]
    assert verdicts.index("clean") < verdicts.index("not_checked")


def test_summary_headline_ignores_unchecked_providers():
    """An indicator with one real answer and several unconfigured providers
    should read as that one answer, not get diluted by 'not_checked' noise
    in the denominator, and an indicator with only unconfigured providers
    should still read plainly as 'not checked' rather than 'unknown'."""
    finding = {
        "type": "ip", "value": "198.51.100.42", "severity": "info",
        "intel": {
            "virustotal": {"verdict": "malicious", "detail": "12 malicious"},
            "shodan": {"verdict": "not_checked", "detail": "No API key configured"},
            "greynoise": {"verdict": "not_checked", "detail": "No API key configured"},
        },
    }
    d = PlagReport._as_dict(finding, 1)
    assert d["intel_summary"]["verdict"] == "malicious"
    assert "1 of 1 sources" in d["intel_summary"]["note"]

    unconfigured = {
        "type": "ip", "value": "198.51.100.42", "severity": "info",
        "intel": {
            "shodan": {"verdict": "not_checked", "detail": "No API key configured"},
        },
    }
    d2 = PlagReport._as_dict(unconfigured, 1)
    assert d2["intel_summary"]["verdict"] == "not_checked"


def test_build_report_context_attaches_geo_rows_to_ip_findings(monkeypatch):
    monkeypatch.setattr(PlagGeo, "locate", lambda value, conn: {
        "city": "Jakarta", "country": "Indonesia", "note": "",
    })
    stored = {
        "original": "", "deobfuscated": "", "source_kind": "pasted", "pass_log": [],
        "findings": [
            {"type": "ip", "value": "198.51.100.42", "severity": "info",
             "context": "", "mitre": [], "description": ""},
            {"type": "domain", "value": "example.invalid", "severity": "info",
             "context": "", "mitre": [], "description": ""},
        ],
    }
    ctx = PlagReport.build_report_context(stored)
    findings = {f["value"]: f for f in ctx["analysis"]["findings"]}
    assert findings["198.51.100.42"]["geo_rows"]
    assert findings["example.invalid"]["geo_rows"] == []


def test_report_html_includes_the_geolocation_section(monkeypatch):
    monkeypatch.setattr(PlagGeo, "locate", lambda value, conn: {
        "city": "Jakarta", "country": "Indonesia", "note": "",
    })
    stored = {
        "original": "", "deobfuscated": "", "source_kind": "pasted", "pass_log": [],
        "findings": [
            {"type": "ip", "value": "198.51.100.42", "severity": "info",
             "context": "", "mitre": [], "description": ""},
        ],
    }
    html = PlagReport.render_html(stored)
    assert "Geolocation" in html
    assert "Jakarta" in html


# The extractor and the report are owned by different modules, so a new
# indicator type can be added in PlagGrep and reach an analyst-facing report
# with no label at all. It does not crash - _as_dict falls back to
# type.replace("_", " ").title() - which is exactly why it goes unnoticed:
# the report just prints "Ipv6 Port" and "Unc Path" at the reader.
_MIXED_SAMPLE = "\n".join([
    'Write-Host "2001:db8::1 and [2001:db8::2]:443"',
    'Write-Host "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"',
    r'Write-Host "C:\Users\Public\stage.ps1"',
    'Write-Host "' + chr(92) * 2 + r'host.example.invalid\share\x.dll"',
    "schtasks /create /tn UpdaterTask /tr calc.exe",
    r"New-Service -Name EvilSvc -BinaryPathName C:\x.exe",
    'Write-Host "malicious.example.invalid"',
    'Write-Host "198.51.100.24"',
])


def test_every_extractable_type_has_a_report_label():
    from plaguardsv2.GuardModules import PlagGrep

    produced = {f.type for f in PlagGrep.scan("", _MIXED_SAMPLE, "")}
    assert produced, "sample produced no findings - it has stopped exercising anything"
    unlabelled = sorted(t for t in produced if t not in PlagReport.TYPE_LABEL)
    assert not unlabelled, (
        "these types reach the report with an auto-generated label: "
        f"{unlabelled} - add them to PlagReport.TYPE_LABEL"
    )
