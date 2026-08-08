"""Threat-intel scoping and reporting.

Reserved / non-routable indicators used to be sent to every provider, which
came back as a wall of raw "HTTP 400" strings. They are now short-circuited
with an explanation instead.
"""
from plaguardsv2.GuardModules import PlagReport, PlagScope
from plaguardsv2.GuardModules.PlagProviders.base import explain_http


def test_reserved_ips_are_still_queried_but_flagged():
    """Providers do answer for reserved IP ranges, so suppressing the
    lookup would throw away real results. They get an advisory note
    alongside the provider verdicts instead."""
    assert PlagScope.skip_reason("ip", "198.51.100.42") is None
    assert PlagScope.skip_reason("ip", "192.168.1.5") is None

    assert "documentation" in PlagScope.advisory("ip", "198.51.100.42").lower()
    assert "private" in PlagScope.advisory("ip", "192.168.1.5")
    assert "loopback" in PlagScope.advisory("ip", "127.0.0.1")


def test_routable_ip_has_no_advisory():
    assert PlagScope.advisory("ip", "8.8.8.8") is None


def test_reserved_tld_is_not_queried():
    assert PlagScope.skip_reason("domain", "malicious.example.invalid")
    assert PlagScope.skip_reason("url", "http://bad.example.invalid/p.ps1")


def test_partial_hash_is_not_queried():
    assert PlagScope.skip_reason("hash_partial", "e3b0c442")


def test_routable_indicators_are_queried():
    assert PlagScope.skip_reason("ip", "8.8.8.8") is None
    assert PlagScope.skip_reason("domain", "example.com") is None


def test_http_errors_are_explained_not_raw():
    assert "rejected this value" in explain_http("OTX", 400)
    assert "API plan" in explain_http("Shodan", 403)
    assert "rate limit" in explain_http("VirusTotal", 429)
    assert "key rejected" in explain_http("AbuseIPDB", 401)


def test_intel_summary_picks_worst_verdict():
    summary = PlagReport._summarise_intel([
        {"label": "A", "verdict": "clean", "detail": ""},
        {"label": "B", "verdict": "malicious", "detail": ""},
        {"label": "C", "verdict": "unknown", "detail": ""},
    ])
    assert summary["verdict"] == "malicious"
    assert summary["text"] == "Malicious"


def test_intel_summary_reports_not_checked_when_empty():
    summary = PlagReport._summarise_intel([])
    assert summary["verdict"] == "not_checked"
    assert summary["text"] == "Not checked"


def test_intel_summary_surfaces_scope_reason():
    summary = PlagReport._summarise_intel([
        {"label": "Scope check", "verdict": "not_applicable", "detail": "reserved suffix"},
    ])
    assert summary["verdict"] == "not_applicable"
    assert summary["note"] == "reserved suffix"


def test_advisory_note_does_not_outrank_a_real_verdict():
    """The reserved-range note is context, not a verdict - a provider
    result must still drive the headline."""
    summary = PlagReport._summarise_intel([
        {"label": "Scope check", "verdict": "info", "detail": "documentation range"},
        {"label": "VirusTotal", "verdict": "clean", "detail": "0 malicious"},
    ])
    assert summary["verdict"] == "clean"
    assert "VirusTotal" in summary["note"]


def test_code_lines_are_hard_wrapped():
    """xhtml2pdf won't break a long unbroken token, so wrapping happens in
    Python to guarantee the appendix fits the page."""
    long_line = "A" * 500
    rows = PlagReport._numbered_lines(long_line)
    assert len(rows) > 1
    assert all(len(r["text"]) <= PlagReport.CODE_WRAP_COLUMNS for r in rows)
    assert rows[0]["n"] == 1 and rows[1]["n"] == ""


def test_provider_links_point_at_the_right_detail_page():
    """A result row links to the provider's own page for the indicator."""
    from plaguardsv2.GuardModules import PlagLinks

    assert PlagLinks.reference_url("virustotal", "ip", "198.51.100.42") == \
        "https://www.virustotal.com/gui/ip-address/198.51.100.42"
    assert PlagLinks.reference_url("virustotal", "domain", "malicious.example.invalid") == \
        "https://www.virustotal.com/gui/domain/malicious.example.invalid"
    assert PlagLinks.reference_url("abuseipdb", "ip", "198.51.100.42") == \
        "https://www.abuseipdb.com/check/198.51.100.42"
    assert PlagLinks.reference_url("shodan", "ip", "198.51.100.42") == \
        "https://www.shodan.io/host/198.51.100.42"
    assert PlagLinks.reference_url("greynoise", "ip", "198.51.100.42") == \
        "https://viz.greynoise.io/ip/198.51.100.42"
    assert PlagLinks.reference_url("otx", "hash", "e3b0c442") == \
        "https://otx.alienvault.com/indicator/file/e3b0c442"


def test_provider_links_strip_a_port_and_encode_the_value():
    from plaguardsv2.GuardModules import PlagLinks

    # Providers index the host, not host:port.
    assert PlagLinks.reference_url("shodan", "ip_port", "198.51.100.42:4444") == \
        "https://www.shodan.io/host/198.51.100.42"
    # A URL goes in encoded, so following the link can never fetch the target.
    url = PlagLinks.reference_url("virustotal", "url", "http://bad.example.invalid/a?b=1")
    assert "://bad.example.invalid" not in url
    assert url.startswith("https://www.virustotal.com/gui/search/")


def test_no_link_where_a_provider_has_no_page_for_that_type():
    """An IP-only provider gets no link for a domain, rather than one that
    lands on a 'not found' page."""
    from plaguardsv2.GuardModules import PlagLinks

    assert PlagLinks.reference_url("shodan", "domain", "example.invalid") is None
    assert PlagLinks.reference_url("greynoise", "hash", "e3b0c442") is None
    assert PlagLinks.reference_url("virustotal", "mutex", r"Global\ABAD-IDEA-123") is None
    assert PlagLinks.reference_url("virustotal", "ip", "") is None
