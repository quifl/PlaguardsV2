from plaguardsv2.GuardModules import PlagGrep as ioc_extractor


def _values_of(findings, type_):
    return {f.value for f in findings if f.type == type_}


def test_extracts_ip_address():
    findings = ioc_extractor.scan("", "$server = '203.0.113.10'")
    assert "203.0.113.10" in _values_of(findings, "ip")


def test_extracts_domain_with_plausible_tld():
    findings = ioc_extractor.scan("", "$d = 'contoso-test.com'")
    assert "contoso-test.com" in _values_of(findings, "domain")


def test_rejects_dotnet_namespace_as_domain():
    findings = ioc_extractor.scan("", "[System.Management.Automation.Language.Parser]")
    assert _values_of(findings, "domain") == set()


def test_extracts_url():
    findings = ioc_extractor.scan("", "Invoke-WebRequest http://contoso-test.com/data.txt")
    assert any(v.startswith("http://contoso-test.com") for v in _values_of(findings, "url"))


def test_refangs_defanged_ip_and_url():
    findings = ioc_extractor.scan("", "198[.]51[.]100[.]77 and hxxp://contoso-test[.]com/x")
    ips = _values_of(findings, "ip")
    urls = _values_of(findings, "url")
    assert "198.51.100.77" in ips
    assert any(u.startswith("http://contoso-test.com") for u in urls)
    ip_finding = next(f for f in findings if f.type == "ip" and f.value == "198.51.100.77")
    assert ip_finding.defanged is True


def test_findings_are_deduplicated_across_original_and_deobfuscated():
    findings = ioc_extractor.scan("203.0.113.10", "203.0.113.10")
    ip_findings = [f for f in findings if f.type == "ip" and f.value == "203.0.113.10"]
    assert len(ip_findings) == 1


def test_empty_input_produces_no_findings():
    assert ioc_extractor.scan("", "") == []
