from plaguardsv2.GuardModules import PlagGrep as ioc_extractor


def _signature_names(findings):
    return {f.value for f in findings if f.type == "signature"}


def test_iex_signature_detected_with_mitre_tag():
    findings = ioc_extractor.scan("", "IEX $decodedPayload")
    names = _signature_names(findings)
    assert "Invoke-Expression / IEX usage" in names
    finding = next(f for f in findings if f.value == "Invoke-Expression / IEX usage")
    assert "T1059.001" in finding.mitre


def test_download_cradle_signature_detected():
    findings = ioc_extractor.scan("", "(New-Object Net.WebClient).DownloadString($url)")
    assert "Remote download cradle" in _signature_names(findings)


def test_hidden_window_flag_signature_detected():
    findings = ioc_extractor.scan("", "-WindowStyle Hidden -NoProfile")
    assert "Hidden/bypass execution flags" in _signature_names(findings)


def test_scheduled_task_signature_detected():
    findings = ioc_extractor.scan("", "schtasks /create /tn demo /tr demo.exe")
    assert "Scheduled task persistence" in _signature_names(findings)


def test_no_signatures_on_benign_script():
    findings = ioc_extractor.scan("", "Get-ChildItem -Path C:\\Temp | Sort-Object Name")
    assert _signature_names(findings) == set()


def test_high_severity_findings_sorted_first():
    findings = ioc_extractor.scan(
        "",
        "IO.Compression.GzipStream\n(New-Object Net.WebClient).DownloadFile($url, $out)",
    )
    rank = {"high": 3, "medium": 2, "low": 1, "info": 0}
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, key=lambda s: rank[s], reverse=True)
