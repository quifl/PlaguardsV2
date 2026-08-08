from plaguardsv2.GuardModules import PlagGrep as ioc_extractor


def _signature_names(findings):
    return {f.value for f in findings if f.type == "signature"}


def test_env_var_slicing_signature_detected():
    findings = ioc_extractor.scan("", "$env:PUBLIC[13]+$env:PUBLIC[5]")
    assert "Environment-variable character-slicing" in _signature_names(findings)


def test_wildcard_cmdlet_resolution_signature_detected():
    findings = ioc_extractor.scan(
        "", '$ExecutionContext.InvokeCommand.GetCmdlets() | Where-Object {$_.Name -like "*v*k*"}'
    )
    assert "Dynamic cmdlet resolution via wildcard match" in _signature_names(findings)


def test_securestring_marshal_bridge_signature_detected():
    findings = ioc_extractor.scan(
        "", "[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($x)"
    )
    assert "SecureString/Marshal execution bridge" in _signature_names(findings)


def test_securestring_marshal_bridge_without_system_prefix():
    findings = ioc_extractor.scan(
        "", "[Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)"
    )
    assert "SecureString/Marshal execution bridge" in _signature_names(findings)
