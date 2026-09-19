"""Indicator classes added to PlagGrep: IPv6, cryptocurrency wallets,
Windows/UNC paths, named persistence artefacts and residual Base64 - plus the
backtracking safety of every pattern in the module.

The defect class these guard is *false* indicators. A missed IOC costs an
analyst a lookup; an invented one ends up in a shared report and sends a
team hunting an artefact that was never there. So each type carries at
least one negative case built from the shapes that genuinely collide with
it - PowerShell's `::` static-member syntax, a batch file's `::` comment,
a SHA-1 digest, a `-replace '\\\\','/'` argument, an unresolved `$taskName`.

The other defect class is denial of service: every pattern here runs over
attacker-supplied text, so `test_patterns_do_not_backtrack_catastrophically`
holds the whole module to a linear-time budget.

Addresses follow RFC 3849 (2001:db8::/32), RFC 5737 (198.51.100.0/24,
203.0.113.0/24) and RFC 2606 (.invalid). The wallet addresses are
synthesised from a fixed seed and carry real checksums, so they exercise
validation without naming anyone's actual wallet.
"""
import base64
import time

from plaguardsv2.GuardModules import PlagGrep as ioc_extractor

# Synthesised from the seed "plaguards-doc-wallet"; checksums are genuine.
BTC_P2PKH = "14h9PhGLagKS2feU6XfZNNwSPK6EXzzCnt"
BTC_P2SH = "35PAKEkn8adp7qLuDdL9o1JNXqNx8tJ17K"
BTC_BECH32 = "bc1q9zqq2sp2xqjq33az07g9r2tmkghd3hqww3myxt"
BTC_TAPROOT = "bc1pe3fytk8aqw8gdnv4lxyneuq0pckp4zqu68cr9np4pjx9ka5lw6wszfr0qv"
ETH_ADDRESS = "0x52908400098527886E0F7030069857D2E4169EE7"
XMR_ADDRESS = ("4Aa81GfzLww77HXjac9kvav5Bu49CNF3jma81GfzLww77HXjac9kvav5"
               "Bu49CNF3jma81GfzLww77HXjac9kvav5Bu49CNF")
SHA1_DIGEST = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def _values_of(findings, type_):
    return {f.value for f in findings if f.type == type_}


def _one(findings, type_, value):
    return next(f for f in findings if f.type == type_ and f.value == value)


# --- C1: IPv6 -------------------------------------------------------------

def test_extracts_full_and_compressed_ipv6():
    script = ("$a = '2001:0db8:0000:0000:0000:0000:0000:0001'\n"
              "$b = '2001:db8::1'\n"
              "$c = 'fe80::1'\n"
              "Write-Host 'done'\n")
    ips = _values_of(ioc_extractor.scan("", script), "ip")
    assert "2001:0db8:0000:0000:0000:0000:0000:0001" in ips
    assert "2001:db8::1" in ips
    assert "fe80::1" in ips


def test_extracts_ipv4_mapped_ipv6():
    ips = _values_of(ioc_extractor.scan("", "$m = '::ffff:198.51.100.24'"), "ip")
    assert "::ffff:198.51.100.24" in ips


def test_extracts_bracketed_ipv6_endpoint_and_its_bare_address():
    findings = ioc_extractor.scan("", "$c2 = '[2001:db8:85a3::8a2e:370:7334]:8443'")
    assert "[2001:db8:85a3::8a2e:370:7334]:8443" in _values_of(findings, "ipv6_port")
    # The bare address is added alongside so geolocation has something it can
    # resolve - PlagGeo strips a port with rsplit(":"), which a bracketed
    # address would turn into garbage.
    assert "2001:db8:85a3::8a2e:370:7334" in _values_of(findings, "ip")


def test_ipv6_type_is_ip_so_it_reaches_geolocation():
    from plaguardsv2.GuardModules import PlagGeo

    findings = ioc_extractor.scan("", "$a = '2001:db8::dead'")
    assert PlagGeo.category("2001:db8::dead") == "documentation"
    assert PlagGeo.enrich(findings)["2001:db8::dead"]["category"] == "documentation"


def test_ipv6_does_not_fire_on_powershell_static_member_syntax():
    script = ("$d = [System.Convert]::FromBase64String($x)\n"
              "$e = [Math]::Abs(-1)\n"
              "$f = [Convert]::ToBase64String($y)\n"
              "Write-Host 'done'\n")
    assert _values_of(ioc_extractor.scan("", script), "ip") == set()


def test_ipv6_does_not_fire_on_batch_comment_marker():
    # `::` opens a comment in a batch file and parses as the IPv6
    # unspecified address; `::add` is a word, not a hextet.
    script = ":: download the stage\n:: add the task\necho done\n"
    assert _values_of(ioc_extractor.scan(script, script), "ip") == set()


def test_ipv6_does_not_fire_on_clocks_or_mac_addresses():
    script = "$t = '12:34:56'\n$mac = '00:1A:2B:3C:4D:5E'\nWrite-Host 'done'\n"
    assert _values_of(ioc_extractor.scan("", script), "ip") == set()


# --- C2: cryptocurrency wallets ------------------------------------------

def test_extracts_bitcoin_addresses_in_all_three_forms():
    script = (f"$a = '{BTC_P2PKH}'\n$b = '{BTC_P2SH}'\n"
              f"$c = '{BTC_BECH32}'\n$d = '{BTC_TAPROOT}'\nWrite-Host 'done'\n")
    wallets = _values_of(ioc_extractor.scan("", script), "crypto_wallet")
    assert {BTC_P2PKH, BTC_P2SH, BTC_BECH32, BTC_TAPROOT} <= wallets


def test_extracts_ethereum_and_monero_addresses():
    script = f"$e = '{ETH_ADDRESS}'\n$m = '{XMR_ADDRESS}'\nWrite-Host 'done'\n"
    wallets = _values_of(ioc_extractor.scan("", script), "crypto_wallet")
    assert ETH_ADDRESS in wallets
    assert XMR_ADDRESS in wallets


def test_wallet_finding_is_high_severity_and_tagged():
    finding = _one(ioc_extractor.scan("", f"$a='{BTC_P2PKH}'"), "crypto_wallet", BTC_P2PKH)
    assert finding.severity == "high"
    assert "T1657" in finding.mitre


def test_bitcoin_address_with_a_broken_checksum_is_rejected():
    # Last character changed: right shape, wrong base58check digest.
    broken = BTC_P2PKH[:-1] + ("u" if BTC_P2PKH[-1] != "u" else "v")
    assert _values_of(ioc_extractor.scan("", f"$a = '{broken}'"), "crypto_wallet") == set()


def test_bech32_address_with_a_broken_checksum_is_rejected():
    broken = BTC_BECH32[:-1] + ("q" if BTC_BECH32[-1] != "q" else "p")
    assert _values_of(ioc_extractor.scan("", f"$a = '{broken}'"), "crypto_wallet") == set()


def test_ethereum_detection_does_not_cannibalise_hash_extraction():
    script = f"$h = '{SHA1_DIGEST}'\n$w = '{ETH_ADDRESS}'\nWrite-Host 'done'\n"
    findings = ioc_extractor.scan("", script)
    assert SHA1_DIGEST in _values_of(findings, "hash_sha1")
    assert SHA1_DIGEST not in _values_of(findings, "crypto_wallet")
    assert ETH_ADDRESS in _values_of(findings, "crypto_wallet")
    # A bare 40-hex run stays a hash; only the 0x-prefixed form is a wallet.
    assert not any(f.type.startswith("hash") and f.value.startswith("0x") for f in findings)


def test_wallet_does_not_fire_on_ordinary_identifiers():
    script = ("$id = '3TheQuickBrownFoxJumpsOverLazyDg'\n"
              "$tag = '1SomeVeryLongCamelCaseIdentifierName'\n"
              "Write-Host 'done'\n")
    assert _values_of(ioc_extractor.scan("", script), "crypto_wallet") == set()


# --- C3: Windows and UNC paths -------------------------------------------

def test_extracts_local_windows_paths():
    script = ("$drop = 'C:\\Users\\Public\\Documents\\stage.dat'\n"
              "$roam = '%APPDATA%\\Microsoft\\Windows\\upd.lnk'\n"
              "$tmp = $env:TEMP\\loader.ps1\n"
              "Write-Host 'done'\n")
    paths = _values_of(ioc_extractor.scan("", script), "file_path")
    assert "C:\\Users\\Public\\Documents\\stage.dat" in paths
    assert "%APPDATA%\\Microsoft\\Windows\\upd.lnk" in paths
    assert "$env:TEMP\\loader.ps1" in paths


def test_quoted_path_keeps_its_spaces():
    script = "Copy-Item 'C:\\Program Files\\Common Files\\svc host.exe' $d\nWrite-Host 'done'\n"
    paths = _values_of(ioc_extractor.scan("", script), "file_path")
    assert "C:\\Program Files\\Common Files\\svc host.exe" in paths


def test_extracts_unc_path_with_lateral_movement_tag():
    script = "$share = '\\\\fileserver01\\finance$\\export\\dump.zip'\nWrite-Host 'done'\n"
    findings = ioc_extractor.scan("", script)
    value = "\\\\fileserver01\\finance$\\export\\dump.zip"
    assert value in _values_of(findings, "unc_path")
    assert "T1021.002" in _one(findings, "unc_path", value).mitre


def test_paths_do_not_fire_on_escapes_registry_keys_or_mutexes():
    script = ("$r = $text -replace '\\\\','/'\n"
              "Set-ItemProperty 'HKLM:\\SOFTWARE\\Contoso\\Run' -Name x -Value y\n"
              "$m = 'Global\\ABAD-IDEA-123'\n"
              "$s = 'a\\b\\c'\n"
              "Write-Host 'done'\n")
    findings = ioc_extractor.scan("", script)
    assert _values_of(findings, "file_path") == set()
    assert _values_of(findings, "unc_path") == set()


def test_path_prefix_is_collapsed_into_the_longer_path():
    script = ("$dir = 'C:\\Users\\Public'\n"
              "$file = 'C:\\Users\\Public\\stage.dat'\n"
              "Write-Host 'done'\n")
    paths = _values_of(ioc_extractor.scan("", script), "file_path")
    assert "C:\\Users\\Public\\stage.dat" in paths
    assert "C:\\Users\\Public" not in paths


# --- C4: named persistence artefacts -------------------------------------

def test_extracts_scheduled_task_names():
    script = ("schtasks /create /tn \"UpdaterSvcTask\" /tr calc /sc minute\n"
              "Register-ScheduledTask -TaskName 'OneDriveSyncHelper' -Action $a\n"
              "Write-Host 'done'\n")
    names = _values_of(ioc_extractor.scan("", script), "scheduled_task")
    assert {"UpdaterSvcTask", "OneDriveSyncHelper"} <= names


def test_extracts_service_names():
    script = ("New-Service -BinaryPathName $p -Name \"WinTelemetrySvc\" -DisplayName z\n"
              "sc.exe create HostSyncSvc binPath= C:\\Windows\\Temp\\h.exe\n"
              "Write-Host 'done'\n")
    names = _values_of(ioc_extractor.scan("", script), "service_name")
    assert {"WinTelemetrySvc", "HostSyncSvc"} <= names


def test_named_artefacts_carry_their_technique_ids():
    findings = ioc_extractor.scan("", "schtasks /create /tn 'T1' /tr calc\nNew-Service -Name 'S1'")
    assert "T1053.005" in _one(findings, "scheduled_task", "T1").mitre
    assert "T1543.003" in _one(findings, "service_name", "S1").mitre


def test_unresolved_artefact_name_is_not_reported():
    # The name is still an expression. Reporting `$taskName` would invent an
    # artefact for the analyst to hunt; UNKNOWN is the honest answer.
    script = ("schtasks /create /tn $taskName /tr calc\n"
              "Register-ScheduledTask -TaskName $($n) -Action $a\n"
              "New-Service -Name $svc\n"
              "Write-Host 'done'\n")
    findings = ioc_extractor.scan("", script)
    assert _values_of(findings, "scheduled_task") == set()
    assert _values_of(findings, "service_name") == set()


def test_service_name_does_not_fire_on_unrelated_name_parameters():
    script = "Get-Process -Name explorer\nGet-ChildItem -Name\nWrite-Host 'done'\n"
    assert _values_of(ioc_extractor.scan("", script), "service_name") == set()


def test_cmdlet_task_registration_is_its_own_signature():
    # persistence.py keys on `schtasks`/`New-ScheduledTask`, neither of which
    # appears in `Register-ScheduledTask`.
    findings = ioc_extractor.scan("", "Register-ScheduledTask -TaskName 'X' -Action $a")
    assert "Scheduled task registration via cmdlet" in _values_of(findings, "signature")


# --- C5: residual Base64 --------------------------------------------------

def test_undecodable_base64_blob_is_reported_as_informational():
    blob = base64.b64encode(bytes(range(256))).decode()
    findings = ioc_extractor.scan("orig", f"$p = '{blob}'\nWrite-Host 'done'\n")
    blobs = [f for f in findings if f.type == "base64_blob"]
    assert len(blobs) == 1
    assert blobs[0].severity == "info"
    assert "could not be decoded statically" in blobs[0].description
    assert set(blobs[0].mitre) == {"T1027.010", "T1140"}


def test_base64_that_was_decoded_in_this_run_is_not_reported():
    plain = "Write-Host 'hello from the second stage of this inert sample'"
    blob = base64.b64encode(plain.encode("utf-16-le")).decode()
    # The deobfuscated text carries the plaintext, which is what "decoded
    # elsewhere in the same run" looks like from PlagGrep's side.
    findings = ioc_extractor.scan(f"-enc {blob}", f"# was: {blob}\n{plain}\n")
    assert _values_of(findings, "base64_blob") == set()


def test_base64_blob_does_not_fire_on_short_tokens_hashes_or_url_paths():
    long_path = "a" * 80
    script = ("$t = 'U2hvcnRUb2tlbg=='\n"
              "$h = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'\n"
              f"$u = 'https://cdn.example.invalid/assets/{long_path}.js'\n"
              "Write-Host 'done'\n")
    assert _values_of(ioc_extractor.scan("", script), "base64_blob") == set()


def test_monero_address_is_not_double_reported_as_a_base64_blob():
    findings = ioc_extractor.scan("", f"$w = '{XMR_ADDRESS}'\nWrite-Host 'done'\n")
    assert XMR_ADDRESS in _values_of(findings, "crypto_wallet")
    assert _values_of(findings, "base64_blob") == set()


# --- defanging ------------------------------------------------------------

def test_new_types_survive_the_defanging_path():
    # Colon-separated indicators need `[:]`, not the dot bracketing used for
    # v4 and domains, and everything must refang back to the original.
    for value, ioc_type in (("2001:db8::1", "ip"),
                            ("[2001:db8::1]:8443", "ipv6_port")):
        defanged = ioc_extractor.defang(value, ioc_type)
        assert defanged != value
        assert ioc_extractor.refang(defanged) == value


def test_non_network_new_types_are_not_mangled_by_defang():
    for value, ioc_type in ((BTC_P2PKH, "crypto_wallet"),
                            ("C:\\Users\\Public\\stage.dat", "file_path"),
                            ("\\\\host01\\share\\x.zip", "unc_path"),
                            ("UpdaterSvcTask", "scheduled_task")):
        assert ioc_extractor.defang(value, ioc_type) == value


def test_defang_text_neutralises_ipv6_inside_free_text():
    out = ioc_extractor.defang_text("C2=[2001:db8::1]:8443 alt=2001:db8::99")
    assert "2001:db8::1" not in out
    assert "2001:db8::99" not in out
    assert "2001[:]db8[:][:]99" in out


def test_defanged_ipv6_in_the_source_is_refanged_and_flagged():
    findings = ioc_extractor.scan("", "$c = '2001[:]db8[:][:]1'\nWrite-Host 'done'\n")
    assert "2001:db8::1" in _values_of(findings, "ip")
    assert _one(findings, "ip", "2001:db8::1").defanged is True


def test_ipv4_port_defang_is_unchanged_by_the_ipv6_branch():
    assert ioc_extractor.defang("198.51.100.24:4444", "ip_port") == "198[.]51[.]100[.]24:4444"
    assert ioc_extractor.defang("http://a.example.invalid:8080/x", "url") == \
        "hxxp://a[.]example[.]invalid:8080/x"


# --- C6: backtracking safety ---------------------------------------------

def test_patterns_do_not_backtrack_catastrophically():
    """Each pattern against the input shaped to make it backtrack.

    The bound is deliberately loose (250ms for 40k characters): it is there
    to catch a pattern that has gone exponential or quadratic, not to police
    ordinary speed. `_DOMAIN_RE` and `_EMAIL_RE` both failed this before
    their label repetitions were bounded - 8s and 1.4s respectively.
    """
    size = 20_000
    cases = [
        ("_DOMAIN_RE", "a." * size + "!"),
        ("_EMAIL_RE", "a@" + "b." * size + "!"),
        ("_IPV6_CANDIDATE_RE", "ab:" * size),
        ("_IPV6_CANDIDATE_RE", "::" + "a" * size),
        ("_IPV6_PORT_RE", "[" + "a:" * size + "]"),
        ("_BTC_BASE58_RE", "1" + "z" * size),
        ("_BTC_BECH32_RE", "bc1" + "q" * size),
        ("_ETH_RE", "0x" + "a" * size),
        ("_XMR_RE", "4A" + "z" * size),
        ("_WINDOWS_PATH_RE", "C:\\" + "a\\" * size),
        ("_WINDOWS_PATH_RE", "C:\\" + "a" * size),
        ("_QUOTED_PATH_RE", "'C:\\" + "a" * size),
        ("_SCHEDULED_TASK_RE", "/tn " + "a" * size),
        ("_SERVICE_NAME_RE", "New-Service " + "a" * size),
        ("_B64_BLOB_RE", "aB1+/" * size),
        ("_USER_AGENT_RE", "Mozilla/5.0 " + "a" * size),
        ("_URL_RE", "http://" + "a" * size),
        ("_REGISTRY_RE", "HKLM\\" + "a" * size),
        ("_IP_PORT_RE", "203.0.113.9:" * (size // 4)),
    ]
    slow = []
    for name, text in cases:
        pattern = getattr(ioc_extractor, name)
        start = time.perf_counter()
        pattern.findall(text)
        elapsed = time.perf_counter() - start
        if elapsed > 0.25:
            slow.append(f"{name} took {elapsed*1000:.0f}ms on {len(text)} chars")
    assert not slow, "; ".join(slow)


def test_scan_stays_linear_on_a_pathological_document():
    """A whole scan() over indicator-dense text, including the span
    bookkeeping - the overlap checks were quadratic in match count before
    they were moved onto a bisect-backed span set."""
    unit = ("Copy-Item 'C:\\Users\\Public\\a.dat' 'C:\\Users\\Public\\b.dat'\n"
            "schtasks /create /tn T /tr calc\n"
            "$x = '203.0.113.9:4444' ; $y = '2001:db8::1'\n")
    small, large = unit * 100, unit * 400

    def timed(text):
        start = time.perf_counter()
        ioc_extractor.scan("", text)
        return time.perf_counter() - start

    timed(small)  # warm the pattern cache so the ratio is not skewed
    ratio = timed(large) / max(timed(small), 1e-4)
    assert ratio < 10, f"4x the input took {ratio:.1f}x the time - superlinear"


def test_empty_input_still_produces_no_findings():
    assert ioc_extractor.scan("", "") == []
