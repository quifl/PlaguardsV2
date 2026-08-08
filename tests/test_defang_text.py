"""Free-text defanging (used for resolved variable values) and the
substring dedupe that removes partially-folded indicator fragments."""
from plaguardsv2.GuardModules import PlagEngine, PlagGrep, PlagReport, PlagStore


def test_defangs_indicators_inside_a_sentence():
    text = "C2=malicious.example.invalid | IP=198.51.100.42:4444"
    out = PlagGrep.defang_text(text)
    assert "malicious[.]example[.]invalid" in out
    assert "198[.]51[.]100[.]42:4444" in out
    assert "malicious.example.invalid" not in out


def test_defangs_url_scheme_in_text():
    out = PlagGrep.defang_text("fetch http://bad.example.invalid/p.ps1 now")
    assert "hxxp://bad[.]example[.]invalid/p[.]ps1" in out


def test_leaves_ordinary_prose_untouched():
    text = "e.g. nothing to defang here, just words."
    assert PlagGrep.defang_text(text) == text


def test_non_network_values_are_not_mangled():
    text = "MUTEX=Global\\ABAD-IDEA-123 UA=EVILBOT/1.0"
    assert PlagGrep.defang_text(text) == text


def test_partial_user_agent_fragment_is_suppressed():
    # "EVIL"+"BOT/1.0" leaves a stray BOT/1.0 next to the folded full UA.
    findings = PlagGrep.scan(
        "", 'x = "Mozilla/5.0 (Windows NT 10.0) EVILBOT/1.0"', "BOT/1.0"
    )
    uas = {f.value for f in findings if f.type == "user_agent"}
    assert "BOT/1.0" not in uas
    assert any("EVILBOT/1.0" in u for u in uas)


def test_user_agent_does_not_swallow_following_fields():
    text = "UA=Mozilla/5.0 (Windows NT 10.0) EVILBOT/1.0 MUTEX=Global\\ABAD-IDEA-123 PORT=4444"
    findings = PlagGrep.scan("", text)
    uas = [f.value for f in findings if f.type == "user_agent"]
    assert uas == ["Mozilla/5.0 (Windows NT 10.0) EVILBOT/1.0"]


def test_report_resolved_variables_are_defanged():
    src = '$d="example.invalid"\n$d="malicious."+$d\n'
    conn = PlagStore.get_conn(":memory:")
    result = PlagEngine.run_analysis(src, skip_intel=True, conn=conn)
    stored = PlagStore.get_analysis(conn, result["id"])

    ctx = PlagReport.build_report_context(stored)
    values = {row["name"]: row["value"] for row in ctx["resolved_display"]}
    assert values["d"] == "malicious[.]example[.]invalid"


def test_report_cover_has_no_creator_credit():
    conn = PlagStore.get_conn(":memory:")
    result = PlagEngine.run_analysis("Write-Host 'hi'\n", skip_intel=True, conn=conn)
    stored = PlagStore.get_analysis(conn, result["id"])
    html = PlagReport.render_html(stored)
    assert "Created by quifl" not in html
