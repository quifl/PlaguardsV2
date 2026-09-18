"""Plain-English explanations for the pass log, and how a missing one renders.

A pass-log entry with no matching explanation used to render the report's
"What this technique is" column as the literal text `&mdash;` rather than an
em dash - `PlagExplain.explain()` returning `""` fed into a Jinja `{{ }}`
expression containing the HTML entity `&mdash;`, which autoescaping turned
into `&amp;mdash;` and the browser then displayed as-is.
"""
from plaguardsv2.GuardModules import PlagExplain, PlagReport


def test_every_pass_type_used_in_this_session_has_an_explanation():
    for entry in (
        "Pass 1: folded JScript string method chain(s) (1 call(s))",
        "IOC check: 3 of 4 indicator(s) queried against the configured threat-intel providers",
        "Geolocation: 1 of 2 address(es) located",
    ):
        assert PlagExplain.explain(entry) != ""


def test_an_unrecognised_entry_falls_back_to_a_real_em_dash_not_the_html_entity():
    stored = {
        "original": "", "deobfuscated": "", "source_kind": "pasted",
        "findings": [], "pass_log": ["Some future transform with no explanation yet"],
    }
    ctx = PlagReport.build_report_context(stored)
    assert ctx["pass_log_display"][0]["why"] == ""

    html = PlagReport.render_html(stored)
    # The bug's signature: Jinja autoescaping turning the HTML entity into
    # `&amp;mdash;`, which a browser shows as the literal text `&mdash;`.
    assert "&amp;mdash;" not in html
    assert "<td>—</td>" in html
