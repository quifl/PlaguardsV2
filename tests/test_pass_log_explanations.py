"""Plain-English explanations for the pass log, and how a missing one renders.

A pass-log entry with no matching explanation used to render the report's
"What this technique is" column as the literal text `&mdash;` rather than an
em dash - `PlagExplain.explain()` returning `""` fed into a Jinja `{{ }}`
expression containing the HTML entity `&mdash;`, which autoescaping turned
into `&amp;mdash;` and the browser then displayed as-is.
"""
import re
from pathlib import Path

from plaguardsv2.GuardModules import PlagDeobfus, PlagExplain, PlagReport


def test_every_transform_the_engine_can_emit_has_an_explanation():
    """The report pairs each transform with what the technique is, and a
    label with no entry renders that column empty.

    Checked against the pipeline itself rather than a hand-written list: two
    passes were added without explanations and shipped that way, because
    nothing failed when the column came out blank.
    """
    source = Path(PlagDeobfus.__file__).read_text(encoding="utf-8")
    labels = re.findall(
        r'\(\s*"([^"]{10,120})",\s*(?:_[a-z_]+|Plag[A-Za-z]+\.[a-z_]+)\s*\)', source
    )
    assert len(labels) > 20, "pipeline labels not found - has the pass list moved?"

    missing = sorted({lab for lab in labels if not PlagExplain.explain(lab)})
    assert not missing, "transforms with no report explanation: " + "; ".join(missing)


def test_every_pass_type_used_in_this_session_has_an_explanation():
    for entry in (
        "Pass 1: folded JScript string method chain(s) (1 call(s))",
        "IOC check: 3 of 4 indicator(s) queried against the configured threat-intel providers",
        "Geolocation: 1 of 2 address(es) located",
    ):
        assert PlagExplain.explain(entry) != ""


def test_an_unrecognised_entry_falls_back_to_a_real_em_dash_not_the_html_entity():
    # Must use the real "Pass N: ..." shape; the report renders anything
    # else under Analysis notes, not as a transform.
    stored = {
        "original": "", "deobfuscated": "", "source_kind": "pasted",
        "findings": [],
        "pass_log": ["Pass 1: some future transform with no explanation yet"],
    }
    ctx = PlagReport.build_report_context(stored)
    assert ctx["pass_log_display"][0]["why"] == ""

    html = PlagReport.render_html(stored)
    # The bug's signature: Jinja autoescaping turning the HTML entity into
    # `&amp;mdash;`, which a browser shows as the literal text `&mdash;`.
    assert "&amp;mdash;" not in html
    assert "<td>—</td>" in html
