"""Renders an Analysis into a detailed, shareable PDF via a Jinja2 HTML
template and xhtml2pdf (pure-Python, no native/system dependencies - works
the same on Windows, Linux, and inside Docker)."""
from __future__ import annotations

import base64
import hashlib
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
import pypdf
from xhtml2pdf import pisa

from . import (PlagCharts, PlagConfig, PlagEncode, PlagExplain, PlagGeo, PlagGrep,
               PlagMitre, PlagWatermark)

TEMPLATE_DIR = Path(__file__).parent / "report_templates"
LOGO_PATH = Path(__file__).parent.parent / "PlagWeb" / "static" / "assets" / "plaguard-logo.png"

# Shown on the report cover and in page footers.
TAGLINE = "PlaguardsV2 · PowerShell deobfuscation & IOC triage for blue teams"

SEVERITY_ORDER = ["high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "high": "High", "medium": "Medium", "low": "Low", "info": "Info",
}

TYPE_LABEL = {
    "ip": "IP address",
    "ip_port": "IP:port",
    "domain": "Domain",
    "url": "URL",
    "email": "Email",
    "hash_md5": "MD5 hash",
    "hash_sha1": "SHA-1 hash",
    "hash_sha256": "SHA-256 hash",
    "hash_partial": "Partial hash",
    "user_agent": "User-Agent",
    "registry_key": "Registry key",
    "mutex": "Mutex",
    "signature": "Signature",
}

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)

_PROVIDER_LABELS = {p["id"]: p["label"] for p in PlagConfig.PROVIDERS}
_logo_data_uri_cache: str | None = None


def _logo_data_uri() -> str | None:
    global _logo_data_uri_cache
    if _logo_data_uri_cache is None and LOGO_PATH.exists():
        encoded = base64.b64encode(LOGO_PATH.read_bytes()).decode()
        _logo_data_uri_cache = f"data:image/png;base64,{encoded}"
    return _logo_data_uri_cache


VALUE_WRAP_COLUMNS = 30
# The wide value column of a detail table, in 7.6pt Courier.
CONTEXT_WRAP_COLUMNS = 88
# The resolved-variables table gives its value column about two thirds.
RESOLVED_WRAP_COLUMNS = 74
_VALUE_BREAK_AFTER = "/].-_:?&=,;"


def _wrap_value(value: str, width: int = VALUE_WRAP_COLUMNS) -> list[str]:
    """Break a long indicator into cell-sized chunks.

    xhtml2pdf will not split an unbroken token, so a long defanged URL runs
    straight past its cell border no matter what the column width says. The
    caller joins these with <br/>. Splitting just after a separator keeps each
    piece readable; a token with no separator is cut at the width.
    """
    if len(value) <= width:
        return [value]

    parts: list[str] = []
    rest = value
    while len(rest) > width:
        window = rest[:width]
        cut = max((window.rfind(c) for c in _VALUE_BREAK_AFTER), default=-1)
        # Only honour a separator in the back half, otherwise a URL scheme's
        # "//" would leave a three-character sliver on its own line.
        cut = cut + 1 if cut >= width // 2 else width
        parts.append(rest[:cut])
        rest = rest[cut:]
    if rest:
        parts.append(rest)
    return parts


def _as_dict(f, index: int) -> dict:
    if isinstance(f, dict):
        d = dict(f)
    else:
        d = {
            "type": f.type,
            "value": f.value,
            "context": f.context,
            "mitre": f.mitre,
            "severity": f.severity,
            "description": f.description,
            "defanged": f.defanged,
            "intel": f.intel,
        }
    d.setdefault("triage_status", "unreviewed")
    d.setdefault("triage_note", "")
    d.setdefault("intel", {})
    d["n"] = index
    # Reports get shared around, so network-reachable indicators are defanged
    # to make them non-clickable and safe to paste into a ticket.
    d["display_value"] = PlagGrep.defang(d.get("value", ""), d.get("type"))
    d["display_value_parts"] = _wrap_value(d["display_value"])
    # Context is usually one unbroken blob - pre-split it or it runs straight
    # off the edge of the table.
    d["context_parts"] = _wrap_value(str(d.get("context") or ""), CONTEXT_WRAP_COLUMNS)
    d["type_label"] = TYPE_LABEL.get(d.get("type"), d.get("type", "").replace("_", " ").title())
    d["severity_label"] = SEVERITY_LABEL.get(d.get("severity"), d.get("severity", ""))
    d["mitre_described"] = [PlagMitre.describe(t) for t in d.get("mitre") or []]
    intel = d["intel"]
    # The scope entry is an explanatory note about the indicator itself, not
    # a provider verdict, so it gets its own row instead of masquerading as
    # one more source in the list.
    scope = intel.get("scope")
    d["scope_note"] = scope.get("detail", "") if scope else ""
    # Every provider that supports this indicator type is listed - not just
    # the ones that returned a verdict - so the report shows what wasn't
    # checked (and why) as plainly as what was. Checked providers sort first;
    # a page of "no API key configured" rows would bury the answer.
    d["intel_display"] = [
        {"label": _PROVIDER_LABELS.get(source, source), **result}
        for source, result in sorted(
            intel.items(),
            key=lambda item: (item[1].get("verdict") == "not_checked",
                               _PROVIDER_LABELS.get(item[0], item[0])),
        )
        if source != "scope"
    ]
    # A single headline verdict for the overview table: worst wins, so a row
    # can be read at a glance without expanding every provider. Unchecked
    # providers don't count toward it, or an all-unconfigured indicator would
    # read as "unknown" instead of plainly "not checked".
    checked = [r for r in d["intel_display"] if r.get("verdict") != "not_checked"]
    d["intel_summary"] = _summarise_intel(checked, scope)
    d["verdict_label"] = str(d.get("triage_status", "unreviewed")).replace("_", " ")
    return d


_VERDICT_RANK = ["malicious", "suspicious", "clean", "unknown", "not_applicable", "error", "info"]
_VERDICT_TEXT = {
    "malicious": "Malicious",
    "suspicious": "Suspicious",
    "clean": "Clean",
    "unknown": "No data",
    "not_applicable": "Not applicable",
    "error": "Lookup failed",
    "info": "Context only",
}


def _summarise_intel(intel_display: list[dict], scope: dict | None = None) -> dict:
    """Collapse per-provider results into one headline for the overview
    table - "cleanunknownerrorclean" told the reader nothing."""
    scored = [r for r in intel_display if r.get("verdict") != "info"]

    if not scored:
        # No provider answered. If the indicator was ruled out up front,
        # say why; otherwise it simply wasn't checked.
        if scope and scope.get("verdict") == "not_applicable":
            return {"verdict": "not_applicable", "text": _VERDICT_TEXT["not_applicable"],
                    "note": scope.get("detail", "")}
        return {"verdict": "not_checked", "text": "Not checked", "note": ""}

    verdicts = [r.get("verdict", "unknown") for r in scored]
    for candidate in _VERDICT_RANK:
        if candidate in verdicts:
            headline = candidate
            break
    else:
        headline = "unknown"

    agreeing = sum(1 for v in verdicts if v == headline)
    if headline == "not_applicable":
        note = scored[0].get("detail", "")
    else:
        names = [r["label"] for r in scored if r.get("verdict") == headline]
        note = f"{agreeing} of {len(verdicts)} sources: " + ", ".join(names[:3])
        if len(names) > 3:
            note += f" +{len(names) - 3} more"
    return {"verdict": headline, "text": _VERDICT_TEXT.get(headline, headline), "note": note}


def _geo_host(finding: dict) -> str:
    value = str(finding.get("value", ""))
    return value.rsplit(":", 1)[0] if finding.get("type") == "ip_port" else value


def _geo_for_findings(findings: list[dict], conn) -> dict[str, dict]:
    """Geolocation for every address among the findings, computed live -
    the same approach the spreadsheet export already uses, so a report run
    before a GeoIP database was configured still comes back enriched."""
    geo: dict[str, dict] = {}
    for f in findings:
        if f.get("type") not in ("ip", "ip_port"):
            continue
        host = _geo_host(f)
        if host and host not in geo:
            geo[host] = PlagGeo.locate(host, conn)
    return geo


def _resolved_row(name: str, value) -> dict:
    """One row of the resolved-variables table.

    A resolved value can still be a stage rather than the payload - a list of
    character codes, or another Base64 blob. Decoding it here means the table
    shows what it holds instead of a wall of digits.
    """
    shown = PlagGrep.defang_text(str(value))
    row = {
        "name": name,
        "value": shown,
        "value_parts": _wrap_value(shown, RESOLVED_WRAP_COLUMNS),
        "decoded": "",
        "decoded_parts": [],
        "decoded_how": "",
    }
    payload = PlagEncode.decode_payload(str(value))
    if payload:
        how, text = payload
        decoded = PlagGrep.defang_text(text)
        row["decoded_how"] = how
        row["decoded"] = decoded
        row["decoded_parts"] = _wrap_value(decoded, RESOLVED_WRAP_COLUMNS)
    return row


def _severity_counts(findings: list[dict]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    return counts


def _triage_counts(findings: list[dict]) -> dict:
    counts = {"confirmed_threat": 0, "false_positive": 0, "unreviewed": 0, "unknown": 0}
    for f in findings:
        status = f.get("triage_status", "unreviewed")
        counts[status] = counts.get(status, 0) + 1
    return counts


CODE_WRAP_COLUMNS = 96


def _numbered_lines(text: str) -> list[dict]:
    """Split into rows, hard-wrapping at a fixed column.

    xhtml2pdf does not reliably break a long unbroken token, so an
    obfuscated one-liner would run off the page edge. Wrapping here
    guarantees it fits regardless of what the renderer supports.

    Nothing is numbered: an inline "12 | " gutter is what turns a wrapped
    one-liner into an unreadable wall, and the line numbers were never
    referenced from anywhere else in the report. `gutter` stays in the row
    shape (always empty) so the templates need no special-casing.
    """
    rows: list[dict] = []
    for i, line in enumerate((text or "").split("\n")):
        if not line:
            rows.append({"n": i + 1, "gutter": "", "text": ""})
            continue
        for offset in range(0, len(line), CODE_WRAP_COLUMNS):
            rows.append({
                "n": i + 1 if offset == 0 else "",
                "gutter": "",
                "text": line[offset:offset + CODE_WRAP_COLUMNS],
            })
    return rows


# A transform entry is written as "Pass N: ...". Everything else the engine
# appends to pass_log is a statement about the analysis itself - that the
# fixed point was not reached, or that high-entropy runs are still opaque.
# Counting those under "Transforms applied (N)" overstates the count and,
# worse, presents a caveat as though it were a decode that happened.
_TRANSFORM_PREFIX = "Pass "


def _transform_entries(pass_log: list) -> list:
    return [e for e in pass_log if str(e).startswith(_TRANSFORM_PREFIX)]


def _status_entries(pass_log: list) -> list:
    return [e for e in pass_log if not str(e).startswith(_TRANSFORM_PREFIX)]


def _source_line(analysis: dict) -> str:
    filename = analysis.get("filename") or "pasted-script"
    kind = analysis.get("source_kind")
    if kind is None:
        kind = "pasted" if filename == "pasted-script" else "file"
    return "Pasted script" if kind == "pasted" else f"File: {filename}"


def build_report_context(analysis: dict, analyst_name: str = "", utc_offset: float | None = None,
                          redact_iocs: bool = False, conn=None) -> dict:
    if utc_offset is None:
        utc_offset = PlagConfig.DEFAULT_UTC_OFFSET

    findings = [_as_dict(f, i + 1) for i, f in enumerate(analysis.get("findings", []))]
    geo_map = _geo_for_findings(findings, conn)
    for f in findings:
        f["geo_rows"] = PlagGeo.describe(geo_map.get(_geo_host(f))) if f.get("type") in ("ip", "ip_port") else []
    severity_counts = _severity_counts(findings)
    triage_counts = _triage_counts(findings)
    normalized = {**analysis, "findings": findings}

    # Note: not called "items" - Jinja would resolve `group.items` to the
    # dict's built-in method rather than this key.
    grouped = [
        {"severity": sev, "label": SEVERITY_LABEL[sev],
         "entries": [f for f in findings if f.get("severity") == sev]}
        for sev in SEVERITY_ORDER
    ]
    grouped = [g for g in grouped if g["entries"]]

    original_text = analysis.get("original") or ""
    original_sha256 = hashlib.sha256(original_text.encode("utf-8", "replace")).hexdigest()

    generated = datetime.now(timezone.utc) + timedelta(hours=utc_offset)
    tz_label = PlagConfig.format_utc_offset(utc_offset)
    # e.g. "08 August 2026 - 11:17:47 (UTC+7)"
    generated_display = f"{generated.strftime('%d %B %Y - %H:%M:%S')} ({tz_label})"
    generated_date = generated.strftime("%d %B %Y")
    generated_time = f"{generated.strftime('%H:%M:%S')} ({tz_label})"

    # Resolved values usually contain the payload's real IOCs, so they get
    # the same defanging treatment as the findings table.
    resolved_vars = analysis.get("resolved_vars") or {}
    resolved_display = [_resolved_row(name, value) for name, value in resolved_vars.items()]

    return {
        "analysis": normalized,
        "grouped_findings": grouped,
        "redact_iocs": redact_iocs,
        "generated_at": generated_display,
        "generated_date": generated_date,
        "generated_time": generated_time,
        "generated_tz": tz_label,
        "watermark_data_uri": PlagWatermark.watermark_data_uri(),
        "tagline": TAGLINE,
        "source_line": _source_line(analysis),
        "counts": severity_counts,
        "triage_counts": triage_counts,
        "total_findings": len(findings),
        "original_sha256": original_sha256,
        "original_lines": _numbered_lines(original_text),
        "deobfuscated_lines": _numbered_lines(analysis.get("deobfuscated", "")),
        "deobfuscated_raw_lines": _numbered_lines(
            analysis.get("deobfuscated_raw") or analysis.get("deobfuscated", "")
        ),
        "toc": _toc(bool(grouped)),
        "resolved_vars": resolved_vars,
        "resolved_display": resolved_display,
        "pass_log_display": [
            {"entry": entry, "why": PlagExplain.explain(entry)}
            for entry in _transform_entries(analysis.get("pass_log", []))
        ],
        "analysis_notes": _status_entries(analysis.get("pass_log", [])),
        "severity_chart": PlagCharts.severity_bar_chart(severity_counts) if findings else None,
        "triage_chart": PlagCharts.triage_pie_chart(triage_counts) if findings else None,
        "logo_data_uri": _logo_data_uri(),
        "analyst_name": analyst_name,
    }


# The body sections of one analysis, in the order the templates emit them.
# `heading` is how each appears in the rendered PDF: it is what _locate_sections
# matches on, so it must stay in step with the templates' heading text.
_SECTIONS = [
    ("summary", "Analysis Summary", "Analysis Summary"),
    ("indicators", "Indicators at a glance", "Indicators at a glance"),
    ("details", "Finding details", "Finding details"),
    ("deobfuscation", "Deobfuscation", "Deobfuscation"),
    ("appendix-a", "Appendix A", "Appendix A - Deobfuscated script"),
    ("appendix-b", "Appendix B", "Appendix B - Original input"),
]


def _sections_for(has_grouped_findings: bool):
    """Finding details only exists when there is something to detail."""
    return [s for s in _SECTIONS if has_grouped_findings or s[0] != "details"]


def _toc(has_grouped_findings: bool) -> list[dict]:
    """Contents entries for a single-analysis report."""
    return [
        {
            "anchor": f"sec-{slug}", "heading": heading, "title": title,
            "number": str(i), "level": 1,
        }
        for i, (slug, heading, title) in enumerate(_sections_for(has_grouped_findings), 1)
    ]


def _combined_toc(sections: list[dict]) -> list[dict]:
    """Contents for a combined report: each analysis, then its own sections.

    Headings repeat across analyses, which is fine - _locate_sections only ever
    searches forward, so the second "Finding details" resolves to the second
    analysis.
    """
    entries: list[dict] = []
    for i, section in enumerate(sections, 1):
        entries.append({
            "anchor": f"sec-{i}",
            # Matches the analysis' <h1> in the body.
            "heading": f"{i}. {section['source_line']}",
            "title": section["source_line"],
            "number": str(i), "level": 1,
        })
        # No "Analysis Summary" sub-entry here: in a combined report the
        # analysis' own heading *is* the summary, so listing it would point at
        # a heading that does not exist.
        subs = [s for s in _sections_for(bool(section.get("grouped_findings")))
                if s[0] != "summary"]
        for j, (slug, heading, title) in enumerate(subs, 1):
            entries.append({
                "anchor": f"sec-{i}-{slug}", "heading": heading, "title": title,
                "number": f"{i}.{j}", "level": 2,
            })
    return entries


def render_html(analysis: dict, analyst_name: str = "", utc_offset: float | None = None,
                 redact_iocs: bool = False, conn=None) -> str:
    template = _env.get_template("report.html")
    return template.render(**build_report_context(analysis, analyst_name, utc_offset, redact_iocs, conn))


def render_combined_pdf(analyses: list[dict], analyst_name: str = "",
                         utc_offset: float | None = None, redact_iocs: bool = False,
                         conn=None) -> bytes:
    """One document covering several analyses - a shared cover and contents,
    then each analysis in full. Used when a batch is submitted and the
    analyst wants a single artefact to hand over."""
    if not analyses:
        raise ValueError("No analyses to combine")

    sections = [
        build_report_context(a, analyst_name, utc_offset, redact_iocs, conn) for a in analyses
    ]
    totals = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for section in sections:
        for key in totals:
            totals[key] += section["counts"][key]

    first = sections[0]
    context = {
        "sections": sections,
        "toc": _combined_toc(sections),
        "counts": totals,
        "total_findings": sum(s["total_findings"] for s in sections),
        "generated_at": first["generated_at"],
        "generated_date": first["generated_date"],
        "generated_time": first["generated_time"],
        "logo_data_uri": _logo_data_uri(),
        "watermark_data_uri": PlagWatermark.watermark_data_uri(),
        "analyst_name": analyst_name,
        "tagline": TAGLINE,
        "redact_iocs": redact_iocs,
    }
    ids = [a.get("id") for a in analyses if a.get("id")]
    label = ", ".join(str(i) for i in ids[:4]) + (" +" if len(ids) > 4 else "")
    return _render_split("report_combined.html", context, "combined PDF report",
                         title=f"Plaguards Report {label}" if ids else "Plaguards Report")


def render_pdf(analysis: dict, analyst_name: str = "", utc_offset: float | None = None,
                redact_iocs: bool = False, conn=None) -> bytes:
    context = build_report_context(analysis, analyst_name, utc_offset, redact_iocs, conn)
    analysis_id = analysis.get("id")
    title = f"Plaguards Report {analysis_id}" if analysis_id else "Plaguards Report"
    return _render_split("report.html", context, "PDF report", title=title)


def _render_one(template_name: str, context: dict, part: str, what: str) -> bytes:
    """Render one half of a report to PDF bytes."""
    html = _env.get_template(template_name).render(part=part, **context)
    buf = io.BytesIO()
    result = pisa.CreatePDF(src=html, dest=buf)
    if result.err:
        raise RuntimeError(f"Failed to render {what} ({part} matter)")
    return buf.getvalue()


def _render_split(template_name: str, context: dict, what: str,
                   title: str = "Plaguards Report") -> bytes:
    """Render the front matter and the body as separate documents, then join
    them.

    xhtml2pdf offers no way to offset or restart <pdf:pagenumber>, so a
    single-pass render would number the cover and contents. Rendering the body
    on its own makes its first page genuinely page 1, and the front matter is
    simply prepended - which is what "page numbers start after the contents"
    means in the finished file.

    The body goes first so the contents can carry real page numbers: the body
    is what defines them, and it does not depend on the front matter at all.
    """
    body = _render_one(template_name, context, "body", what)
    toc = context.get("toc") or []
    body_pages = [p.extract_text() or "" for p in pypdf.PdfReader(io.BytesIO(body)).pages]
    body_index = _locate_sections(body_pages, toc)
    # strict: _locate_sections returns one index per contents entry. A
    # mismatch would silently shift every page number that follows it.
    for entry, index in zip(toc, body_index, strict=True):
        # Body page 0 prints as "Page 1", so the contents quote index + 1.
        entry["page"] = "" if index is None else str(index + 1)

    front = _render_one(template_name, context, "front", what)
    front_pages = len(pypdf.PdfReader(io.BytesIO(front)).pages)

    writer = pypdf.PdfWriter()
    for chunk in (front, body):
        writer.append(io.BytesIO(chunk))
    _link_contents(writer, front_pages, body_index)
    # Browsers and PDF readers name the window from /Title, so a report opened
    # straight from a URL is not called after the last path segment.
    writer.add_metadata({"/Title": title, "/Producer": "PlaguardsV2",
                         "/Creator": "PlaguardsV2"})

    out = io.BytesIO()
    writer.write(out)
    writer.close()
    return out.getvalue()


def _locate_sections(page_texts: list[str], toc: list[dict]) -> list[int | None]:
    """Body page index for each contents entry, in document order.

    The search moves forward only. Headings repeat in a combined report - every
    analysis has its own "Finding details" - so position, not just text, is what
    identifies a section.
    """
    found: list[int | None] = []
    cursor = 0
    for entry in toc:
        heading = entry["heading"]
        hit = None
        for i in range(cursor, len(page_texts)):
            # Anchored to a line start so a heading word appearing inside quoted
            # script text in an appendix cannot win the match.
            if any(line.strip().startswith(heading)
                   for line in page_texts[i].splitlines()):
                hit = i
                break
        found.append(hit)
        if hit is not None:
            cursor = hit
    return found


def _link_contents(writer, front_pages: int, body_index: list) -> None:
    """Point the Contents entries at the body pages they name.

    The two halves are rendered separately, so the links the renderer emitted
    on the Contents page resolve to placeholder anchors in the front matter.
    Their rectangles are already in the right places though, so re-aiming the
    destinations is enough - and cheaper than laying the links out by hand.

    Best-effort: if the shape of the document is not what we expect, the links
    are left pointing at the front matter rather than somewhere wrong.
    """
    if not body_index:
        return

    annots = []
    for page in writer.pages[:front_pages]:
        for ref in page.get("/Annots") or []:
            obj = ref.get_object()
            if obj.get("/Subtype") == "/Link" and "/Dest" in obj:
                annots.append(obj)
    if len(annots) != len(body_index):
        return

    for annot, index in zip(annots, body_index, strict=True):
        if index is None:
            continue
        target = front_pages + index
        annot[pypdf.generic.NameObject("/Dest")] = pypdf.generic.ArrayObject([
            writer.pages[target].indirect_reference,
            pypdf.generic.NameObject("/XYZ"),
            pypdf.generic.NullObject(),
            pypdf.generic.NullObject(),
            pypdf.generic.NullObject(),
        ])
