"""Findings as a spreadsheet.

A PDF is for reading; a table is for pivoting, sorting and pasting into a
ticket. Same data as the report - every finding with its severity, MITRE
mapping, threat-intel verdict and analyst decision - plus the geolocation
columns for any address, in the spirit of HolmesGeo's enriched output.

CSV is written with the standard library. XLSX needs openpyxl and is simply
unavailable if it is not installed, rather than being a hard dependency.
"""
from __future__ import annotations

import csv
import io

from . import PlagGeo, PlagGrep, PlagMitre

COLUMNS = [
    ("n", "#"),
    ("severity", "Severity"),
    ("type", "Type"),
    ("value", "Value"),
    ("defanged_value", "Value (defanged)"),
    ("mitre", "MITRE ATT&CK"),
    ("description", "What it means"),
    ("intel_verdict", "Threat intel"),
    ("intel_detail", "Threat intel detail"),
    ("triage_status", "Analyst verdict"),
    ("context", "Seen in context"),
    # HolmesGeo-style enrichment, populated for addresses only.
    ("geo_category", "IP category"),
    ("geo_city", "City"),
    ("geo_region", "Region"),
    ("geo_region_code", "Region code"),
    ("geo_postal_code", "Postal code"),
    ("geo_latitude", "City latitude"),
    ("geo_longitude", "City longitude"),
    # Pivoting on a coordinate without this column invites treating a
    # country-level guess as a street address.
    ("geo_accuracy_radius", "Accuracy radius (km)"),
    ("geo_time_zone", "Time zone"),
    ("geo_country", "Country"),
    ("geo_country_code", "Country code"),
    ("geo_registered_country", "Registered country"),
    ("geo_continent", "Continent"),
    ("geo_asn", "ASN number"),
    ("geo_organization", "ASN organization"),
    ("geo_network", "Network"),
    ("geo_network_flags", "Network type"),
    ("geo_reverse_dns", "Reverse DNS"),
]

MAX_CELL = 2000

# Leads that make a spreadsheet treat a cell as a formula. Every value here
# came out of a sample the analyst believes is hostile (CWE-1236).
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def _is_number(value: str) -> bool:
    try:
        float(value)
    except (TypeError, ValueError):
        return False
    return True


def _csv_safe(value):
    """Neutralise a formula lead for CSV, where there is no cell type to set.

    A leading apostrophe is the only portable way to say "this is text" in a
    CSV, so it is added - but never to a genuine number, or every negative
    longitude in the geolocation columns would stop being a number.
    """
    if not isinstance(value, str) or not value.startswith(_FORMULA_LEAD):
        return value
    return value if _is_number(value) else "'" + value


def _intel_summary(intel: dict) -> tuple[str, str]:
    """Worst verdict across providers, and who said what."""
    ranked = ["malicious", "suspicious", "unknown", "error", "clean"]
    scored = {
        source: result for source, result in (intel or {}).items()
        if source != "scope" and result.get("verdict") != "not_checked"
    }
    if not scored:
        return "not checked", ""
    verdicts = [r.get("verdict", "unknown") for r in scored.values()]
    headline = next((v for v in ranked if v in verdicts), "unknown")
    detail = "; ".join(
        f"{source}: {result.get('verdict', '')}"
        + (f" ({result['detail']})" if result.get("detail") else "")
        for source, result in sorted(scored.items())
    )
    return headline.replace("_", " "), detail


def build_rows(analysis: dict, geo: dict | None = None) -> list[dict]:
    """One row per finding, with geolocation filled in for addresses."""
    # The report's own labels, so a ticket and the PDF name a finding the same way.
    from .PlagReport import TYPE_LABEL

    geo = geo or {}
    rows = []
    for index, finding in enumerate(analysis.get("findings") or [], 1):
        get = finding.get if isinstance(finding, dict) \
            else lambda k, d=None, finding=finding: getattr(finding, k, d)
        value = str(get("value", "") or "")
        ftype = get("type", "") or ""
        verdict, detail = _intel_summary(get("intel", {}) or {})

        # Every geolocation column exists on every row, even for a finding
        # that is not an address, so the table stays rectangular.
        row = {f"geo_{field}": "" for field in PlagGeo.FIELDS if field != "ip"}
        row.update({
            "n": index,
            "severity": (get("severity", "") or "").capitalize(),
            "type": TYPE_LABEL.get(ftype, ftype.replace("_", " ").capitalize()),
            "value": value,
            "defanged_value": PlagGrep.defang(value, ftype),
            "mitre": "; ".join(PlagMitre.describe(t) for t in (get("mitre") or [])),
            "description": get("description", "") or "",
            "intel_verdict": verdict,
            "intel_detail": detail,
            "triage_status": str(get("triage_status", "unreviewed")).replace("_", " "),
            "context": (get("context", "") or "")[:MAX_CELL],
        })

        host = value.rsplit(":", 1)[0] if ftype == "ip_port" else value
        record = geo.get(host)
        if record:
            for field in PlagGeo.FIELDS:
                if field == "ip":
                    continue
                row[f"geo_{field}"] = record.get(field, "")
        rows.append(row)
    return rows


def to_csv(rows: list[dict]) -> bytes:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow([label for _key, label in COLUMNS])
    for row in rows:
        writer.writerow([_csv_safe(row.get(key, "")) for key, _label in COLUMNS])
    # BOM so Excel opens a UTF-8 CSV without mangling non-ASCII values.
    return b"\xef\xbb\xbf" + buf.getvalue().encode("utf-8")


def xlsx_available() -> bool:
    try:
        import openpyxl  # noqa: F401
    except ImportError:
        return False
    return True


LAYER_COLUMNS = [
    ("id", "Layer"), ("parent", "From layer"), ("language", "Language"),
    ("how", "How it was reached"), ("depth", "Depth"), ("size", "Size (bytes)"),
    ("indicators", "Indicators"), ("flags", "Flags"),
]


def to_xlsx(rows: list[dict], title: str = "Findings", layers: list[dict] | None = None) -> bytes:
    """The same table as a real spreadsheet - frozen header, filters, widths.
    `layers` (PlagReport.layer_rows) adds a Layers sheet for a layered analysis."""
    import openpyxl
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    def cell_text(value):
        # XML 1.0 forbids most control characters; a sample's text can carry them.
        return ILLEGAL_CHARACTERS_RE.sub("\ufffd", value) if isinstance(value, str) else value

    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = title[:31] or "Findings"

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", start_color="0D1A2B")
    for column, (_key, label) in enumerate(COLUMNS, 1):
        cell = sheet.cell(row=1, column=column, value=label)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(vertical="center")

    severity_fill = {
        "high": PatternFill("solid", start_color="F6DBE0"),
        "medium": PatternFill("solid", start_color="FBEED3"),
        "low": PatternFill("solid", start_color="D9EFE2"),
        "info": PatternFill("solid", start_color="E6E9F0"),
    }
    for r, row in enumerate(rows, 2):
        for c, (key, _label) in enumerate(COLUMNS, 1):
            value = cell_text(row.get(key, ""))
            cell = sheet.cell(row=r, column=c, value=value)
            # openpyxl types a leading "=" as a formula, which Excel then
            # evaluates. Pinning to text keeps the value byte-for-byte.
            if isinstance(value, str) and value.startswith(_FORMULA_LEAD):
                cell.data_type = "s"
            cell.alignment = Alignment(vertical="top", wrap_text=(key == "context"))
        fill = severity_fill.get(str(row.get("severity", "")).lower())
        if fill:
            sheet.cell(row=r, column=2).fill = fill

    widths = {"value": 38, "defanged_value": 38, "mitre": 34, "description": 44,
              "intel_detail": 44, "context": 52}
    for column, (key, label) in enumerate(COLUMNS, 1):
        sheet.column_dimensions[get_column_letter(column)].width = widths.get(key, max(12, len(label) + 2))

    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}{max(1, len(rows) + 1)}"

    if layers:
        extra = book.create_sheet("Layers")
        for column, (_key, label) in enumerate(LAYER_COLUMNS, 1):
            cell = extra.cell(row=1, column=column, value=label)
            cell.font = header_font
            cell.fill = header_fill
        for r, layer in enumerate(layers, 2):
            for c, (key, _label) in enumerate(LAYER_COLUMNS, 1):
                value = cell_text(layer.get(key, ""))
                cell = extra.cell(row=r, column=c, value=value)
                if isinstance(value, str) and value.startswith(_FORMULA_LEAD):
                    cell.data_type = "s"
        extra.column_dimensions["D"].width = 48
        extra.freeze_panes = "A2"

    out = io.BytesIO()
    book.save(out)
    return out.getvalue()
