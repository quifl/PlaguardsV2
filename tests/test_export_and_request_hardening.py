"""Two places where a sample's own text escapes being treated as data.

Both share a premise the rest of the codebase already accepts: every value in
a finding was lifted out of a file the analyst believes is hostile. The
question is not whether the author might put something awkward in it, but
what happens when they do.
"""
import io
import zipfile

import openpyxl
import requests

from plaguardsv2.GuardModules import PlagTable
from plaguardsv2.GuardModules.PlagProviders import base

DDE = "=cmd|'/c calc'!A1"


def _rows(value, **extra):
    finding = {"type": "mutex", "value": value, "severity": "high", "context": "x"}
    rows = PlagTable.build_rows({"findings": [finding]}, {})
    rows[0].update(extra)
    return rows


def test_xlsx_never_writes_a_finding_as_a_formula():
    """openpyxl types a leading "=" as a formula, and Excel evaluates it on
    open - turning the export of an analysed sample into its delivery."""
    sheet_xml = zipfile.ZipFile(io.BytesIO(PlagTable.to_xlsx(_rows(DDE)))).read(
        "xl/worksheets/sheet1.xml").decode()
    assert "<f>" not in sheet_xml

    cell = openpyxl.load_workbook(io.BytesIO(PlagTable.to_xlsx(_rows(DDE)))).active.cell(
        row=2, column=4)
    assert cell.data_type == "s"
    assert cell.value == DDE, "the value itself must survive intact"


def test_csv_neutralises_a_formula_lead():
    line = PlagTable.to_csv(_rows(DDE)).decode("utf-8-sig").splitlines()[1]
    assert "'" + DDE in line


def test_csv_leaves_real_numbers_alone():
    """A blanket prefix would turn every negative longitude in the
    geolocation columns into text."""
    line = PlagTable.to_csv(_rows("x", geo_longitude="-93.2348")).decode(
        "utf-8-sig").splitlines()[1]
    assert "-93.2348" in line and "'-93.2348" not in line


def test_an_indicator_cannot_steer_a_provider_request():
    """Interpolated raw, "http://a.invalid/../../../v1/pulses" collapses to a
    different endpoint - the sample's author choosing which URL gets called
    with the analyst's API key attached."""
    hostile = "http://a.invalid/../../../../v1/pulses"
    base_url = "https://otx.alienvault.com/api/v1/indicators"

    raw = requests.Request("GET", f"{base_url}/url/{hostile}/general").prepare().url
    assert "/indicators/url/" not in raw, "precondition: raw interpolation escapes the path"

    safe = requests.Request(
        "GET", f"{base_url}/url/{base.path_segment(hostile)}/general").prepare().url
    assert safe.startswith(f"{base_url}/url/")
    assert safe.endswith("/general")
    assert "?" not in safe and "#" not in safe


def test_encoding_leaves_ordinary_indicators_readable():
    for value in ("8.8.8.8", "example.com", "d41d8cd98f00b204e9800998ecf8427e"):
        assert base.path_segment(value) == value
