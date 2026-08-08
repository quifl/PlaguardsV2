"""Batch / zip submission handling."""
import io
import zipfile

import pytest

from plaguardsv2.GuardModules import PlagBatch, PlagReport


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries:
            zf.writestr(name, body)
    return buf.getvalue()


def test_extracts_supported_files():
    data = make_zip([("a.ps1", "Write-Host 'a'"), ("b.txt", "Write-Host 'b'")])
    results, skipped = PlagBatch.extract_zip(data)
    assert sorted(n for n, _ in results) == ["a.ps1", "b.txt"]
    assert not skipped


def test_skips_unsupported_and_empty_entries():
    data = make_zip([("keep.ps1", "Write-Host 'x'"), ("skip.exe", "MZ"), ("blank.txt", "   ")])
    results, skipped = PlagBatch.extract_zip(data)
    assert [n for n, _ in results] == ["keep.ps1"]
    assert any("skip.exe" in s for s in skipped)
    assert any("blank.txt" in s for s in skipped)


def test_directory_components_are_stripped():
    """A zip entry must not get to choose where its contents land."""
    data = make_zip([("../../evil.ps1", "Write-Host 'x'"), ("nested/dir/ok.ps1", "Write-Host 'y'")])
    results, _ = PlagBatch.extract_zip(data)
    names = [n for n, _ in results]
    assert "evil.ps1" in names and "ok.ps1" in names
    assert not any("/" in n or "\\" in n or ".." in n for n in names)


def test_oversized_entry_is_skipped():
    big = "A" * (PlagBatch.MAX_ENTRY_BYTES + 10)
    data = make_zip([("big.ps1", big), ("small.ps1", "Write-Host 'ok'")])
    results, skipped = PlagBatch.extract_zip(data)
    assert [n for n, _ in results] == ["small.ps1"]
    assert any("big.ps1" in s for s in skipped)


def test_entry_count_is_capped():
    data = make_zip([(f"f{i}.ps1", "Write-Host 'x'") for i in range(PlagBatch.MAX_ENTRIES + 15)])
    results, skipped = PlagBatch.extract_zip(data)
    assert len(results) == PlagBatch.MAX_ENTRIES
    assert any("stopped after" in s for s in skipped)


def test_corrupt_archive_raises_batch_error():
    with pytest.raises(PlagBatch.BatchError):
        PlagBatch.extract_zip(b"this is definitely not a zip")


def test_is_zip_detection():
    assert PlagBatch.is_zip("bundle.ZIP")
    assert not PlagBatch.is_zip("script.ps1")


def test_scope_note_is_separate_from_provider_results():
    """The scope entry explains the indicator; it must not appear as one
    more provider verdict."""
    finding = {
        "type": "ip", "value": "198.51.100.42", "severity": "info",
        "intel": {
            "scope": {"verdict": "info", "detail": "documentation range"},
            "virustotal": {"verdict": "clean", "detail": "0 malicious"},
        },
    }
    d = PlagReport._as_dict(finding, 1)
    assert d["scope_note"] == "documentation range"
    assert [r["label"] for r in d["intel_display"]] == ["VirusTotal"]
    assert d["intel_summary"]["verdict"] == "clean"


def test_summary_falls_back_to_scope_when_nothing_queried():
    finding = {
        "type": "domain", "value": "x.invalid", "severity": "info",
        "intel": {"scope": {"verdict": "not_applicable", "detail": "reserved suffix"}},
    }
    d = PlagReport._as_dict(finding, 1)
    assert d["intel_display"] == []
    assert d["intel_summary"]["verdict"] == "not_applicable"
    assert d["intel_summary"]["note"] == "reserved suffix"




def test_code_lines_wrap_without_a_gutter():
    """Long lines are hard-wrapped to fit the page, and nothing is numbered -
    an inline "12 | " gutter turned a wrapped one-liner into a wall of text."""
    rows = PlagReport._numbered_lines("A" * 200 + "\nB")
    assert [r["text"] for r in rows] == ["A" * 96, "A" * 96, "A" * 8, "B"]
    assert all(r["gutter"] == "" for r in rows)


def test_long_indicator_values_are_broken_into_cell_sized_parts():
    """xhtml2pdf will not split an unbroken token, so a long defanged URL is
    pre-split - preferably just after a separator."""
    value = "hxxp://malicious[.]example[.]invalid/payload[.]ps1"
    parts = PlagReport._wrap_value(value)
    assert len(parts) > 1
    assert "".join(parts) == value
    assert all(len(p) <= PlagReport.VALUE_WRAP_COLUMNS for p in parts)
    # A value that already fits is left alone.
    assert PlagReport._wrap_value("198[.]51[.]100[.]42") == ["198[.]51[.]100[.]42"]


def _example_analysis():
    return {
        "filename": "sample.ps1",
        "original": "$a = 'x'",
        "deobfuscated": "$a = 'x'",
        "deobfuscated_raw": "$a = 'x'",
        "findings": [],
        "pass_log": [],
        "resolved_vars": {},
        "truncated": False,
    }


def test_page_numbering_restarts_after_the_front_matter():
    """Front matter carries no footer, and the body's first page is page 1 -
    the two halves are rendered and merged separately to get there."""
    import re

    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(PlagReport.render_pdf(_example_analysis())))
    texts = [page.extract_text() or "" for page in reader.pages]
    numbered = [i for i, t in enumerate(texts) if re.search(r"Page \d+ of", t)]

    first = numbered[0]
    assert first > 0
    assert re.search(r"Page 1 of \d+", texts[first])
    assert numbered == list(range(first, len(texts)))


def test_contents_and_disclaimer_are_separate_pages():
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(PlagReport.render_pdf(_example_analysis())))
    texts = [page.extract_text() or "" for page in reader.pages]
    contents = next(i for i, t in enumerate(texts) if t.lstrip().startswith("Contents"))
    disclaimer = next(i for i, t in enumerate(texts) if "Disclaimer & scope" in t)
    assert disclaimer == contents + 1


def test_contents_entries_link_to_their_section():
    """Each Contents row jumps to the body page its section starts on."""
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(PlagReport.render_pdf(_example_analysis())))
    contents = next(
        i for i, p in enumerate(reader.pages)
        if (p.extract_text() or "").lstrip().startswith("Contents")
    )
    links = [
        a.get_object() for a in reader.pages[contents].get("/Annots") or []
        if a.get_object().get("/Subtype") == "/Link"
    ]
    assert links, "the Contents page should carry link annotations"

    by_id = {p.indirect_reference.idnum: i for i, p in enumerate(reader.pages)}
    targets = [by_id[link["/Dest"][0].idnum] for link in links]
    # Every entry points into the body, in the order the sections appear.
    assert all(t > contents for t in targets)
    assert targets == sorted(targets)

    # Search past the Contents page itself, which also names every section.
    summary = next(
        i for i, p in enumerate(reader.pages)
        if i > contents
        and any(l.strip().startswith("Analysis Summary")
                for l in (p.extract_text() or "").splitlines())
    )
    assert targets[0] == summary


def test_the_report_shows_both_deobfuscated_forms():
    analysis = _example_analysis()
    analysis["deobfuscated_raw"] = "$a='x';$b='y'"
    analysis["deobfuscated"] = "$a='x'\n$b='y'"
    ctx = PlagReport.build_report_context(analysis)
    assert [r["text"] for r in ctx["deobfuscated_raw_lines"]] == ["$a='x';$b='y'"]
    assert [r["text"] for r in ctx["deobfuscated_lines"]] == ["$a='x'", "$b='y'"]


def _pdf(analysis=None):
    from pypdf import PdfReader
    return PdfReader(io.BytesIO(PlagReport.render_pdf(analysis or _example_analysis())))


def test_contents_quotes_the_page_each_section_starts_on():
    """The number printed beside an entry is the page the reader lands on."""
    import re

    reader = _pdf()
    texts = [p.extract_text() or "" for p in reader.pages]
    contents = next(i for i, t in enumerate(texts) if t.lstrip().startswith("Contents"))
    first_body = next(i for i, t in enumerate(texts) if re.search(r"Page 1 of", t))

    # Pair each quoted number with the link that sits on the same row.
    links = [
        a.get_object() for a in reader.pages[contents].get("/Annots") or []
        if a.get_object().get("/Subtype") == "/Link"
    ]
    by_id = {p.indirect_reference.idnum: i for i, p in enumerate(reader.pages)}
    landed = [by_id[link["/Dest"][0].idnum] - first_body + 1 for link in links]

    quoted = [int(n) for n in re.findall(r"^\s*(\d+)\s*$", texts[contents], re.M)]
    # Section numbers (1..6) come first on each row, page numbers second.
    assert landed == sorted(landed)
    assert all(page >= 1 for page in landed)
    assert set(landed).issubset(set(quoted))


def test_the_reformatted_appendix_is_gone():
    analysis = _example_analysis()
    analysis["deobfuscated_raw"] = "$a='x';$b='y'"
    analysis["deobfuscated"] = "$a='x'\n$b='y'"
    body = "\n".join((p.extract_text() or "") for p in _pdf(analysis).pages)
    assert "Reformatted" not in body
    assert "Appendix A" in body and "Appendix B" in body


def test_long_context_is_broken_up_so_it_stays_inside_its_cell():
    blob = "A" * 400
    finding = {
        "type": "signature", "value": "Base64-encoded command", "severity": "medium",
        "context": blob, "mitre": [], "description": "", "defanged": False, "intel": {},
    }
    parts = PlagReport._as_dict(finding, 1)["context_parts"]
    assert len(parts) > 1
    assert "".join(parts) == blob
    assert all(len(p) <= PlagReport.CONTEXT_WRAP_COLUMNS for p in parts)


def test_threat_intel_label_spans_its_provider_rows():
    """One merged label cell, not an empty one beside every provider."""
    finding = {
        "type": "ip", "value": "198.51.100.42", "severity": "info",
        "context": "", "mitre": [], "description": "", "defanged": False,
        "intel": {
            "virustotal": {"verdict": "clean", "detail": "0 malicious"},
            "abuseipdb": {"verdict": "clean", "detail": "0%"},
            "shodan": {"verdict": "error", "detail": "not permitted"},
        },
    }
    analysis = _example_analysis()
    analysis["findings"] = [finding]
    html = PlagReport.render_html(analysis)
    assert 'rowspan="3">Threat intel<' in html
    # No empty label cells stacked beside the remaining provider rows.
    assert '<td class="dk"></td>' not in html
    # The other occurrence is the overview table's column header.
    assert html.count(">Threat intel<") == 2


def test_the_disclaimer_is_a_formal_numbered_notice():
    body = "\n".join((p.extract_text() or "") for p in _pdf().pages)
    assert "IMPORTANT" in body and "READ BEFORE RELYING ON THIS DOCUMENT" in body
    # Numbered clauses, not loose paragraphs.
    assert "1." in body and "6." in body
    assert "Issued by PlaguardsV2" in body
