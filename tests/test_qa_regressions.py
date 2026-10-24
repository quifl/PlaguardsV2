"""Regressions found in a full QA pass over every page, form and the CLI."""
import io
import json

import pytest
import requests
from click.testing import CliRunner

from plaguardsv2.GuardModules import PlagConfig, PlagGeo, PlagIntel, PlagTable
from plaguardsv2.GuardModules.PlagProviders import base
from plaguardsv2.PlagWeb import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    for p in PlagConfig.PROVIDERS:
        monkeypatch.delenv(p["env_var"], raising=False)
    app = create_app(str(tmp_path / "qa.db"))
    app.config["TESTING"] = True
    return app.test_client()


def _flashes(client, resp):
    page = client.get(resp.headers["Location"]).get_data(as_text=True) if resp.status_code == 302 else ""
    return page


def _analyze(client, text="Write-Host 'http://one.example.invalid/a'"):
    resp = client.post("/analyze", data={"script_text": text, "skip_intel": "on"})
    return int(resp.headers["Location"].rsplit("/", 1)[1])


# Providers

@pytest.mark.parametrize("exc,expected", [
    (requests.exceptions.SSLError("x"), "TLS handshake failed"),
    (requests.ConnectionError("x"), "could not be reached"),
    (requests.Timeout("x"), "no response within 15s"),
])
def test_a_network_failure_is_explained_not_raised(exc, expected):
    """requests.SSLError does not exist at the top level; referencing it crashed
    every analysis that ran while a provider was unreachable."""
    assert expected in base.explain_exception(exc, 15)


def test_an_unreachable_provider_leaves_an_error_row(monkeypatch):
    def refuse(*_a, **_k):
        raise requests.ConnectionError("refused")
    monkeypatch.setattr(base.requests, "request", refuse)
    status, body, err = base.safe_json_request("GET", "https://provider.invalid/")
    assert status is None and body is None and "could not be reached" in err


# Routes

def test_unknown_page_gets_the_app_404(client):
    resp = client.get("/no-such-page")
    assert resp.status_code == 404 and "Not found" in resp.get_data(as_text=True)


def test_report_viewer_for_a_missing_analysis_is_404(client):
    assert client.get("/analysis/9999/report/view").status_code == 404


@pytest.mark.parametrize("query", ["", "?ids=", "?ids=9998,9999", "?ids=abc"])
def test_combined_viewer_without_real_analyses_is_404(client, query):
    """The PDF route redirects to History on failure, which then rendered
    inside the viewer's frame."""
    assert client.get("/history/report/view" + query).status_code == 404


@pytest.mark.parametrize("route", ["/history/bulk-export", "/history/bulk-delete"])
def test_bulk_actions_ignore_junk_ids(client, route):
    resp = client.post(route, data={"analysis_id": ["abc", ""]})
    assert resp.status_code == 302
    assert "Select at least one analysis" in _flashes(client, resp)


def test_delete_message_is_pluralised_properly(client):
    ids = [_analyze(client), _analyze(client)]
    resp = client.post("/history/bulk-delete", data={"analysis_id": [str(i) for i in ids]})
    assert "Deleted 2 analyses." in _flashes(client, resp)


def test_a_combined_batch_leaves_no_message_for_a_later_page(client):
    files = [(io.BytesIO(b"Write-Host 198.51.100.11"), "a.ps1"),
             (io.BytesIO(b"var u='http://b.example.invalid/'"), "b.js")]
    resp = client.post("/analyze", data={"file": files, "skip_intel": "on", "batch_report": "combined"},
                       content_type="multipart/form-data")
    assert "/history/report/view" in resp.headers["Location"]
    assert "Analyzed" not in client.get("/").get_data(as_text=True)


def test_result_page_counts_transforms_not_notes(client):
    analysis_id = _analyze(client, "$a = 'mal' + 'icious.example.invalid'; Write-Host $a")
    page = client.get(f"/analysis/{analysis_id}").get_data(as_text=True)
    # Two transforms (fold, propagate); tracing and "lookups skipped" are notes.
    assert "2 deobfuscation transforms applied" in page
    assert "lookups skipped at your request" in page


def test_out_of_scope_lookup_does_not_blame_missing_keys(client):
    page = client.post("/lookup", data={"ioc_value": "host.example.invalid", "ioc_type": "auto"}).get_data(as_text=True)
    assert "Add API keys" not in page
    assert "was not sent to any provider" in page


def test_lookup_shows_readable_type_and_verdict(client, monkeypatch):
    monkeypatch.setattr(PlagIntel, "enrich", lambda findings, **_k: [
        f.intel.update({"virustotal": {"verdict": "not_checked", "detail": "No API key configured"}})
        for f in findings])
    page = client.post("/lookup", data={"ioc_value": "d41d8cd98f00b204e9800998ecf8427e",
                                        "ioc_type": "auto"}).get_data(as_text=True)
    assert "(MD5 hash)" in page and "VirusTotal: not checked<" in page and ": not_checked<" not in page


# Settings

def test_bad_general_settings_are_rejected_without_claiming_saved(client):
    resp = client.post("/settings", data={"form": "general", "history_limit": "0",
                                          "analyst_name": "QA", "utc_offset": "abc"})
    page = _flashes(client, resp)
    assert "History limit must be" in page and "UTC offset must be" in page
    assert "General settings saved" not in page
    assert 'value="QA"' not in client.get("/settings").get_data(as_text=True)


def test_saving_no_keys_says_so(client):
    resp = client.post("/settings", data={"form": "keys"})
    assert "No keys entered" in _flashes(client, resp)


def test_a_saved_key_can_be_removed(client):
    client.post("/settings", data={"form": "keys", "shodan": "qa-placeholder"})
    assert "Remove" in client.get("/settings").get_data(as_text=True)
    resp = client.post("/settings", data={"form": "keys", "remove_key": "shodan"})
    assert "Removed the saved Shodan key." in _flashes(client, resp)
    with client.application.app_context():
        from plaguardsv2.GuardModules import PlagStore
        conn = PlagStore.get_conn(client.application.config["DB_PATH"])
        assert PlagConfig.key_source(conn, "shodan") is None


def test_a_key_from_env_is_labelled_and_cannot_be_removed_here(client, monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "qa-env-placeholder")
    page = client.get("/settings").get_data(as_text=True)
    assert "Set in .env" in page
    assert 'value="shodan"' not in page  # no Remove button for it


def test_remove_buttons_cannot_be_the_key_forms_default_button(client):
    """Enter in a key field submits the form's first submit button."""
    client.post("/settings", data={"form": "keys", "shodan": "qa-placeholder"})
    page = client.get("/settings").get_data(as_text=True)
    assert 'form="removeKeyForm" name="remove_key"' in page


def test_a_missing_geolite_path_is_reported(client, tmp_path):
    resp = client.post("/settings", data={"form": "geoip", "geoip_city_db": str(tmp_path / "none.mmdb"),
                                          "geoip_country_db": "", "geoip_asn_db": ""})
    assert "No GeoLite2 City database found" in _flashes(client, resp)
    assert "Not found" in client.get("/settings").get_data(as_text=True)


def test_a_database_added_after_saving_the_path_is_picked_up(tmp_path):
    folder = tmp_path / "geo"
    folder.mkdir()
    assert PlagGeo.resolve_database(str(folder), "city") is None
    (folder / "GeoLite2-City.mmdb").write_bytes(b"")
    assert PlagGeo.resolve_database(str(folder), "city").endswith("GeoLite2-City.mmdb")


# Exports and CLI

def test_spreadsheet_uses_the_reports_labels():
    rows = PlagTable.build_rows({"findings": [
        {"type": "hash_md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "severity": "high"}]})
    assert rows[0]["type"] == "MD5 hash" and rows[0]["severity"] == "High"


def test_cli_stores_the_file_name_and_puts_triage_in_the_json(tmp_path):
    from plaguardsv2.PlagCLI import cli

    sample = tmp_path / "nested" / "sample.ps1"
    sample.parent.mkdir()
    sample.write_text("Write-Host 'http://cli.example.invalid/x'", encoding="utf-8")
    out = tmp_path / "out.json"
    result = CliRunner().invoke(cli, [
        "analyze", str(sample), "--no-intel", "--triage", "--json", str(out),
        "--db-path", str(tmp_path / "cli.db")], input="t\n" * 20)
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["filename"] == "sample.ps1"
    assert data["findings"] and all(f["triage_status"] == "confirmed_threat" for f in data["findings"])
