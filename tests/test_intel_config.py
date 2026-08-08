from plaguardsv2.GuardModules import PlagConfig, PlagStore
from plaguardsv2.GuardModules.PlagProviders import abuseipdb


def test_env_key_used_when_no_db_value(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env-value")
    conn = PlagStore.get_conn(":memory:")
    assert PlagConfig.get_api_key(conn, "virustotal") == "env-value"


def test_db_value_overrides_env(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env-value")
    conn = PlagStore.get_conn(":memory:")
    PlagConfig.set_api_key(conn, "virustotal", "db-value")
    assert PlagConfig.get_api_key(conn, "virustotal") == "db-value"


def test_missing_key_returns_none(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    conn = PlagStore.get_conn(":memory:")
    assert PlagConfig.get_api_key(conn, "shodan") is None


def test_abuseipdb_lookup_without_key_is_not_checked():
    result = abuseipdb.lookup("ip", "203.0.113.10", None)
    assert result["verdict"] == "not_checked"


def test_abuseipdb_lookup_parses_malicious_verdict(monkeypatch):
    def fake_request(method, url, **kwargs):
        body = {"data": {"abuseConfidenceScore": 90, "totalReports": 12, "countryCode": "US"}}
        return 200, body, None

    monkeypatch.setattr(abuseipdb, "safe_json_request", fake_request)
    result = abuseipdb.lookup("ip", "203.0.113.10", "fake-key")
    assert result["verdict"] == "malicious"
    assert "90" in result["detail"]


def test_abuseipdb_unsupported_finding_type():
    result = abuseipdb.lookup("domain", "example.com", "fake-key")
    assert result["verdict"] == "not_checked"
