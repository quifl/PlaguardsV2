"""Finding and merging GeoLite2 databases.

None of these touch a real .mmdb - the reader functions are exercised
separately (they degrade to None without geoip2 or a real database, which
is exactly the "unreadable" path already covered elsewhere). What's tested
here is the part that's easy to get wrong without one: resolving whatever
Settings' City / Country / ASN fields point at down to one .mmdb file each
- a bare file, a folder, or MaxMind's still-zipped .tar.gz download - and
merging whichever of the three showed up into one record.
"""
import tarfile

from plaguardsv2.GuardModules import PlagGeo


def test_classify_reads_the_kind_from_the_filename():
    assert PlagGeo._classify("GeoLite2-ASN.mmdb") == "asn"
    assert PlagGeo._classify("GeoLite2-City.mmdb") == "city"
    assert PlagGeo._classify("GeoLite2-Country.mmdb") == "country"
    assert PlagGeo._classify("custom-database.mmdb") is None


def test_a_bare_mmdb_file_is_trusted_for_whichever_field_it_was_entered_in(tmp_path):
    """Each Settings field already says what kind it is, so a plain file -
    with no naming convention to go by - is used as-is rather than sniffed
    or second-guessed."""
    db = tmp_path / "geoip.mmdb"
    db.write_bytes(b"not a real database, just a path to resolve")

    assert PlagGeo._resolve_one(str(db), "city") == str(db)
    assert PlagGeo._resolve_one(str(db), "asn") == str(db)


def test_a_folder_with_all_three_yields_the_one_matching_the_kind_asked_for(tmp_path):
    asn = tmp_path / "GeoLite2-ASN.mmdb"
    city = tmp_path / "GeoLite2-City.mmdb"
    country = tmp_path / "GeoLite2-Country.mmdb"
    for f in (asn, city, country):
        f.write_bytes(b"placeholder")

    assert PlagGeo._resolve_one(str(tmp_path), "asn") == str(asn)
    assert PlagGeo._resolve_one(str(tmp_path), "city") == str(city)
    assert PlagGeo._resolve_one(str(tmp_path), "country") == str(country)


def test_a_folder_with_one_unnamed_database_is_used_regardless_of_kind(tmp_path):
    """Pointed at a folder holding just one file for one specific field,
    there's nothing to disambiguate by name - so it's used anyway."""
    db = tmp_path / "downloaded.mmdb"
    db.write_bytes(b"placeholder")

    assert PlagGeo._resolve_one(str(tmp_path), "asn") == str(db)


def test_a_missing_path_resolves_to_nothing(tmp_path):
    assert PlagGeo._resolve_one(str(tmp_path / "does-not-exist"), "city") is None
    assert PlagGeo._resolve_one("", "city") is None


def _make_archive(downloads_dir, name, mmdb_name, build_dir):
    """A .tar.gz shaped like MaxMind's own downloads: one dated folder
    holding the .mmdb plus a couple of text files alongside it.

    Built under `build_dir`, well outside `downloads_dir`, so the raw .mmdb
    used to build the archive can never itself be picked up by a scan of
    `downloads_dir` - only the archive should be found there.
    """
    src_dir = build_dir / f"{name}_20260809"
    src_dir.mkdir(parents=True)
    (src_dir / mmdb_name).write_bytes(b"placeholder")
    (src_dir / "COPYRIGHT.txt").write_text("(c) MaxMind")

    archive = downloads_dir / f"{name}_20260809.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(src_dir, arcname=f"{name}_20260809")
    return archive


def test_a_tar_gz_file_is_extracted_and_resolved(tmp_path):
    build = tmp_path / "build"
    archive = _make_archive(tmp_path, "GeoLite2-ASN", "GeoLite2-ASN.mmdb", build)
    cache = tmp_path / "cache"

    found = PlagGeo._resolve_one(str(archive), "asn", cache_dir=cache)
    assert found.endswith("GeoLite2-ASN.mmdb")
    # Actually landed in the cache folder, not read out of the archive in place.
    assert str(cache) in found


def test_a_folder_holding_a_tar_gz_download_is_extracted_too(tmp_path):
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    _make_archive(downloads, "GeoLite2-City", "GeoLite2-City.mmdb", tmp_path / "build")
    cache = tmp_path / "cache"

    found = PlagGeo._resolve_one(str(downloads), "city", cache_dir=cache)
    assert found.endswith("GeoLite2-City.mmdb")
    assert str(cache) in found


def test_extraction_is_reused_rather_than_repeated(tmp_path):
    downloads = tmp_path / "downloads"
    downloads.mkdir()
    _make_archive(downloads, "GeoLite2-Country", "GeoLite2-Country.mmdb", tmp_path / "build")
    cache = tmp_path / "cache"

    first = PlagGeo._resolve_one(str(downloads), "country", cache_dir=cache)
    extracted_dir = list(cache.iterdir())[0]
    marker = extracted_dir / "still-here.txt"
    marker.write_text("proof the folder was not wiped and rebuilt")

    second = PlagGeo._resolve_one(str(downloads), "country", cache_dir=cache)
    assert second == first
    assert marker.exists()


def test_merge_prefers_city_over_country_and_always_takes_asn(monkeypatch):
    monkeypatch.setattr(PlagGeo, "_from_maxmind_city", lambda v, p: {
        "city": "Jakarta", "latitude": -6.2, "longitude": 106.8,
        "country": "Indonesia", "country_code": "ID", "continent": "Asia",
        "network": "203.0.113.0/24",
    })
    monkeypatch.setattr(PlagGeo, "_from_maxmind_country", lambda v, p: {
        "country": "should not win", "country_code": "XX", "continent": "",
        "network": "",
    })
    monkeypatch.setattr(PlagGeo, "_from_maxmind_asn", lambda v, p: {
        "asn": "AS13335", "organization": "Cloudflare, Inc.", "network": "203.0.113.0/24",
    })

    result = PlagGeo._from_maxmind("203.0.113.9", {"city": "c", "country": "k", "asn": "a"})
    assert result["city"] == "Jakarta"
    assert result["country"] == "Indonesia"
    assert result["asn"] == "AS13335"
    assert result["organization"] == "Cloudflare, Inc."
    assert result["source"] == "MaxMind GeoLite2 (local: City + ASN)"


def test_merge_falls_back_to_country_when_city_has_no_answer(monkeypatch):
    monkeypatch.setattr(PlagGeo, "_from_maxmind_city", lambda v, p: None)
    monkeypatch.setattr(PlagGeo, "_from_maxmind_country", lambda v, p: {
        "country": "Indonesia", "country_code": "ID", "continent": "Asia", "network": "",
    })

    result = PlagGeo._from_maxmind("203.0.113.9", {"city": "c", "country": "k"})
    assert result["country"] == "Indonesia"
    assert "latitude" not in result  # Country never had it to give
    assert result["source"] == "MaxMind GeoLite2 (local: Country)"


def test_asn_fills_the_network_only_when_nothing_else_already_did(monkeypatch):
    monkeypatch.setattr(PlagGeo, "_from_maxmind_asn", lambda v, p: {
        "asn": "AS13335", "organization": "Cloudflare, Inc.", "network": "203.0.113.0/24",
    })

    result = PlagGeo._from_maxmind("203.0.113.9", {"asn": "a"})
    assert result["network"] == "203.0.113.0/24"
    assert result["source"] == "MaxMind GeoLite2 (local: ASN)"


def test_merge_with_nothing_configured_or_matching_is_none():
    assert PlagGeo._from_maxmind("203.0.113.9", {}) is None


def test_describe_formats_a_full_record():
    """The PDF report and the Quick IOC Lookup page share this formatting,
    so it lives on PlagGeo rather than being duplicated in each caller."""
    rows = PlagGeo.describe({
        "city": "Jakarta", "latitude": -6.2, "longitude": 106.8,
        "country": "Indonesia", "country_code": "ID", "continent": "Asia",
        "asn": "AS13335", "organization": "Cloudflare, Inc.",
        "network": "203.0.113.0/24", "reverse_dns": "host.example.invalid",
        "source": "MaxMind GeoLite2 (local: City + ASN)",
    })
    by_label = {r["label"]: r["value"] for r in rows}
    assert by_label["City"] == "Jakarta"
    assert by_label["Country"] == "Indonesia (ID)"
    assert by_label["Coordinates"] == "-6.2, 106.8"
    assert by_label["Operator"] == "Cloudflare, Inc. (AS13335)"
    # Network and reverse DNS are network-reachable values, so they're
    # defanged like any other indicator that gets shared around.
    assert by_label["Network"] == "203[.]0[.]113[.]0/24"
    assert "example[.]invalid" in by_label["Reverse DNS"]


def test_describe_for_a_non_public_address_is_just_the_reason():
    rows = PlagGeo.describe({"note": "private address - no public geolocation"})
    assert rows == [{"label": "Note", "value": "private address - no public geolocation"}]


def test_describe_for_nothing_is_empty():
    assert PlagGeo.describe(None) == []
    assert PlagGeo.describe({}) == []
