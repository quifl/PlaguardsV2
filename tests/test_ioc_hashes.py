from plaguardsv2.GuardModules import PlagGrep as ioc_extractor

# These are the well-known hashes of the empty string - placeholders, not
# tied to any real sample.
_MD5_EMPTY = "d41d8cd98f00b204e9800998ecf8427e"
_SHA1_EMPTY = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
_SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _values_of(findings, type_):
    return {f.value for f in findings if f.type == type_}


def test_extracts_md5_hash():
    findings = ioc_extractor.scan("", _MD5_EMPTY)
    assert _MD5_EMPTY in _values_of(findings, "hash_md5")


def test_extracts_sha1_hash():
    findings = ioc_extractor.scan("", _SHA1_EMPTY)
    assert _SHA1_EMPTY in _values_of(findings, "hash_sha1")


def test_extracts_sha256_hash():
    findings = ioc_extractor.scan("", _SHA256_EMPTY)
    assert _SHA256_EMPTY in _values_of(findings, "hash_sha256")


def test_hash_lengths_do_not_overlap():
    text = f"{_MD5_EMPTY} {_SHA1_EMPTY} {_SHA256_EMPTY}"
    findings = ioc_extractor.scan("", text)
    assert len(_values_of(findings, "hash_md5")) == 1
    assert len(_values_of(findings, "hash_sha1")) == 1
    assert len(_values_of(findings, "hash_sha256")) == 1
