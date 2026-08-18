import hashlib
import inspect
import json
import re

import pytest

from lastrites.core.canonicalize import canonicalize
from lastrites.core.fingerprint import fingerprint

PEPPER = b"\x11" * 32
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


# --- plain canonicalizer -----------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("abc123", "abc123"),
        ("  abc123  ", "abc123"),
        ('"abc123"', "abc123"),
        ("'abc123'", "abc123"),
        ('  "abc123"  ', "abc123"),
    ],
)
def test_plain_canonicalizer_strips_quotes_and_whitespace(raw, expected):
    assert canonicalize(raw, fmt="plain") == expected


# --- structured secret (JSON service account) canonicalizer -------------


def test_json_canonicalizer_is_stable_across_reserialization():
    service_account = {
        "type": "service_account",
        "project_id": "mock-project",
        "private_key": "mock-private-key-material-not-a-real-pem",
        "client_email": "mock@mock-project.iam.gserviceaccount.com",
    }
    pretty = json.dumps(service_account, indent=2, sort_keys=False)
    compact_reordered = json.dumps(
        dict(reversed(list(service_account.items()))), separators=(",", ":")
    )

    assert canonicalize(pretty, fmt="json") == canonicalize(
        compact_reordered, fmt="json"
    )


# --- fingerprint: HMAC-SHA256, peppered, clusters identical values ------


def test_fingerprint_is_hmac_sha256_hex_digest():
    fp = fingerprint(PEPPER, "abc123")
    assert HEX_64.match(fp)


def test_fingerprint_clusters_identical_values_across_surface_formats():
    a = fingerprint(PEPPER, "abc123", fmt="plain")
    b = fingerprint(PEPPER, "  abc123  ", fmt="plain")
    c = fingerprint(PEPPER, '"abc123"', fmt="plain")
    d = fingerprint(PEPPER, "'abc123'", fmt="plain")

    assert a == b == c == d


def test_fingerprint_clusters_reserialized_structured_secrets():
    service_account = {
        "type": "service_account",
        "project_id": "mock",
        "private_key": "FAKE",
    }
    pretty = json.dumps(service_account, indent=4, sort_keys=False)
    compact = json.dumps(service_account, separators=(",", ":"), sort_keys=True)

    fp_pretty = fingerprint(PEPPER, pretty, fmt="json")
    fp_compact = fingerprint(PEPPER, compact, fmt="json")

    assert fp_pretty == fp_compact


def test_fingerprint_depends_on_pepper():
    other_pepper = b"\x22" * 32
    assert fingerprint(PEPPER, "abc123") != fingerprint(other_pepper, "abc123")


def test_fingerprint_is_not_a_bare_hash():
    value = "supersecret123"
    fp = fingerprint(PEPPER, value)
    bare_sha256 = hashlib.sha256(value.encode("utf-8")).hexdigest()

    assert fp != bare_sha256


def test_no_bare_hash_path_in_fingerprint_source():
    """hashlib.sha256 may only appear as the digestmod argument to hmac.new."""
    source = inspect.getsource(__import__("lastrites.core.fingerprint", fromlist=["_"]))
    for line in source.splitlines():
        if "hashlib.sha" in line or "hashlib.md5" in line:
            assert "hmac.new(" in line, f"bare hash usage found: {line!r}"
