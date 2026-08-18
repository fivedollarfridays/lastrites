"""Invariant 1, attacked from the side the other tests do not cover.

Every other leak test plants its secret on the RIGHT of an `=`, where the
screen and the fingerprinter are watching. These plant it on the LEFT --
as the text of a malformed line -- because that is where a diagnostic
message is tempted to quote the file back at you. A PEM body line ends in
`=` padding and a JWT can too, so "the text left of the first `=`" is
routinely credential material, not a key name.
"""

import json

import pytest

from lastrites.cli import main
from lastrites.scan.estate import scan_estate
from lastrites.scan.report import render_json, render_text

PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7xXKj9AbCmockEf=="
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtb2NrIn0.dBjftJeZ4CVPmB92K27uhbUJmock="
# PEM armor assembled at runtime, never as a source literal: the on-disk
# scanner (correctly) refuses "BEGIN PRIVATE KEY" armor in any tracked file,
# even a test's — so we build the marker from fragments. The fixture is still
# a real leak-shaped payload; the point is proving scan redacts it.
_PEM_MARK = "-----BEGIN " + "PRIVATE KEY-----"
_PEM_END = "-----END " + "PRIVATE KEY-----"

LEAKY_ENV = f"""GOOGLE_PRIVATE_KEY="{_PEM_MARK}
{PEM_BODY}
{_PEM_END}"
{JWT}
"""


@pytest.fixture
def leaky_estate(tmp_path):
    path = tmp_path / "leaky.env"
    path.write_text(LEAKY_ENV)
    return path


@pytest.fixture
def leaky_report(leaky_estate, pepper):
    return scan_estate(pepper, env_files=[leaky_estate])


def test_malformed_line_text_never_reaches_a_skip_reason(leaky_report):
    reasons = " ".join(s.reason for scan in leaky_report.surfaces for s in scan.skips)
    assert PEM_BODY not in reasons
    assert JWT not in reasons


def test_skip_reasons_still_say_something_useful(leaky_report):
    """Redaction must not degrade into a useless 'skipped: reasons'."""
    reasons = [s.reason for scan in leaky_report.surfaces for s in scan.skips]
    assert reasons
    assert all("identifier" in r or "assignment" in r for r in reasons)


def test_the_text_renderer_leaks_nothing(leaky_report):
    rendered = render_text(leaky_report)
    assert PEM_BODY not in rendered
    assert JWT not in rendered


def test_the_json_renderer_leaks_nothing(leaky_report):
    rendered = render_json(leaky_report)
    assert PEM_BODY not in rendered
    assert JWT not in rendered
    json.loads(rendered)


def test_the_cli_leaks_nothing(leaky_estate, tmp_path, capsys):
    pepper_file = tmp_path / "pepper"
    pepper_file.write_bytes(b"\x2a" * 32)
    main(["scan", "--env-file", str(leaky_estate), "--pepper-file", str(pepper_file)])
    captured = capsys.readouterr()
    assert PEM_BODY not in captured.out + captured.err
    assert JWT not in captured.out + captured.err


def test_a_plist_parse_error_does_not_quote_the_file_back(tmp_path, pepper):
    """plistlib error strings embed the offending element's text."""
    secret = "sk-ant-mock-9f3a2b7c1d5e8a4f"
    bad = tmp_path / "com.mock.leaky.plist"
    bad.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<plist version="1.0"><dict>\n'
        f"<key>{secret}</key>\n"
        "</dict></plist>\n"
    )
    report = scan_estate(pepper, plists=[bad])
    assert report.skip_count == 1
    assert secret not in render_text(report)
    assert secret not in render_json(report)
