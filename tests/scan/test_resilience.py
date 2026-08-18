"""One damaged file must not take the estate scan down with it.

THREAT-MODEL §5's failure mode at maximum blast radius: a scanner that
raises on surface 3 of 40 discards the 2 it already read AND the 37 it
never reached, and reports nothing at all. Tolerant parsing has to hold at
the orchestration level too, not just inside each parser.
"""

import pytest

from lastrites.scan import estate as estate_module
from lastrites.scan.estate import scan_estate


def test_an_unexpected_scanner_crash_degrades_to_a_counted_skip(
    monkeypatch, estate, pepper
):
    def explode(path):
        raise AttributeError("simulated: 'int' object has no attribute 'upper'")

    monkeypatch.setattr(estate_module.launchd, "scan_file", explode)
    report = scan_estate(
        pepper,
        crontabs=[estate / "crontab.txt"],
        plists=[estate / "com.mock.agent.plist"],
        env_files=[estate / "app.env"],
    )

    # The crontab and env file still got scanned and still cluster.
    assert report.surface_count == 3
    assert any(scan.surface == "crontab" for scan in report.surfaces)
    assert report.credentials


def test_the_crash_is_reported_not_swallowed(monkeypatch, estate, pepper):
    monkeypatch.setattr(
        estate_module.launchd,
        "scan_file",
        lambda path: (_ for _ in ()).throw(RuntimeError("x")),
    )
    report = scan_estate(pepper, plists=[estate / "com.mock.agent.plist"])

    assert report.skip_count == 1
    assert "RuntimeError" in report.surfaces[0].skips[0].reason


def test_a_crashed_surface_is_marked_unreadable(monkeypatch, estate, pepper):
    monkeypatch.setattr(
        estate_module.launchd,
        "scan_file",
        lambda path: (_ for _ in ()).throw(RuntimeError("x")),
    )
    report = scan_estate(pepper, plists=[estate / "com.mock.agent.plist"])
    assert report.readable_count == 0


def test_a_crash_message_is_not_quoted_into_the_report(monkeypatch, estate, pepper):
    """Exception text can carry the value that caused it."""
    secret = "mock-cf-7f3a2b91c4d6e805"
    monkeypatch.setattr(
        estate_module.launchd,
        "scan_file",
        lambda path: (_ for _ in ()).throw(ValueError(f"bad value {secret}")),
    )
    report = scan_estate(pepper, plists=[estate / "com.mock.agent.plist"])
    assert secret not in report.surfaces[0].skips[0].reason


# --- readable vs merely attempted ---------------------------------------


def test_a_readable_surface_counts_as_readable(estate, pepper):
    report = scan_estate(pepper, env_files=[estate / "app.env"])
    assert report.readable_count == 1


def test_an_unopenable_surface_is_attempted_but_not_readable(estate, pepper):
    report = scan_estate(pepper, env_files=[estate / "nope.env"])
    assert report.surface_count == 1
    assert report.readable_count == 0


def test_an_unparseable_plist_is_attempted_but_not_readable(estate, pepper):
    report = scan_estate(pepper, plists=[estate / "com.mock.broken.plist"])
    assert report.readable_count == 0


def test_a_plist_that_is_not_a_launchd_job_was_still_read(estate, pepper, tmp_path):
    """A well-formed plist with an array root parsed perfectly. Calling it
    unreadable would raise the 'saw nothing' alarm over a healthy file."""
    path = tmp_path / "com.mock.array.plist"
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<plist version="1.0"><array><string>mock</string></array></plist>\n'
    )
    report = scan_estate(pepper, plists=[path])
    assert report.readable_count == 1
    assert report.skip_count == 1


def test_a_plist_with_a_bad_env_block_was_still_read(estate, pepper):
    """The file parsed fine; one block inside it did not. That is a skip,
    not a failure to read the surface."""
    report = scan_estate(pepper, plists=[estate / "com.mock.badenv.plist"])
    assert report.readable_count == 1
    assert report.skip_count == 1


@pytest.mark.parametrize("payload", [b"\x00\x01\x02\xff\xfe", b""])
def test_binary_and_empty_files_do_not_raise(tmp_path, pepper, payload):
    path = tmp_path / "weird.env"
    path.write_bytes(payload)
    report = scan_estate(pepper, env_files=[path])
    assert report.surface_count == 1
