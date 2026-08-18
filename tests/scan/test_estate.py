"""The whole-estate scan: three surfaces, one report, nothing hidden."""

import pytest

from lastrites.core.fingerprint import fingerprint
from lastrites.scan.blindspots import DEFAULT_BLIND_SPOTS
from lastrites.scan.estate import scan_estate

from .conftest import SHARED_TOKEN


@pytest.fixture
def report(estate, pepper):
    return scan_estate(
        pepper,
        crontabs=[estate / "crontab.txt"],
        plists=[
            estate / "com.mock.agent.plist",
            estate / "com.mock.broken.plist",
            estate / "com.mock.badenv.plist",
        ],
        env_files=[estate / "app.env"],
    )


# --- the clustering acceptance criterion, end to end --------------------


def test_the_planted_token_clusters_across_all_three_surfaces(report, pepper):
    target = fingerprint(pepper, SHARED_TOKEN)
    credential = next(c for c in report.credentials if c.fingerprint == target)

    assert len(credential.copies) == 3
    assert {copy.surface for copy in credential.copies} == {
        "crontab",
        "launchd-plist",
        "env-file",
    }
    assert credential.provider == "cloudflare"


def test_surface_local_secrets_stay_separate_credentials(report):
    """Three distinct mock values planted once each, plus the shared one."""
    assert len(report.credentials) == 4


# --- skip accounting ----------------------------------------------------


def test_skips_are_totalled_across_every_surface(report):
    # 2 malformed crontab lines + 1 broken plist + 1 non-dict env block
    # + 3 malformed env-file lines
    assert report.skip_count == 7


def test_every_skip_is_attributable_to_a_surface(report):
    per_surface = sum(scan.skip_count for scan in report.surfaces)
    assert per_surface == report.skip_count


def test_surface_count_is_the_number_of_surfaces_attempted(report):
    assert report.surface_count == 5


def test_an_unopenable_file_still_counts_as_an_attempted_surface(estate, pepper):
    """Dropping it would quietly shrink the denominator of the coverage claim."""
    missing = scan_estate(pepper, env_files=[estate / "nope.env"])
    assert missing.surface_count == 1
    assert missing.skip_count == 1


def test_a_scan_that_opened_nothing_reports_zero_surfaces(pepper):
    empty = scan_estate(pepper)
    assert empty.surface_count == 0
    assert empty.credentials == []


# --- blind spots --------------------------------------------------------


def test_blind_spots_are_always_reported_never_omitted(report):
    assert report.blind_spots
    assert len(report.blind_spots) == len(DEFAULT_BLIND_SPOTS)


def test_every_blind_spot_is_named_and_explained(report):
    for spot in report.blind_spots:
        assert spot.name
        assert spot.detail


def test_the_keychain_blind_spot_is_declared(report):
    """THREAT-MODEL: 'secrets it cannot see' has to be said out loud."""
    assert any("keychain" in spot.name for spot in report.blind_spots)


def test_an_empty_scan_still_declares_its_blind_spots(pepper):
    """Zero findings plus zero caveats would read as a clean estate."""
    assert scan_estate(pepper).blind_spots


# --- the report holds fingerprints, never values ------------------------


def test_the_report_never_carries_a_raw_value(report):
    assert SHARED_TOKEN not in repr(report.credentials)
