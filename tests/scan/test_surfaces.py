"""Per-surface scanners: parse tolerantly, count every skip, hide nothing.

THREAT-MODEL §5 -- a parser that silently drops a malformed plist reports
false confidence. Every test here asserts both halves: what was parsed AND
what was skipped.
"""

import pytest

from lastrites.scan.surfaces import envfile, launchd
from lastrites.scan.surfaces import crontab as crontab_surface

from .conftest import SHARED_TOKEN


def keys_of(scan):
    return {candidate.key for candidate in scan.candidates}


# --- crontab ------------------------------------------------------------


@pytest.fixture
def crontab_scan(estate):
    return crontab_surface.scan_file(estate / "crontab.txt")


def test_crontab_extracts_env_assignments_and_inline_command_assignments(crontab_scan):
    assert "CLOUDFLARE_API_TOKEN" in keys_of(crontab_scan)
    assert "BACKUP_WEBHOOK_SECRET" in keys_of(crontab_scan)


def test_crontab_screens_out_the_boring_env_assignments(crontab_scan):
    assert {"PATH", "SHELL", "MAILTO"}.isdisjoint(keys_of(crontab_scan))


def test_crontab_counts_malformed_lines_instead_of_raising(crontab_scan):
    assert crontab_scan.skip_count == 2
    reasons = " ".join(skip.reason for skip in crontab_scan.skips)
    assert "cron" in reasons.lower()


def test_crontab_skips_carry_a_locator_pointing_at_the_offending_line(crontab_scan):
    assert all(":" in skip.locator for skip in crontab_scan.skips)


def test_crontab_comments_and_blanks_are_not_counted_as_skips(crontab_scan):
    """A comment is not a parse failure; counting it would drown the signal."""
    assert crontab_scan.skip_count == 2


def test_crontab_candidate_locators_name_the_file_and_line(crontab_scan, estate):
    token = next(c for c in crontab_scan.candidates if c.value == SHARED_TOKEN)
    assert str(estate / "crontab.txt") in token.locator
    assert token.surface == "crontab"


def test_crontab_finds_a_secret_passed_as_a_command_line_flag():
    """`--token=` in a cron command is a mainstream way to leak a credential
    into the process table, and is exactly the forgotten copy the graph exists
    to find."""
    scan = crontab_surface.scan_text(
        "0 3 * * * /usr/bin/curl --token=mock-secret-abc123xyz789def https://mock.invalid\n",
        "/mock/crontab",
    )
    assert "token" in keys_of(scan)
    assert scan.skip_count == 0


def test_crontab_does_not_mistake_a_path_fragment_for_an_assignment():
    scan = crontab_surface.scan_text(
        "0 3 * * * /usr/bin/report --out=/var/log/mock.log\n", "/mock/crontab"
    )
    assert scan.candidates == []


def test_a_bare_special_schedule_with_no_command_is_a_named_skip():
    scan = crontab_surface.scan_text("@reboot\n", "/mock/crontab")
    assert scan.skip_count == 1
    assert "command" in scan.skips[0].reason


# --- launchd plist ------------------------------------------------------


@pytest.fixture
def plist_scan(estate):
    return launchd.scan_file(estate / "com.mock.agent.plist")


def test_plist_extracts_environment_variables(plist_scan):
    assert "CLOUDFLARE_API_TOKEN" in keys_of(plist_scan)
    assert "MOCK_SERVICE_KEY" in keys_of(plist_scan)


def test_plist_screens_out_path(plist_scan):
    assert "PATH" not in keys_of(plist_scan)


def test_plist_ignores_non_string_environment_values_without_skipping(plist_scan):
    """An <integer> in EnvironmentVariables cannot hold a secret."""
    assert "StartCount" not in keys_of(plist_scan)
    assert plist_scan.skip_count == 0


def test_plist_locator_names_the_environment_variables_block(plist_scan):
    token = next(c for c in plist_scan.candidates if c.value == SHARED_TOKEN)
    assert "EnvironmentVariables" in token.locator
    assert token.surface == "launchd-plist"


def test_malformed_plist_is_counted_not_raised(estate):
    scan = launchd.scan_file(estate / "com.mock.broken.plist")
    assert scan.candidates == []
    assert scan.skip_count == 1
    assert "parse" in scan.skips[0].reason.lower()


def test_plist_with_non_dict_environment_block_is_counted_not_raised(estate):
    scan = launchd.scan_file(estate / "com.mock.badenv.plist")
    assert scan.candidates == []
    assert scan.skip_count == 1


def test_unreadable_file_is_a_counted_skip_not_a_crash(estate):
    scan = launchd.scan_file(estate / "does-not-exist.plist")
    assert scan.skip_count == 1
    assert scan.candidates == []


# --- env file -----------------------------------------------------------


@pytest.fixture
def env_scan(estate):
    return envfile.scan_file(estate / "app.env")


def test_env_file_handles_export_prefix_and_quoted_values(env_scan):
    token = next(c for c in env_scan.candidates if c.key == "CLOUDFLARE_API_TOKEN")
    assert token.value == f'"{SHARED_TOKEN}"'


def test_env_file_extracts_the_password_and_drops_the_settings(env_scan):
    assert "DATABASE_PASSWORD" in keys_of(env_scan)
    assert {"NODE_ENV", "LOG_LEVEL"}.isdisjoint(keys_of(env_scan))


def test_env_file_counts_all_three_malformed_lines(env_scan):
    assert env_scan.skip_count == 3
    assert len(env_scan.skips) == 3


def test_env_file_skip_reasons_are_specific(env_scan):
    reasons = [skip.reason for skip in env_scan.skips]
    assert any("assignment" in r for r in reasons)
    assert any("identifier" in r for r in reasons)


def test_env_scan_records_its_surface_and_source(env_scan, estate):
    assert env_scan.surface == "env-file"
    assert env_scan.source == str(estate / "app.env")
