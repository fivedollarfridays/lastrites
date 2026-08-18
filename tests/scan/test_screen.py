"""The candidate screen: entropy + key-name hints, tuned to over-collect.

Over-collecting is the safe direction (a false candidate costs a wasted
fingerprint; a missed one is a copy the graph never learns about), but
"over-collect" is not "collect everything" -- a scan that flags PATH as a
secret trains its operator to ignore it. Both directions are pinned here.
"""

import math

import pytest

from lastrites.scan.entropy import shannon_entropy
from lastrites.scan.screen import screen_candidate

# --- Shannon entropy ---------------------------------------------------


def test_entropy_of_a_single_repeated_character_is_zero():
    assert shannon_entropy("aaaaaaaaaaaa") == 0.0


def test_entropy_of_a_uniform_alphabet_is_log2_of_its_size():
    assert shannon_entropy("abcd" * 4) == pytest.approx(math.log2(4))


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_random_hex_scores_above_english_prose():
    assert shannon_entropy("9f3a2b7c1d5e8a4f6b0c") > shannon_entropy("configuration")


# --- the screen, direction 1: non-secrets stay out ----------------------

NON_SECRETS = [
    ("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin"),
    ("SHELL", "/bin/sh"),
    ("HOME", "/Users/mockuser"),
    ("MAILTO", "ops@example.invalid"),
    ("NODE_ENV", "production"),
    ("LOG_LEVEL", "debug"),
    ("AWS_REGION", "us-east-1"),
    ("RETRY_COUNT", "5"),
    ("BUILD_LABEL", "aaaaaaaaaaaaaaaaaaaaaa"),
    ("DESCRIPTION", "the quick brown fox jumps over it"),
    ("BACKUP_DIR", "/var/backups/nightly/archive"),
]


@pytest.mark.parametrize("key,value", NON_SECRETS, ids=[k for k, _ in NON_SECRETS])
def test_low_entropy_non_secrets_are_excluded(key, value):
    result = screen_candidate(key, value)
    assert not result.accepted
    assert result.reason, "a rejection must name its reason -- silent drops are the bug"


# --- the screen, direction 2: real-shaped secrets get collected ---------

SECRETS = [
    # key-name hint carries it even when the value is shortish
    ("CLOUDFLARE_API_TOKEN", "mock-cf-7f3a2b91c4"),
    ("DATABASE_PASSWORD", "mock-pw-9c2e5a81f7b04d63"),
    ("SIGNING_SECRET", "mock-sg-4d81b7e05a2c6f39"),
    # no hint in the key at all -- entropy alone has to carry it
    ("WIDGET_BLOB", "mock-8f4a1c6e9b2d7503aefb1c8d4620937e"),
    ("X7", "mock-3b91d75c0e28a6f4b1d093e7c25a8f60"),
]


@pytest.mark.parametrize("key,value", SECRETS, ids=[k for k, _ in SECRETS])
def test_high_entropy_and_hinted_values_are_collected(key, value):
    assert screen_candidate(key, value).accepted


def test_a_non_secret_key_name_beats_a_high_entropy_value():
    """PATH is PATH even when it is long and varied."""
    long_path = "/usr/local/bin:/opt/homebrew/sbin:/Users/mockuser/.cargo/bin"
    assert not screen_candidate("PATH", long_path).accepted


# --- an explicit key name outranks the shape heuristics ----------------


def test_a_hinted_key_survives_a_value_that_starts_like_a_path():
    """Base64 secrets begin with '/' about one time in 64. AWS's do."""
    result = screen_candidate(
        "AWS_SECRET_ACCESS_KEY", "/wJalrXUtnFEMImockK7MDENGbPxRfiCY"
    )
    assert result.accepted


def test_a_hinted_key_survives_a_value_below_the_length_floor():
    assert screen_candidate("DB_PASSWORD", "mock-pw12").accepted


def test_a_hinted_key_does_not_rescue_an_empty_value():
    """Empty values would all fingerprint alike and cluster into one lie."""
    assert not screen_candidate("DB_PASSWORD", "").accepted
    assert not screen_candidate("DB_PASSWORD", '""').accepted


@pytest.mark.parametrize(
    "key", ["SSH_KEY_PATH", "TLS_CERT_FILE", "SECRET_DIR", "CREDENTIALS_FILE"]
)
def test_a_key_that_names_a_location_is_not_rescued_by_its_hint(key):
    """`SSH_KEY_PATH=/home/mockuser/.ssh/id_rsa` is a path, not the key."""
    assert not screen_candidate(key, "/home/mockuser/.ssh/id_rsa").accepted


def test_a_non_secret_key_still_beats_a_hint():
    assert not screen_candidate("PATH", "/usr/local/bin:/usr/bin").accepted


# --- what the hint must NOT buy ----------------------------------------
#
# A hint that bypasses every shape rule is worse than no hint at all. Config
# literals are shared across unrelated machines and files, so collecting them
# does not merely add noise -- identical values fingerprint identically and
# CLUSTER, manufacturing a fake credential whose copy count outranks every
# real one. The blast-radius signal ends up inverted.

HINTED_NON_SECRETS = [
    ("AUTH_ENABLED", "true"),
    ("FEATURE_AUTH", "false"),
    ("SESSION_TIMEOUT", "3600"),
    ("TOKEN_REFRESH_SECONDS", "86400"),
    ("SESSION_STORE", "none"),
    ("AUTH_MODE", "default"),
    ("SSH_AUTH_SOCK", "/private/tmp/com.apple.launchd.7cJmock/Listeners"),
    ("SESSION_MANAGER", "local/host:@/tmp/.ICE-unix/1234"),
]


@pytest.mark.parametrize(
    "key,value", HINTED_NON_SECRETS, ids=[k for k, _ in HINTED_NON_SECRETS]
)
def test_a_hint_does_not_rescue_a_configuration_literal(key, value):
    assert not screen_candidate(key, value).accepted


def test_two_unrelated_config_settings_do_not_become_one_credential(
    estate, pepper, tmp_path
):
    """The concrete harm, pinned end to end: shared literals must not cluster."""
    from lastrites.scan.estate import scan_estate

    for name, keys in (("a.env", "AUTH_ENABLED"), ("b.env", "FEATURE_AUTH")):
        (tmp_path / name).write_text(f"{keys}=true\nSESSION_TIMEOUT=3600\n")

    report = scan_estate(pepper, env_files=[tmp_path / "a.env", tmp_path / "b.env"])
    assert report.credentials == []


def test_hint_matching_respects_word_boundaries():
    """`AUTHOR` is not `AUTH`; `MONKEY` is not `KEY`."""
    assert not screen_candidate("AUTHOR", "Kevin Masterson").accepted
    assert not screen_candidate("MONKEY_COUNT", "17").accepted


def test_structured_json_secret_survives_the_whitespace_rule():
    blob = '{\n  "type": "service_account",\n  "private_key": "mock-pk-8a3f2c9d1b"\n}'
    # Deliberately an unhinted key name, so only the JSON exemption can save it.
    assert screen_candidate("SERVICE_ACCOUNT_BLOB", blob).accepted
