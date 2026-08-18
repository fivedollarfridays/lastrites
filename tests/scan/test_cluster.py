"""Clustering: identical fingerprints across surfaces are one credential.

This is the load-bearing trick of the whole graph (DESIGN §Discovery) --
it finds the copy you forgot, without anyone maintaining a registry.
"""

from lastrites.core.fingerprint import fingerprint
from lastrites.scan.cluster import cluster_candidates
from lastrites.scan.models import Candidate

from .conftest import SHARED_TOKEN


def candidate(key, value, surface, locator, fmt="plain"):
    return Candidate(key=key, value=value, surface=surface, locator=locator, fmt=fmt)


def three_surface_copies():
    """The same mock token, written the way each surface would write it."""
    return [
        candidate("CLOUDFLARE_API_TOKEN", SHARED_TOKEN, "crontab", "/mock/crontab:6"),
        candidate(
            "CLOUDFLARE_API_TOKEN",
            SHARED_TOKEN,
            "launchd-plist",
            "/mock/com.mock.agent.plist:EnvironmentVariables/CLOUDFLARE_API_TOKEN",
        ),
        # env files quote; canonicalization has to see through that
        candidate(
            "CLOUDFLARE_API_TOKEN", f'"{SHARED_TOKEN}"', "env-file", "/mock/app.env:2"
        ),
    ]


def test_one_value_on_three_surfaces_is_one_credential_with_three_edges(pepper):
    credentials = cluster_candidates(three_surface_copies(), pepper)

    assert len(credentials) == 1
    assert len(credentials[0].copies) == 3
    assert {copy.surface for copy in credentials[0].copies} == {
        "crontab",
        "launchd-plist",
        "env-file",
    }


def test_the_cluster_key_is_the_peppered_fingerprint(pepper):
    credentials = cluster_candidates(three_surface_copies(), pepper)
    assert credentials[0].fingerprint == fingerprint(pepper, SHARED_TOKEN)


def test_distinct_values_do_not_cluster(pepper):
    candidates = [
        candidate("A_TOKEN", "mock-aa-1c9e4b70d258a3f6", "env-file", "/mock/a.env:1"),
        candidate("B_TOKEN", "mock-bb-7d20f6c85a91e34b", "env-file", "/mock/b.env:1"),
    ]
    assert len(cluster_candidates(candidates, pepper)) == 2


def test_the_same_value_twice_in_one_file_is_two_copies_of_one_credential(pepper):
    dupes = [
        candidate("TOKEN_A", SHARED_TOKEN, "env-file", "/mock/app.env:2"),
        candidate("TOKEN_B", SHARED_TOKEN, "env-file", "/mock/app.env:9"),
    ]
    credentials = cluster_candidates(dupes, pepper)
    assert len(credentials) == 1
    assert len(credentials[0].copies) == 2


def test_clustered_credential_carries_the_classification(pepper):
    credentials = cluster_candidates(three_surface_copies(), pepper)
    assert credentials[0].provider == "cloudflare"
    assert credentials[0].kind == "api-token"


def test_a_named_copy_lends_its_classification_to_its_anonymous_twins(pepper):
    """One well-named copy documents the credential for every other copy."""
    candidates = [
        candidate("BLOB", SHARED_TOKEN, "env-file", "/mock/a.env:1"),
        candidate("CLOUDFLARE_API_TOKEN", SHARED_TOKEN, "crontab", "/mock/crontab:6"),
    ]
    assert cluster_candidates(candidates, pepper)[0].provider == "cloudflare"


def test_clustering_never_retains_the_raw_value(pepper):
    credentials = cluster_candidates(three_surface_copies(), pepper)
    rendered = repr(credentials)
    assert SHARED_TOKEN not in rendered


def test_copies_carry_the_key_name_and_format_for_the_future_rewriter(pepper):
    copies = cluster_candidates(three_surface_copies(), pepper)[0].copies
    assert all(copy.key == "CLOUDFLARE_API_TOKEN" for copy in copies)
    assert all(copy.fmt == "plain" for copy in copies)


def test_empty_input_clusters_to_nothing(pepper):
    assert cluster_candidates([], pepper) == []
