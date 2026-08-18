"""Canarying every registered credential in one sweep pass.

One bad registration must never abort the ones queued behind it -- the
same containment philosophy as `scan/estate.py`'s `_guarded`.
"""

from __future__ import annotations

import pytest

from lastrites.canary.transport import ProbeResponse, ProbeTimeout
from lastrites.core.fingerprint import fingerprint
from lastrites.core.store import GraphStore
from lastrites.sweep.canary_all import canary_all
from lastrites.sweep.registry import CredentialRegistration

PEPPER = b"\x55" * 32
SECRET = "mock-secret-value-for-sweep-tests"


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "graph.sqlite3"
    s = GraphStore(db)
    yield s
    s.close()


def _seed(store, secret=SECRET, provider="cloudflare"):
    fp = fingerprint(PEPPER, secret)
    store.add_credential(
        fp, kind="api-token", rotation_class="unknown", provider=provider
    )
    return fp


def _alive_transport(request, timeout=None):
    return ProbeResponse(status=200, body=b'{"success":true}')


def _dead_transport(request, timeout=None):
    return ProbeResponse(status=401, body=b"")


def test_alive_registration_records_evidence_and_updates_last_verified(
    store, monkeypatch
):
    fp = _seed(store)
    monkeypatch.setenv("SWEEP_TEST_VALUE", SECRET)
    registration = CredentialRegistration(
        fingerprint_prefix=fp[:12], provider="cloudflare", value_env="SWEEP_TEST_VALUE"
    )

    result = canary_all(store, PEPPER, [registration], transport=_alive_transport)

    assert result.runs == [type(result.runs[0])(fp, "cloudflare", "alive")]
    assert result.skips == []
    evidence = store.list_canary_evidence(fp)
    assert len(evidence) == 1
    assert evidence[0]["verdict"] == "alive"
    assert store.get_credential(fp)["last_verified"] is not None


def test_dead_registration_records_evidence_without_last_verified(store, monkeypatch):
    fp = _seed(store)
    monkeypatch.setenv("SWEEP_TEST_VALUE", SECRET)
    registration = CredentialRegistration(
        fingerprint_prefix=fp[:12], provider="cloudflare", value_env="SWEEP_TEST_VALUE"
    )

    result = canary_all(store, PEPPER, [registration], transport=_dead_transport)

    assert result.runs[0].verdict == "dead"
    assert store.get_credential(fp)["last_verified"] is None


def test_missing_env_var_is_skipped_not_raised(store):
    fp = _seed(store)
    registration = CredentialRegistration(
        fingerprint_prefix=fp[:12], provider="cloudflare", value_env="NOT_SET_VAR"
    )

    result = canary_all(store, PEPPER, [registration], transport=_alive_transport)

    assert result.runs == []
    assert len(result.skips) == 1
    assert "NOT_SET_VAR" in result.skips[0].reason


def test_value_mismatch_is_skipped(store, monkeypatch):
    fp = _seed(store)
    monkeypatch.setenv("SWEEP_TEST_VALUE", "totally-wrong-value")
    registration = CredentialRegistration(
        fingerprint_prefix=fp[:12], provider="cloudflare", value_env="SWEEP_TEST_VALUE"
    )

    result = canary_all(store, PEPPER, [registration], transport=_alive_transport)

    assert result.runs == []
    assert len(result.skips) == 1
    assert "match" in result.skips[0].reason


def test_unknown_provider_is_skipped(store, monkeypatch):
    fp = _seed(store)
    monkeypatch.setenv("SWEEP_TEST_VALUE", SECRET)
    registration = CredentialRegistration(
        fingerprint_prefix=fp[:12],
        provider="not-a-real-provider",
        value_env="SWEEP_TEST_VALUE",
    )

    result = canary_all(store, PEPPER, [registration], transport=_alive_transport)

    assert result.runs == []
    assert len(result.skips) == 1


def test_no_matching_credential_is_skipped(store, monkeypatch):
    monkeypatch.setenv("SWEEP_TEST_VALUE", SECRET)
    registration = CredentialRegistration(
        fingerprint_prefix="deadbeefdead",
        provider="cloudflare",
        value_env="SWEEP_TEST_VALUE",
    )

    result = canary_all(store, PEPPER, [registration], transport=_alive_transport)

    assert result.runs == []
    assert len(result.skips) == 1


def test_ambiguous_prefix_is_skipped(store, monkeypatch):
    fp1 = fingerprint(PEPPER, "value-one")
    fp2 = fp1[:20] + ("0" if fp1[20] != "0" else "1") + fp1[21:]
    store.add_credential(
        fp1, kind="api-token", rotation_class="unknown", provider="cloudflare"
    )
    store.add_credential(
        fp2, kind="api-token", rotation_class="unknown", provider="cloudflare"
    )
    monkeypatch.setenv("SWEEP_TEST_VALUE", "value-one")
    registration = CredentialRegistration(
        fingerprint_prefix=fp1[:20], provider="cloudflare", value_env="SWEEP_TEST_VALUE"
    )

    result = canary_all(store, PEPPER, [registration], transport=_alive_transport)

    assert result.runs == []
    assert len(result.skips) == 1


def test_one_bad_registration_does_not_block_the_rest(store, monkeypatch):
    good_fp = _seed(store, secret=SECRET)
    monkeypatch.setenv("GOOD_VALUE", SECRET)
    bad_registration = CredentialRegistration(
        fingerprint_prefix="deadbeefdead", provider="cloudflare", value_env="GOOD_VALUE"
    )
    good_registration = CredentialRegistration(
        fingerprint_prefix=good_fp[:12], provider="cloudflare", value_env="GOOD_VALUE"
    )

    result = canary_all(
        store, PEPPER, [bad_registration, good_registration], transport=_alive_transport
    )

    assert len(result.skips) == 1
    assert len(result.runs) == 1
    assert result.runs[0].fingerprint == good_fp


def test_counts_tally_by_verdict(store, monkeypatch):
    alive_fp = _seed(store, secret="alive-secret")
    dead_fp = _seed(store, secret="dead-secret")
    monkeypatch.setenv("ALIVE_VALUE", "alive-secret")
    monkeypatch.setenv("DEAD_VALUE", "dead-secret")

    def transport(request, timeout=None):
        if "alive" in request.headers.get("Authorization", ""):
            return ProbeResponse(status=200, body=b'{"success":true}')
        return ProbeResponse(status=401, body=b"")

    registrations = [
        CredentialRegistration(
            fingerprint_prefix=alive_fp[:12],
            provider="cloudflare",
            value_env="ALIVE_VALUE",
        ),
        CredentialRegistration(
            fingerprint_prefix=dead_fp[:12],
            provider="cloudflare",
            value_env="DEAD_VALUE",
        ),
    ]
    result = canary_all(store, PEPPER, registrations, transport=transport)

    assert result.counts == {"alive": 1, "dead": 1, "unobservable": 0}


def test_unobservable_on_timeout_is_recorded_not_skipped(store, monkeypatch):
    fp = _seed(store)
    monkeypatch.setenv("SWEEP_TEST_VALUE", SECRET)
    registration = CredentialRegistration(
        fingerprint_prefix=fp[:12], provider="cloudflare", value_env="SWEEP_TEST_VALUE"
    )

    def raise_timeout(request, timeout=None):
        raise ProbeTimeout("timed out")

    result = canary_all(store, PEPPER, [registration], transport=raise_timeout)

    assert result.skips == []
    assert result.runs[0].verdict == "unobservable"
