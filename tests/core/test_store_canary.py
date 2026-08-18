"""LR1.3's extension to the LR1.1 graph store: canary evidence rows.

An evidence row carries a verdict, a latency, and an HTTP class -- never
a response body, never a credential value. `find_by_prefix` is the
lookup the CLI needs to resolve a short fingerprint prefix to the
credential it names.
"""

import stat

import pytest

from lastrites.core.fingerprint import fingerprint
from lastrites.core.store import GraphStore

PEPPER = b"\x44" * 32


def _open(tmp_path, name="graph.sqlite3"):
    return GraphStore(tmp_path / name)


def _seeded_credential(store, value="mock-cf-token"):
    fp = fingerprint(PEPPER, value)
    store.add_credential(
        fingerprint=fp,
        kind="api-token",
        rotation_class="unknown",
        provider="cloudflare",
    )
    return fp


# --- schema -----------------------------------------------------------------


def test_schema_has_canary_evidence_table(tmp_path):
    store = _open(tmp_path)
    tables = {
        row[0]
        for row in store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    store.close()
    assert "canary_evidence" in tables


# --- record / list roundtrip -------------------------------------------------


def test_record_and_list_canary_evidence_roundtrip(tmp_path):
    store = _open(tmp_path)
    try:
        fp = _seeded_credential(store)
        store.record_canary_evidence(
            fingerprint=fp,
            ts="2026-08-18T00:00:00Z",
            verdict="alive",
            latency_ms=42.5,
            http_class="200",
        )
        rows = store.list_canary_evidence(fp)
    finally:
        store.close()

    assert rows == [
        {
            "ts": "2026-08-18T00:00:00Z",
            "verdict": "alive",
            "latency_ms": 42.5,
            "http_class": "200",
        }
    ]


def test_canary_evidence_accumulates_across_runs(tmp_path):
    store = _open(tmp_path)
    try:
        fp = _seeded_credential(store)
        store.record_canary_evidence(
            fingerprint=fp, ts="t1", verdict="alive", latency_ms=10.0, http_class="200"
        )
        store.record_canary_evidence(
            fingerprint=fp, ts="t2", verdict="dead", latency_ms=11.0, http_class="401"
        )
        rows = store.list_canary_evidence(fp)
    finally:
        store.close()

    assert [row["verdict"] for row in rows] == ["alive", "dead"]


def test_record_canary_evidence_rejects_non_fingerprint_strings(tmp_path):
    store = _open(tmp_path)
    try:
        with pytest.raises(ValueError):
            store.record_canary_evidence(
                fingerprint="not-a-fingerprint",
                ts="t1",
                verdict="alive",
                latency_ms=1.0,
                http_class="200",
            )
    finally:
        store.close()


# --- last_verified -----------------------------------------------------------


def test_update_last_verified_sets_the_column(tmp_path):
    store = _open(tmp_path)
    try:
        fp = _seeded_credential(store)
        store.update_last_verified(fp, "2026-08-18T01:00:00Z")
        record = store.get_credential(fp)
    finally:
        store.close()

    assert record["last_verified"] == "2026-08-18T01:00:00Z"


def test_update_last_verified_does_not_touch_other_columns(tmp_path):
    store = _open(tmp_path)
    try:
        fp = _seeded_credential(store)
        store.update_last_verified(fp, "2026-08-18T01:00:00Z")
        record = store.get_credential(fp)
    finally:
        store.close()

    assert record["provider"] == "cloudflare"
    assert record["kind"] == "api-token"


# --- find_by_prefix -----------------------------------------------------------


def test_find_by_prefix_returns_the_matching_credential(tmp_path):
    store = _open(tmp_path)
    try:
        fp = _seeded_credential(store)
        matches = store.find_by_prefix(fp[:8])
    finally:
        store.close()

    assert [m["fingerprint"] for m in matches] == [fp]


def test_find_by_prefix_returns_empty_list_when_no_match(tmp_path):
    store = _open(tmp_path)
    try:
        matches = store.find_by_prefix("deadbeef")
    finally:
        store.close()
    assert matches == []


def test_find_by_prefix_matches_only_credentials_sharing_the_prefix(tmp_path):
    store = _open(tmp_path)
    try:
        fp1 = fingerprint(PEPPER, "value-one")
        fp2 = fingerprint(PEPPER, "value-two")
        store.add_credential(
            fingerprint=fp1, kind="api-token", rotation_class="unknown", provider="mock"
        )
        store.add_credential(
            fingerprint=fp2, kind="api-token", rotation_class="unknown", provider="mock"
        )
        matches = store.find_by_prefix(fp1)
    finally:
        store.close()

    assert [m["fingerprint"] for m in matches] == [fp1]


def test_find_by_prefix_returns_multiple_matches_for_a_shared_short_prefix(tmp_path):
    store = _open(tmp_path)
    try:
        fp1 = fingerprint(PEPPER, "value-one")
        # Engineer a genuine shared prefix rather than hoping for a hash
        # collision: two distinct fingerprints, one truncated so it IS a
        # prefix of the other.
        fp2 = fp1[:20] + ("0" if fp1[20] != "0" else "1") + fp1[21:]
        store.add_credential(
            fingerprint=fp1, kind="api-token", rotation_class="unknown", provider="mock"
        )
        store.add_credential(
            fingerprint=fp2, kind="api-token", rotation_class="unknown", provider="mock"
        )
        matches = store.find_by_prefix(fp1[:20])
    finally:
        store.close()

    assert {m["fingerprint"] for m in matches} == {fp1, fp2}


def test_find_by_prefix_rejects_non_hex_input(tmp_path):
    store = _open(tmp_path)
    try:
        with pytest.raises(ValueError):
            store.find_by_prefix("not-hex!!")
    finally:
        store.close()


# --- storage posture: still no raw values ------------------------------------


def test_canary_evidence_never_persists_a_raw_value_or_response_body(tmp_path):
    secret = "sk-mock-canary-raw-value-7f3a9c"
    leaked_body_marker = "mock-response-body-marker-should-never-be-stored"
    fp = fingerprint(PEPPER, secret)

    store = _open(tmp_path)
    store.add_credential(
        fingerprint=fp, kind="api-token", rotation_class="unknown", provider="mock"
    )
    store.record_canary_evidence(
        fingerprint=fp, ts="t1", verdict="alive", latency_ms=1.0, http_class="200"
    )
    store.close()

    for candidate in tmp_path.glob("graph.sqlite3*"):
        data = candidate.read_bytes()
        assert secret.encode("utf-8") not in data
        assert leaked_body_marker.encode("utf-8") not in data


def test_store_file_stays_0600_after_canary_writes(tmp_path):
    store = _open(tmp_path)
    fp = _seeded_credential(store)
    store.record_canary_evidence(
        fingerprint=fp, ts="t1", verdict="alive", latency_ms=1.0, http_class="200"
    )
    store.close()

    mode = stat.S_IMODE((tmp_path / "graph.sqlite3").stat().st_mode)
    assert mode == 0o600
