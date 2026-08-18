import inspect
import stat

import pytest

from lastrites.core.fingerprint import fingerprint
from lastrites.core.store import GraphStore

PEPPER = b"\x33" * 32
FORBIDDEN_PARAM_NAMES = {
    "value",
    "values",
    "secret",
    "secrets",
    "raw",
    "raw_value",
    "plaintext",
    "body",
    "response_body",
}


def _open(tmp_path, name="graph.sqlite3"):
    return GraphStore(tmp_path / name)


# --- storage posture: perms, WAL, schema --------------------------------


def test_store_file_created_0600(tmp_path):
    store = _open(tmp_path)
    store.close()

    mode = stat.S_IMODE((tmp_path / "graph.sqlite3").stat().st_mode)
    assert mode == 0o600


def test_store_uses_wal_journal_mode(tmp_path):
    store = _open(tmp_path)
    mode = store._conn.execute("PRAGMA journal_mode;").fetchone()[0]
    store.close()

    assert mode.lower() == "wal"


def test_schema_has_expected_tables(tmp_path):
    store = _open(tmp_path)
    tables = {
        row[0]
        for row in store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    store.close()

    assert {"credentials", "consumers", "copied_at", "scans"} <= tables


# --- fingerprint-only API -------------------------------------------------


def test_store_public_api_has_no_raw_value_parameters():
    for name, method in inspect.getmembers(GraphStore, predicate=inspect.isfunction):
        if name.startswith("_"):
            continue
        params = set(inspect.signature(method).parameters)
        overlap = params & FORBIDDEN_PARAM_NAMES
        assert not overlap, (
            f"GraphStore.{name} accepts raw-value-shaped param(s): {overlap}"
        )


def test_add_credential_rejects_non_fingerprint_strings(tmp_path):
    store = _open(tmp_path)
    try:
        with pytest.raises(ValueError):
            store.add_credential(
                fingerprint="password123",
                kind="api-key",
                rotation_class="rotatable",
                provider="mock",
            )
    finally:
        store.close()


def test_add_copied_at_rejects_non_fingerprint_strings(tmp_path):
    store = _open(tmp_path)
    try:
        consumer_id = store.add_consumer(
            machine="laptop", locator="/etc/cron.d/job", fmt="env-assignment"
        )
        with pytest.raises(ValueError):
            store.add_copied_at(
                fingerprint="not-a-fingerprint", consumer_id=consumer_id
            )
    finally:
        store.close()


def test_store_module_never_references_pepper():
    import lastrites.core.store as store_mod

    source = inspect.getsource(store_mod)
    assert "pepper" not in source.lower()


# --- functional roundtrips ------------------------------------------------


def test_add_and_get_credential_roundtrip(tmp_path):
    fp = fingerprint(PEPPER, "abc123")
    store = _open(tmp_path)
    try:
        store.add_credential(
            fingerprint=fp,
            kind="api-key",
            rotation_class="rotatable",
            provider="mock-provider",
        )
        record = store.get_credential(fp)
    finally:
        store.close()

    assert record["fingerprint"] == fp
    assert record["kind"] == "api-key"
    assert record["rotation_class"] == "rotatable"
    assert record["provider"] == "mock-provider"


def test_get_credential_returns_none_when_absent(tmp_path):
    store = _open(tmp_path)
    result = store.get_credential("a" * 64)
    store.close()

    assert result is None


def test_list_credentials_returns_every_row(tmp_path):
    fp1 = fingerprint(PEPPER, "abc123")
    fp2 = fingerprint(PEPPER, "xyz789")
    store = _open(tmp_path)
    try:
        store.add_credential(
            fingerprint=fp1,
            kind="api-key",
            rotation_class="rotatable",
            provider="mock-a",
        )
        store.add_credential(
            fingerprint=fp2, kind="api-key", rotation_class="unknown", provider="mock-b"
        )
        records = store.list_credentials()
    finally:
        store.close()

    assert {r["fingerprint"] for r in records} == {fp1, fp2}


def test_list_credentials_empty_store_returns_empty_list(tmp_path):
    store = _open(tmp_path)
    records = store.list_credentials()
    store.close()

    assert records == []


def test_add_consumer_and_copied_at_edge_links_to_credential(tmp_path):
    fp = fingerprint(PEPPER, "abc123")
    store = _open(tmp_path)
    try:
        store.add_credential(
            fingerprint=fp, kind="api-key", rotation_class="rotatable", provider="mock"
        )
        consumer_id = store.add_consumer(
            machine="laptop", locator="/etc/cron.d/job", fmt="env-assignment"
        )
        store.add_copied_at(fingerprint=fp, consumer_id=consumer_id)

        consumers = store.list_consumers_for(fp)
    finally:
        store.close()

    assert len(consumers) == 1
    assert consumers[0]["machine"] == "laptop"
    assert consumers[0]["locator"] == "/etc/cron.d/job"
    assert consumers[0]["format"] == "env-assignment"


def test_record_scan(tmp_path):
    store = _open(tmp_path)
    try:
        store.record_scan(
            surface="crontab",
            ts="2026-08-18T00:00:00Z",
            invoked_by="scheduler",
            skip_count=2,
        )
        rows = list(
            store._conn.execute("SELECT surface, invoked_by, skip_count FROM scans")
        )
    finally:
        store.close()

    assert rows == [("crontab", "scheduler", 2)]


# --- raw values never touch disk ------------------------------------------


def test_raw_secret_never_persisted_to_store_file_bytes(tmp_path):
    secret = "sk-mock-raw-value-never-persisted-7f3a9c"
    fp = fingerprint(PEPPER, secret)

    store = _open(tmp_path)
    store.add_credential(
        fingerprint=fp, kind="api-key", rotation_class="rotatable", provider="mock"
    )
    consumer_id = store.add_consumer(
        machine="laptop", locator="/etc/cron.d/job", fmt="env-assignment"
    )
    store.add_copied_at(fingerprint=fp, consumer_id=consumer_id)
    store.close()

    for candidate in tmp_path.glob("graph.sqlite3*"):
        assert secret.encode("utf-8") not in candidate.read_bytes()
