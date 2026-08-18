"""`lastrites canary <fingerprint-prefix>` -- the operator-facing surface.

The raw credential value never comes from argv (shell history, process
list); it's read from an env var or a file. Every test here monkeypatches
`lastrites.canary.transport.send` -- no real network call.
"""

from __future__ import annotations

import json

import pytest

from lastrites.canary.transport import ProbeResponse, ProbeTimeout
from lastrites.cli import (
    EXIT_CANARY_ALIVE,
    EXIT_CANARY_AMBIGUOUS,
    EXIT_CANARY_BAD_CONFIG,
    EXIT_CANARY_DEAD,
    EXIT_CANARY_MISMATCH,
    EXIT_CANARY_NOT_FOUND,
    EXIT_CANARY_UNOBSERVABLE,
    main,
)
from lastrites.core.fingerprint import fingerprint
from lastrites.core.store import GraphStore

SECRET = "mock-cf-token-for-cli-test-9f3a2b7c"
PEPPER = b"\x2a" * 32


@pytest.fixture
def pepper_file(tmp_path):
    path = tmp_path / "pepper"
    path.write_bytes(PEPPER)
    return path


@pytest.fixture
def value_file(tmp_path):
    path = tmp_path / "value"
    path.write_text(SECRET)
    return path


@pytest.fixture
def seeded_store(tmp_path):
    db = tmp_path / "graph.sqlite3"
    fp = fingerprint(PEPPER, SECRET)
    store = GraphStore(db)
    store.add_credential(
        fingerprint=fp,
        kind="api-token",
        rotation_class="unknown",
        provider="cloudflare",
    )
    store.close()
    return db, fp


def run(argv, pepper_file, capsys):
    code = main([*argv, "--pepper-file", str(pepper_file)])
    return code, capsys.readouterr()


def _base_argv(fp, store, value_file, provider="cloudflare"):
    return [
        "canary",
        fp[:12],
        "--provider",
        provider,
        "--value-file",
        str(value_file),
        "--store",
        str(store),
    ]


# --- help ---------------------------------------------------------------


def test_help_exits_clean(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["canary", "--help"])
    assert exc.value.code == 0
    assert "canary" in capsys.readouterr().out


# --- alive -----------------------------------------------------------------


def test_alive_probe_exits_alive_and_prints_the_verdict(
    monkeypatch, seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store
    monkeypatch.setattr(
        "lastrites.canary.transport.send",
        lambda request, timeout=None: ProbeResponse(
            status=200, body=b'{"success":true}'
        ),
    )
    code, captured = run(_base_argv(fp, db, value_file), pepper_file, capsys)
    assert code == EXIT_CANARY_ALIVE
    assert "alive" in captured.out


def test_alive_probe_updates_last_verified(
    monkeypatch, seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store
    monkeypatch.setattr(
        "lastrites.canary.transport.send",
        lambda request, timeout=None: ProbeResponse(
            status=200, body=b'{"success":true}'
        ),
    )
    run(_base_argv(fp, db, value_file), pepper_file, capsys)

    store = GraphStore(db)
    record = store.get_credential(fp)
    store.close()
    assert record["last_verified"] is not None


# --- dead -----------------------------------------------------------------


def test_dead_probe_exits_dead(
    monkeypatch, seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store
    monkeypatch.setattr(
        "lastrites.canary.transport.send",
        lambda request, timeout=None: ProbeResponse(status=401, body=b""),
    )
    code, captured = run(_base_argv(fp, db, value_file), pepper_file, capsys)
    assert code == EXIT_CANARY_DEAD
    assert "dead" in captured.out


def test_dead_probe_does_not_update_last_verified(
    monkeypatch, seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store
    monkeypatch.setattr(
        "lastrites.canary.transport.send",
        lambda request, timeout=None: ProbeResponse(status=401, body=b""),
    )
    run(_base_argv(fp, db, value_file), pepper_file, capsys)

    store = GraphStore(db)
    record = store.get_credential(fp)
    store.close()
    assert record["last_verified"] is None


# --- unobservable -----------------------------------------------------------


def test_unobservable_probe_exits_unobservable_on_timeout(
    monkeypatch, seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store

    def raise_timeout(request, timeout=None):
        raise ProbeTimeout("timed out")

    monkeypatch.setattr("lastrites.canary.transport.send", raise_timeout)
    code, captured = run(_base_argv(fp, db, value_file), pepper_file, capsys)
    assert code == EXIT_CANARY_UNOBSERVABLE
    assert "unobservable" in captured.out


# --- evidence persistence -----------------------------------------------------------


def test_evidence_row_is_recorded_in_the_store(
    monkeypatch, seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store
    monkeypatch.setattr(
        "lastrites.canary.transport.send",
        lambda request, timeout=None: ProbeResponse(
            status=200, body=b'{"success":true}'
        ),
    )
    run(_base_argv(fp, db, value_file), pepper_file, capsys)

    store = GraphStore(db)
    rows = store.list_canary_evidence(fp)
    store.close()
    assert len(rows) == 1
    assert rows[0]["verdict"] == "alive"


# --- bad probe config -----------------------------------------------------------


def test_generic_bearer_without_url_exits_bad_config_not_a_traceback(
    seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store
    argv = [
        "canary",
        fp[:12],
        "--provider",
        "generic-bearer",
        "--value-file",
        str(value_file),
        "--store",
        str(db),
    ]
    code, captured = run(argv, pepper_file, capsys)
    assert code == EXIT_CANARY_BAD_CONFIG
    assert "url" in (captured.out + captured.err).lower()


# --- lookup failures -----------------------------------------------------------


def test_unknown_prefix_exits_not_found(
    monkeypatch, seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store
    argv = [
        "canary",
        "deadbeef00",
        "--provider",
        "cloudflare",
        "--value-file",
        str(value_file),
        "--store",
        str(db),
    ]
    code, captured = run(argv, pepper_file, capsys)
    assert code == EXIT_CANARY_NOT_FOUND
    assert "no credential" in (captured.out + captured.err).lower()


def test_ambiguous_prefix_exits_ambiguous(
    monkeypatch, tmp_path, value_file, pepper_file, capsys
):
    db = tmp_path / "graph.sqlite3"
    fp1 = fingerprint(PEPPER, SECRET)
    fp2 = fp1[:20] + ("0" if fp1[20] != "0" else "1") + fp1[21:]
    store = GraphStore(db)
    store.add_credential(
        fingerprint=fp1,
        kind="api-token",
        rotation_class="unknown",
        provider="cloudflare",
    )
    store.add_credential(
        fingerprint=fp2,
        kind="api-token",
        rotation_class="unknown",
        provider="cloudflare",
    )
    store.close()

    argv = [
        "canary",
        fp1[:20],
        "--provider",
        "cloudflare",
        "--value-file",
        str(value_file),
        "--store",
        str(db),
    ]
    code, captured = run(argv, pepper_file, capsys)
    assert code == EXIT_CANARY_AMBIGUOUS
    assert "ambiguous" in (captured.out + captured.err).lower()


def test_value_mismatch_exits_mismatch(
    monkeypatch, seeded_store, tmp_path, pepper_file, capsys
):
    db, fp = seeded_store
    wrong_value_file = tmp_path / "wrong-value"
    wrong_value_file.write_text("not-the-right-secret")

    argv = [
        "canary",
        fp[:12],
        "--provider",
        "cloudflare",
        "--value-file",
        str(wrong_value_file),
        "--store",
        str(db),
    ]
    code, captured = run(argv, pepper_file, capsys)
    assert code == EXIT_CANARY_MISMATCH
    assert "does not match" in (captured.out + captured.err).lower()


# --- value input & leak discipline -----------------------------------------------------------


def test_value_can_be_read_from_an_env_var(
    monkeypatch, seeded_store, pepper_file, capsys
):
    db, fp = seeded_store
    monkeypatch.setenv("LASTRITES_TEST_VALUE", SECRET)
    monkeypatch.setattr(
        "lastrites.canary.transport.send",
        lambda request, timeout=None: ProbeResponse(
            status=200, body=b'{"success":true}'
        ),
    )
    argv = [
        "canary",
        fp[:12],
        "--provider",
        "cloudflare",
        "--value-env",
        "LASTRITES_TEST_VALUE",
        "--store",
        str(db),
    ]
    code, _ = run(argv, pepper_file, capsys)
    assert code == EXIT_CANARY_ALIVE


def test_output_never_prints_the_raw_value(
    monkeypatch, seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store
    monkeypatch.setattr(
        "lastrites.canary.transport.send",
        lambda request, timeout=None: ProbeResponse(
            status=200, body=b'{"success":true}'
        ),
    )
    code, captured = run(_base_argv(fp, db, value_file), pepper_file, capsys)
    assert SECRET not in (captured.out + captured.err)


def test_json_output_is_valid_json(
    monkeypatch, seeded_store, value_file, pepper_file, capsys
):
    db, fp = seeded_store
    monkeypatch.setattr(
        "lastrites.canary.transport.send",
        lambda request, timeout=None: ProbeResponse(
            status=200, body=b'{"success":true}'
        ),
    )
    argv = [*_base_argv(fp, db, value_file), "--json"]
    code, captured = run(argv, pepper_file, capsys)
    payload = json.loads(captured.out)
    assert payload["verdict"] == "alive"
