"""`lastrites scan` -- the operator-facing surface.

The load-bearing behaviour: a scan that saw nothing must NOT look like a
clean estate. Silence and safety are different states and the exit code
has to tell them apart.
"""

import json

import pytest

from lastrites.cli import (
    EXIT_NO_SURFACES,
    EXIT_NOTHING_READABLE,
    EXIT_OK,
    EXIT_STORE_FAILED,
    main,
)

from .conftest import SHARED_TOKEN


@pytest.fixture
def pepper_file(tmp_path):
    path = tmp_path / "pepper"
    path.write_bytes(b"\x2a" * 32)
    return path


def run(argv, pepper_file, capsys):
    code = main([*argv, "--pepper-file", str(pepper_file)])
    return code, capsys.readouterr()


# --- help ---------------------------------------------------------------


def test_help_exits_clean(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--help"])
    assert exc.value.code == 0
    assert "scan" in capsys.readouterr().out


# --- a real scan --------------------------------------------------------


@pytest.fixture
def scan_output(estate, pepper_file, capsys):
    code, captured = run(["scan", "--root", str(estate)], pepper_file, capsys)
    return code, captured.out


def test_a_scan_that_found_surfaces_exits_zero(scan_output):
    assert scan_output[0] == 0


def test_output_reports_the_clustered_credential_and_its_copy_count(scan_output):
    out = scan_output[1]
    assert "cloudflare" in out
    assert "3 copies" in out


def test_output_reports_the_total_skip_count(scan_output):
    assert "Skipped (unparseable, counted not hidden): 7" in scan_output[1]


def test_output_names_each_individual_skip_with_its_reason(scan_output):
    """A bare total lets an operator assume the skips were boring."""
    out = scan_output[1]
    assert "app.env:9 -- invalid identifier" in out
    assert "plist parse failed" in out


def test_output_marks_which_surfaces_had_skips(scan_output):
    assert "(3 skipped)" in scan_output[1]


def test_copy_counts_read_as_english(scan_output):
    assert "1 copy" in scan_output[1]
    assert "1 copies" not in scan_output[1]


def test_output_names_the_blind_spots(scan_output):
    out = scan_output[1].lower()
    assert "blind spot" in out
    assert "keychain" in out


def test_output_never_prints_a_credential_value(scan_output):
    assert SHARED_TOKEN not in scan_output[1]


def test_output_prints_truncated_fingerprints_not_full_ones(scan_output):
    """A full fingerprint on a terminal is reconnaissance in the scrollback."""
    assert "..." in scan_output[1] or "…" in scan_output[1]


# --- the zero-surface alarm ---------------------------------------------


def test_zero_surface_scan_exits_nonzero(tmp_path, pepper_file, capsys):
    empty = tmp_path / "empty-estate"
    empty.mkdir()
    code, captured = run(["scan", "--root", str(empty)], pepper_file, capsys)
    assert code != 0
    assert "no surfaces" in (captured.out + captured.err).lower()


def test_a_scan_where_every_surface_was_unreadable_exits_nonzero(
    tmp_path, pepper_file, capsys
):
    """`Surfaces scanned: 3 / Credentials found: 0` with three failed opens is
    silence wearing safety's exit code."""
    argv = [
        "scan",
        "--env-file",
        str(tmp_path / "a.env"),
        "--plist",
        str(tmp_path / "b.plist"),
    ]
    code, captured = run(argv, pepper_file, capsys)
    assert code == EXIT_NOTHING_READABLE
    assert "unread" in (captured.out + captured.err).lower()


def test_the_three_ways_of_seeing_nothing_get_three_exit_codes(
    estate, tmp_path, pepper_file, capsys
):
    """A wrapper that cannot tell 'no targets' from 'nothing readable' from
    'clean' has no more information than a coin flip."""
    empty = tmp_path / "empty"
    empty.mkdir()

    healthy, _ = run(["scan", "--root", str(estate)], pepper_file, capsys)
    no_surfaces, _ = run(["scan", "--root", str(empty)], pepper_file, capsys)
    unreadable, _ = run(
        ["scan", "--env-file", str(tmp_path / "gone.env")], pepper_file, capsys
    )

    assert (healthy, no_surfaces, unreadable) == (
        EXIT_OK,
        EXIT_NO_SURFACES,
        EXIT_NOTHING_READABLE,
    )
    assert len({healthy, no_surfaces, unreadable}) == 3


def test_a_scan_with_one_readable_surface_among_failures_exits_zero(
    estate, tmp_path, pepper_file, capsys
):
    argv = [
        "scan",
        "--env-file",
        str(estate / "app.env"),
        "--env-file",
        str(tmp_path / "a.env"),
    ]
    code, _ = run(argv, pepper_file, capsys)
    assert code == 0


def test_an_unreachable_root_is_reported_even_when_another_root_works(
    estate, tmp_path, pepper_file, capsys
):
    argv = ["scan", "--root", str(estate), "--root", str(tmp_path / "typo"), "--json"]
    code, captured = run(argv, pepper_file, capsys)
    payload = json.loads(captured.out)
    assert code == 0
    assert payload["discovery_skips"]


def test_a_persist_failure_does_not_discard_the_report(
    estate, tmp_path, pepper_file, capsys
):
    """The scan already did the expensive work; losing it to a bad --store
    path would be the worst possible trade."""
    unwritable = tmp_path / "nope" / "graph.sqlite3"
    (tmp_path / "nope").write_text("i am a file, not a directory")
    argv = ["scan", "--root", str(estate), "--store", str(unwritable)]
    code, captured = run(argv, pepper_file, capsys)
    assert "cloudflare" in captured.out
    assert code == EXIT_STORE_FAILED
    assert "store" in captured.err.lower()


def test_zero_surface_scan_still_names_its_blind_spots(tmp_path, pepper_file, capsys):
    empty = tmp_path / "empty-estate"
    empty.mkdir()
    _, captured = run(["scan", "--root", str(empty)], pepper_file, capsys)
    assert "keychain" in captured.out.lower()


# --- machine-readable output --------------------------------------------


def test_json_output_carries_skips_blind_spots_and_credentials(
    estate, pepper_file, capsys
):
    code, captured = run(["scan", "--root", str(estate), "--json"], pepper_file, capsys)
    payload = json.loads(captured.out)

    assert code == 0
    assert payload["skip_count"] == 7
    assert payload["surface_count"] == 5
    assert len(payload["credentials"]) == 4
    assert payload["blind_spots"]


def test_overlapping_roots_do_not_inflate_the_totals(estate, pepper_file, capsys):
    """Double-counted surfaces would understate coverage per surface scanned."""
    argv = ["scan", "--root", str(estate), "--root", str(estate), "--json"]
    _, captured = run(argv, pepper_file, capsys)
    payload = json.loads(captured.out)
    assert payload["surface_count"] == 5
    assert payload["skip_count"] == 7


def test_json_output_never_carries_a_raw_value(estate, pepper_file, capsys):
    _, captured = run(["scan", "--root", str(estate), "--json"], pepper_file, capsys)
    assert SHARED_TOKEN not in captured.out


# --- persistence to the LR1.1 graph store -------------------------------


def test_scan_can_persist_the_graph(estate, pepper_file, tmp_path, capsys):
    from lastrites.core.fingerprint import fingerprint
    from lastrites.core.store import GraphStore

    db = tmp_path / "graph.sqlite3"
    code, _ = run(
        ["scan", "--root", str(estate), "--store", str(db)], pepper_file, capsys
    )
    assert code == 0

    store = GraphStore(db)
    try:
        target = fingerprint(b"\x2a" * 32, SHARED_TOKEN)
        assert store.get_credential(target) is not None
        assert len(store.list_consumers_for(target)) == 3
    finally:
        store.close()


def test_persisted_store_holds_no_raw_values(estate, pepper_file, tmp_path, capsys):
    db = tmp_path / "graph.sqlite3"
    run(["scan", "--root", str(estate), "--store", str(db)], pepper_file, capsys)
    assert SHARED_TOKEN.encode() not in db.read_bytes()
