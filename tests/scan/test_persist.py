"""Persisting the graph must be idempotent.

LR1.4 runs this on a schedule. An `INSERT`-per-scan turns "this token feeds
3 jobs on 2 machines" into "this token feeds 300 jobs" by Thursday, and the
blast-radius message DESIGN promises becomes noise -- which THREAT-MODEL §4
counts as a security failure, not a cosmetic one.
"""

from lastrites.core.fingerprint import fingerprint
from lastrites.core.store import GraphStore
from lastrites.scan.estate import scan_estate
from lastrites.scan.persist import persist

from .conftest import SHARED_TOKEN


def scan(estate, pepper):
    return scan_estate(
        pepper,
        crontabs=[estate / "crontab.txt"],
        plists=[estate / "com.mock.agent.plist"],
        env_files=[estate / "app.env"],
    )


def test_rescanning_does_not_duplicate_copied_at_edges(estate, pepper, tmp_path):
    db = tmp_path / "graph.sqlite3"
    report = scan(estate, pepper)
    persist(report, db)
    persist(report, db)
    persist(report, db)

    store = GraphStore(db)
    try:
        consumers = store.list_consumers_for(fingerprint(pepper, SHARED_TOKEN))
        assert len(consumers) == 3
    finally:
        store.close()


def test_rescanning_does_not_duplicate_credentials(estate, pepper, tmp_path):
    db = tmp_path / "graph.sqlite3"
    report = scan(estate, pepper)
    persist(report, db)
    persist(report, db)

    store = GraphStore(db)
    try:
        count = store._conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        assert count == len(report.credentials)
    finally:
        store.close()


def test_a_later_anonymous_scan_does_not_downgrade_a_known_provider(
    estate, pepper, tmp_path
):
    """The crontab that named the token gets deleted; the copies remain.
    The graph must not forget who issues the credential."""
    db = tmp_path / "graph.sqlite3"
    persist(scan(estate, pepper), db)

    anonymous = scan_estate(pepper, env_files=[estate / "app.env"])
    for credential in anonymous.credentials:
        credential.provider = "unknown"
        credential.kind = "unknown"
    persist(anonymous, db)

    store = GraphStore(db)
    try:
        record = store.get_credential(fingerprint(pepper, SHARED_TOKEN))
        assert record["provider"] == "cloudflare"
        assert record["kind"] == "api-token"
    finally:
        store.close()


def test_a_rescan_does_not_erase_columns_it_does_not_write(estate, pepper, tmp_path):
    """LR1.3/LR1.4 fill in expiry and last_verified. A scheduled rescan that
    NULLs them would silently stale exactly the freshness the dead-man layer
    reads."""
    db = tmp_path / "graph.sqlite3"
    report = scan(estate, pepper)
    persist(report, db)

    target = fingerprint(pepper, SHARED_TOKEN)
    store = GraphStore(db)
    try:
        store.add_credential(
            target,
            "api-token",
            "30-day",
            provider="cloudflare",
            expiry="2026-09-01",
            last_verified="2026-08-18",
        )
    finally:
        store.close()

    persist(report, db)

    store = GraphStore(db)
    try:
        record = store.get_credential(target)
        assert record["rotation_class"] == "30-day"
        assert record["expiry"] == "2026-09-01"
        assert record["last_verified"] == "2026-08-18"
    finally:
        store.close()


def test_copies_on_different_machines_are_different_consumers(
    estate, pepper, tmp_path, monkeypatch
):
    """The dedup key must include the machine, or a two-machine estate
    collapses into one and the blast radius under-reports."""
    import lastrites.scan.persist as persist_module

    db = tmp_path / "graph.sqlite3"
    report = scan(estate, pepper)

    monkeypatch.setattr(persist_module.platform, "node", lambda: "machine-a")
    persist(report, db)
    monkeypatch.setattr(persist_module.platform, "node", lambda: "machine-b")
    persist(report, db)

    store = GraphStore(db)
    try:
        consumers = store.list_consumers_for(fingerprint(pepper, SHARED_TOKEN))
        assert len(consumers) == 6
        assert {c["machine"] for c in consumers} == {"machine-a", "machine-b"}
    finally:
        store.close()


def test_discovery_skips_reach_the_persisted_scan_record(estate, pepper, tmp_path):
    """A mistyped --root that is loud on stdout and silent in the graph is
    a skip the dead-man layer can never see."""
    from lastrites.scan.models import Skip

    db = tmp_path / "graph.sqlite3"
    report = scan_estate(
        pepper,
        env_files=[estate / "app.env"],
        discovery_skips=[Skip("/mock/typo", "root is not a directory")],
    )
    persist(report, db)

    store = GraphStore(db)
    try:
        rows = store._conn.execute("SELECT surface, skip_count FROM scans").fetchall()
        assert sum(skip_count for _, skip_count in rows) == report.skip_count
        assert any(surface == "discovery" for surface, _ in rows)
    finally:
        store.close()


def test_every_surface_is_stamped_with_its_own_skip_count(estate, pepper, tmp_path):
    db = tmp_path / "graph.sqlite3"
    report = scan(estate, pepper)
    persist(report, db)

    store = GraphStore(db)
    try:
        rows = store._conn.execute("SELECT surface, skip_count FROM scans").fetchall()
        assert len(rows) == report.surface_count
        assert sum(skip_count for _, skip_count in rows) == report.skip_count
    finally:
        store.close()
