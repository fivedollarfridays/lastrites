"""Escalation rules read the graph store; they never talk to a channel
directly, so each rule is pinned by asserting the `Alert` list it
returns.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lastrites.core.fingerprint import fingerprint
from lastrites.core.store import GraphStore
from lastrites.sweep.escalation import EscalationConfig, evaluate_escalation

PEPPER = b"\x44" * 32
NOW = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)


def _store(tmp_path):
    return GraphStore(tmp_path / "graph.sqlite3")


def _fp(label: str) -> str:
    return fingerprint(PEPPER, label)


def _config(**overrides) -> EscalationConfig:
    defaults = {"lead_time_days": 7.0, "unobservable_threshold": 3}
    defaults.update(overrides)
    return EscalationConfig(**defaults)


# --- expiry-ledger rule ------------------------------------------------------


def test_expiry_within_lead_time_pages(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(
        fp,
        kind="api-key",
        rotation_class="unknown",
        expiry=(NOW + timedelta(days=3)).isoformat(),
    )
    alerts = evaluate_escalation(store, _config(), now=NOW)
    store.close()

    assert any(a.rule == "expiry-lead-time" and a.fingerprint == fp for a in alerts)


def test_expiry_outside_lead_time_does_not_page(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(
        fp,
        kind="api-key",
        rotation_class="unknown",
        expiry=(NOW + timedelta(days=30)).isoformat(),
    )
    alerts = evaluate_escalation(store, _config(), now=NOW)
    store.close()

    assert alerts == []


def test_already_expired_pages(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(
        fp,
        kind="api-key",
        rotation_class="unknown",
        expiry=(NOW - timedelta(days=1)).isoformat(),
    )
    alerts = evaluate_escalation(store, _config(), now=NOW)
    store.close()

    assert any(a.rule == "expiry-lead-time" for a in alerts)


def test_credential_without_expiry_is_skipped_by_expiry_rule(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(fp, kind="api-key", rotation_class="unknown")
    alerts = evaluate_escalation(store, _config(), now=NOW)
    store.close()

    assert alerts == []


# --- verdict rules: dead ------------------------------------------------------


def test_dead_verdict_pages(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(fp, kind="api-key", rotation_class="unknown")
    store.record_canary_evidence(fp, NOW.isoformat(), "dead", 12.0, "401")
    alerts = evaluate_escalation(store, _config(), now=NOW)
    store.close()

    assert any(a.rule == "verdict-dead" and a.fingerprint == fp for a in alerts)


def test_alive_verdict_does_not_page(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(fp, kind="api-key", rotation_class="unknown")
    store.record_canary_evidence(fp, NOW.isoformat(), "alive", 12.0, "200")
    alerts = evaluate_escalation(store, _config(), now=NOW)
    store.close()

    assert alerts == []


def test_no_evidence_at_all_does_not_page(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(fp, kind="api-key", rotation_class="unknown")
    alerts = evaluate_escalation(store, _config(), now=NOW)
    store.close()

    assert alerts == []


# --- verdict rules: consecutive unobservable ---------------------------------


def test_n_consecutive_unobservable_pages(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(fp, kind="api-key", rotation_class="unknown")
    for i in range(3):
        store.record_canary_evidence(
            fp, NOW.isoformat(), "unobservable", 12.0, "timeout"
        )
    alerts = evaluate_escalation(store, _config(unobservable_threshold=3), now=NOW)
    store.close()

    assert any(
        a.rule == "verdict-unobservable-streak" and a.fingerprint == fp for a in alerts
    )


def test_fewer_than_n_unobservable_does_not_page(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(fp, kind="api-key", rotation_class="unknown")
    for i in range(2):
        store.record_canary_evidence(
            fp, NOW.isoformat(), "unobservable", 12.0, "timeout"
        )
    alerts = evaluate_escalation(store, _config(unobservable_threshold=3), now=NOW)
    store.close()

    assert alerts == []


def test_streak_broken_by_alive_does_not_page(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(fp, kind="api-key", rotation_class="unknown")
    store.record_canary_evidence(fp, NOW.isoformat(), "unobservable", 12.0, "timeout")
    store.record_canary_evidence(fp, NOW.isoformat(), "alive", 12.0, "200")
    store.record_canary_evidence(fp, NOW.isoformat(), "unobservable", 12.0, "timeout")
    store.record_canary_evidence(fp, NOW.isoformat(), "unobservable", 12.0, "timeout")
    alerts = evaluate_escalation(store, _config(unobservable_threshold=3), now=NOW)
    store.close()

    assert alerts == []


def test_dead_takes_priority_over_unobservable_streak_no_double_page(tmp_path):
    fp = _fp("a")
    store = _store(tmp_path)
    store.add_credential(fp, kind="api-key", rotation_class="unknown")
    store.record_canary_evidence(fp, NOW.isoformat(), "unobservable", 12.0, "timeout")
    store.record_canary_evidence(fp, NOW.isoformat(), "unobservable", 12.0, "timeout")
    store.record_canary_evidence(fp, NOW.isoformat(), "dead", 12.0, "401")
    alerts = evaluate_escalation(store, _config(unobservable_threshold=3), now=NOW)
    store.close()

    verdict_alerts = [a for a in alerts if a.rule.startswith("verdict")]
    assert len(verdict_alerts) == 1
    assert verdict_alerts[0].rule == "verdict-dead"


# --- multiple credentials -----------------------------------------------------


def test_rules_evaluate_independently_per_credential(tmp_path):
    dead_fp = _fp("dead")
    alive_fp = _fp("alive")
    store = _store(tmp_path)
    store.add_credential(dead_fp, kind="api-key", rotation_class="unknown")
    store.add_credential(alive_fp, kind="api-key", rotation_class="unknown")
    store.record_canary_evidence(dead_fp, NOW.isoformat(), "dead", 12.0, "401")
    store.record_canary_evidence(alive_fp, NOW.isoformat(), "alive", 12.0, "200")
    alerts = evaluate_escalation(store, _config(), now=NOW)
    store.close()

    fingerprints_paged = {a.fingerprint for a in alerts}
    assert dead_fp in fingerprints_paged
    assert alive_fp not in fingerprints_paged
