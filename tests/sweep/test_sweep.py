"""The sweep orchestrator: scan + canary all + escalate, capture-based
heartbeat.

The heartbeat write is the LAST statement `run_sweep` executes. Any
exception anywhere upstream of it -- scan, persist, canary, escalation,
or the alert channel -- must propagate uncaught and leave no heartbeat
file behind, so a sweep that died mid-way looks exactly like a sweep
that never ran.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from lastrites.canary.transport import ProbeResponse
from lastrites.core.fingerprint import fingerprint
from lastrites.core.store import GraphStore
from lastrites.sweep.channel import ChannelConfig, ChannelError
from lastrites.sweep.contract import INTERACTIVE, SCHEDULER
from lastrites.sweep.escalation import EscalationConfig
from lastrites.sweep.heartbeat import read_heartbeat
from lastrites.sweep.registry import CredentialRegistration
from lastrites.sweep.sweep import run_sweep

PEPPER = b"\x66" * 32
NOW = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)


def _base_kwargs(tmp_path, **overrides):
    kwargs = dict(
        pepper=PEPPER,
        store_path=tmp_path / "graph.sqlite3",
        targets={"crontabs": [], "plists": [], "env_files": []},
        discovery_skips=[],
        registrations=[],
        escalation_config=EscalationConfig(),
        channel_config=None,
        invoked_by=INTERACTIVE,
        heartbeat_path=tmp_path / "heartbeat.json",
        now=NOW,
    )
    kwargs.update(overrides)
    return kwargs


def test_completed_sweep_writes_heartbeat_with_invoked_by(tmp_path):
    kwargs = _base_kwargs(tmp_path, invoked_by=SCHEDULER)
    run_sweep(**kwargs)

    heartbeat = read_heartbeat(kwargs["heartbeat_path"])
    assert heartbeat.invoked_by == SCHEDULER
    assert heartbeat.last_success == NOW.isoformat()


def test_hand_run_sweep_stamps_interactive(tmp_path):
    kwargs = _base_kwargs(tmp_path, invoked_by=INTERACTIVE)
    run_sweep(**kwargs)

    heartbeat = read_heartbeat(kwargs["heartbeat_path"])
    assert heartbeat.invoked_by == INTERACTIVE


def test_sweep_that_fails_mid_way_leaves_no_heartbeat(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("simulated mid-sweep failure")

    monkeypatch.setattr("lastrites.sweep.sweep.evaluate_escalation", boom)
    kwargs = _base_kwargs(tmp_path)

    with pytest.raises(RuntimeError, match="simulated mid-sweep failure"):
        run_sweep(**kwargs)

    assert not kwargs["heartbeat_path"].exists()


def test_channel_failure_prevents_heartbeat_write(tmp_path):
    channel_config = ChannelConfig(command=["notify", "{message}"])

    def failing_runner(argv, **kw):
        class Result:
            returncode = 1
            stderr = "channel down"

        return Result()

    fp = fingerprint(PEPPER, "dead-secret")
    store = GraphStore(tmp_path / "graph.sqlite3")
    store.add_credential(fp, kind="api-token", rotation_class="unknown")
    store.record_canary_evidence(fp, NOW.isoformat(), "dead", 12.0, "401")
    store.close()

    kwargs = _base_kwargs(
        tmp_path,
        channel_config=channel_config,
        channel_runner=failing_runner,
    )
    with pytest.raises(ChannelError):
        run_sweep(**kwargs)

    assert not kwargs["heartbeat_path"].exists()


def test_heartbeat_counts_reflect_scan_and_canary_results(tmp_path):
    fp = fingerprint(PEPPER, "alive-secret")
    store = GraphStore(tmp_path / "graph.sqlite3")
    store.add_credential(
        fp, kind="api-token", rotation_class="unknown", provider="cloudflare"
    )
    store.close()

    registration = CredentialRegistration(
        fingerprint_prefix=fp[:12], provider="cloudflare", value_env="SWEEP_ALIVE_VALUE"
    )
    import os

    os.environ["SWEEP_ALIVE_VALUE"] = "alive-secret"
    try:
        kwargs = _base_kwargs(
            tmp_path,
            registrations=[registration],
            transport=lambda request, timeout=None: ProbeResponse(
                status=200, body=b'{"success":true}'
            ),
        )
        run_sweep(**kwargs)
    finally:
        del os.environ["SWEEP_ALIVE_VALUE"]

    heartbeat = read_heartbeat(kwargs["heartbeat_path"])
    assert heartbeat.counts["alive"] == 1
    assert heartbeat.counts["dead"] == 0


def test_alerts_are_sent_through_the_configured_channel(tmp_path):
    fp = fingerprint(PEPPER, "dead-secret")
    store = GraphStore(tmp_path / "graph.sqlite3")
    store.add_credential(fp, kind="api-token", rotation_class="unknown")
    store.record_canary_evidence(fp, NOW.isoformat(), "dead", 12.0, "401")
    store.close()

    calls = []

    def fake_runner(argv, **kw):
        calls.append(argv)

        class Result:
            returncode = 0
            stderr = ""

        return Result()

    channel_config = ChannelConfig(command=["notify", "{message}"])
    kwargs = _base_kwargs(
        tmp_path, channel_config=channel_config, channel_runner=fake_runner
    )
    run_sweep(**kwargs)

    assert len(calls) == 1
    assert "DEAD" in calls[0][1]


def test_no_channel_configured_still_completes_and_writes_heartbeat(tmp_path):
    fp = fingerprint(PEPPER, "dead-secret")
    store = GraphStore(tmp_path / "graph.sqlite3")
    store.add_credential(fp, kind="api-token", rotation_class="unknown")
    store.record_canary_evidence(fp, NOW.isoformat(), "dead", 12.0, "401")
    store.close()

    kwargs = _base_kwargs(tmp_path, channel_config=None)
    report = run_sweep(**kwargs)

    assert len(report.alerts) == 1
    assert kwargs["heartbeat_path"].exists()


def test_expiry_alert_fires_through_channel(tmp_path):
    fp = fingerprint(PEPPER, "expiring-secret")
    store = GraphStore(tmp_path / "graph.sqlite3")
    store.add_credential(
        fp,
        kind="api-token",
        rotation_class="unknown",
        expiry=(NOW + timedelta(days=1)).isoformat(),
    )
    store.close()

    calls = []

    def fake_runner(argv, **kw):
        calls.append(argv)

        class Result:
            returncode = 0
            stderr = ""

        return Result()

    channel_config = ChannelConfig(command=["notify", "{message}"])
    kwargs = _base_kwargs(
        tmp_path,
        channel_config=channel_config,
        channel_runner=fake_runner,
        escalation_config=EscalationConfig(
            lead_time_days=7.0, unobservable_threshold=3
        ),
    )
    run_sweep(**kwargs)

    assert len(calls) == 1
    assert "expires" in calls[0][1]


def test_unobservable_streak_alert_fires_through_channel(tmp_path):
    fp = fingerprint(PEPPER, "flaky-secret")
    store = GraphStore(tmp_path / "graph.sqlite3")
    store.add_credential(fp, kind="api-token", rotation_class="unknown")
    for _ in range(3):
        store.record_canary_evidence(
            fp, NOW.isoformat(), "unobservable", 12.0, "timeout"
        )
    store.close()

    calls = []

    def fake_runner(argv, **kw):
        calls.append(argv)

        class Result:
            returncode = 0
            stderr = ""

        return Result()

    channel_config = ChannelConfig(command=["notify", "{message}"])
    kwargs = _base_kwargs(
        tmp_path, channel_config=channel_config, channel_runner=fake_runner
    )
    run_sweep(**kwargs)

    assert len(calls) == 1
    assert "UNOBSERVABLE" in calls[0][1]
