"""The sweep: scan + canary all registered credentials + escalate.

Capture-based per docs/WATCH-TOPOLOGY.md -- the heartbeat write is the
LAST statement this function executes. Any exception anywhere upstream
of it (scan, persist, canary, escalation, or the alert channel)
propagates uncaught and no heartbeat is written: a sweep that dies
partway through must look exactly like a sweep that never ran, never
like a completed one with a smaller number in it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from lastrites.core.store import GraphStore
from lastrites.scan.estate import scan_estate
from lastrites.scan.models import ScanReport
from lastrites.scan.persist import persist
from lastrites.sweep.canary_all import CanaryAllResult, canary_all
from lastrites.sweep.channel import ChannelConfig, send_alert
from lastrites.sweep.escalation import Alert, EscalationConfig, evaluate_escalation
from lastrites.sweep.heartbeat import Heartbeat, write_heartbeat


@dataclass
class SweepReport:
    scan: ScanReport
    canary: CanaryAllResult
    alerts: list[Alert]


def _counts(report: SweepReport) -> dict:
    return {
        "surfaces_scanned": report.scan.surface_count,
        "surfaces_readable": report.scan.readable_count,
        "scan_skips": report.scan.skip_count,
        "credentials_found": len(report.scan.credentials),
        "canary_skips": len(report.canary.skips),
        "alerts": len(report.alerts),
        **report.canary.counts,
    }


def run_sweep(
    *,
    pepper: bytes,
    store_path,
    targets: dict,
    discovery_skips: list,
    registrations: list,
    escalation_config: EscalationConfig,
    channel_config: ChannelConfig | None,
    invoked_by: str,
    heartbeat_path,
    now: datetime,
    timeout: float = 5.0,
    transport=None,
    channel_runner=None,
) -> SweepReport:
    scan_report = scan_estate(pepper, discovery_skips=discovery_skips, **targets)
    persist(scan_report, store_path, invoked_by=invoked_by)

    store = GraphStore(Path(store_path))
    try:
        canary_result = canary_all(
            store, pepper, registrations, timeout=timeout, transport=transport
        )
        alerts = evaluate_escalation(store, escalation_config, now=now)
    finally:
        store.close()

    if channel_config is not None:
        channel_kwargs = {} if channel_runner is None else {"runner": channel_runner}
        for alert in alerts:
            send_alert(channel_config, alert.message, **channel_kwargs)

    report = SweepReport(scan=scan_report, canary=canary_result, alerts=alerts)

    heartbeat = Heartbeat(
        last_success=now.isoformat(), invoked_by=invoked_by, counts=_counts(report)
    )
    write_heartbeat(heartbeat, Path(heartbeat_path))

    return report
