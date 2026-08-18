"""Escalation rules: converting stored evidence into pages.

Two families, per the LR1.4 brief: expiry-ledger (page ahead of a known
expiry, at a configurable lead time) and verdict rules (page on a DEAD
canary result, and page when a credential has gone quiet -- N consecutive
UNOBSERVABLE results in a row, since an instrument that stopped seeing
anything is itself a fault per THREAT-MODEL SS6). A DEAD verdict outranks
an UNOBSERVABLE streak for the same credential -- the surface is already
known dead, so a second, weaker page about the same fact is noise, not
signal (THREAT-MODEL SS4 on alert fatigue).

Rules only read the graph store; they never talk to the alert channel
directly, so each one is pinned by asserting the `Alert` list it returns.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from lastrites.canary.models import Verdict


@dataclass(frozen=True)
class EscalationConfig:
    lead_time_days: float = 7.0
    unobservable_threshold: int = 3


@dataclass(frozen=True)
class Alert:
    rule: str
    fingerprint: str
    message: str


def _short(fp: str) -> str:
    return f"{fp[:12]}..."


def _expiry_alerts(store, config: EscalationConfig, now: datetime) -> list[Alert]:
    lead = timedelta(days=config.lead_time_days)
    alerts = []
    for credential in store.list_credentials():
        expiry = credential["expiry"]
        if not expiry:
            continue
        expiry_dt = datetime.fromisoformat(expiry)
        if expiry_dt - now <= lead:
            alerts.append(
                Alert(
                    rule="expiry-lead-time",
                    fingerprint=credential["fingerprint"],
                    message=(
                        f"credential {_short(credential['fingerprint'])} expires {expiry} "
                        f"(within the {config.lead_time_days}-day lead time)"
                    ),
                )
            )
    return alerts


def _verdict_alerts(store, config: EscalationConfig) -> list[Alert]:
    alerts = []
    for credential in store.list_credentials():
        fp = credential["fingerprint"]
        evidence = store.list_canary_evidence(fp)
        if not evidence:
            continue

        if evidence[-1]["verdict"] == Verdict.DEAD.value:
            alerts.append(
                Alert(
                    rule="verdict-dead",
                    fingerprint=fp,
                    message=f"credential {_short(fp)} canary verdict is DEAD",
                )
            )
            continue

        trailing = evidence[-config.unobservable_threshold :]
        if len(trailing) >= config.unobservable_threshold and all(
            row["verdict"] == Verdict.UNOBSERVABLE.value for row in trailing
        ):
            alerts.append(
                Alert(
                    rule="verdict-unobservable-streak",
                    fingerprint=fp,
                    message=(
                        f"credential {_short(fp)} has been UNOBSERVABLE for "
                        f"{config.unobservable_threshold} consecutive canaries"
                    ),
                )
            )
    return alerts


def evaluate_escalation(store, config: EscalationConfig, now: datetime) -> list[Alert]:
    return _expiry_alerts(store, config, now) + _verdict_alerts(store, config)
