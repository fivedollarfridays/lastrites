"""Canarying every registered credential in one sweep pass.

Mirrors the CLI's per-credential discipline (lookup by fingerprint
prefix, verify the supplied value actually fingerprints to that record,
run the provider's probe, record evidence) but resilient across the
whole registry: one bad registration -- a missing env var, a value that
no longer matches, an unknown provider -- is counted as a skip and never
aborts the credentials still queued behind it. The same containment
philosophy as `scan/estate.py`'s `_guarded`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from lastrites.canary.engine import run_probe
from lastrites.canary.models import Verdict
from lastrites.canary.providers import get_provider
from lastrites.core.fingerprint import fingerprint as compute_fingerprint
from lastrites.sweep.registry import CredentialRegistration


@dataclass(frozen=True)
class CanarySkip:
    fingerprint_prefix: str
    reason: str


@dataclass(frozen=True)
class CanaryRun:
    fingerprint: str
    provider: str
    verdict: str


@dataclass
class CanaryAllResult:
    runs: list[CanaryRun] = field(default_factory=list)
    skips: list[CanarySkip] = field(default_factory=list)

    @property
    def counts(self) -> dict:
        counts = {"alive": 0, "dead": 0, "unobservable": 0}
        for run in self.runs:
            counts[run.verdict] += 1
        return counts


def _read_value(registration: CredentialRegistration) -> tuple[str | None, str | None]:
    if registration.value_env:
        value = os.environ.get(registration.value_env)
        if value is None:
            return None, f"env var {registration.value_env} is not set"
        return value, None
    if registration.value_file:
        try:
            return Path(registration.value_file).read_text().strip(), None
        except OSError as exc:
            return None, f"could not read value_file: {exc}"
    return None, "registration has neither value_env nor value_file"


def _resolve_credential(
    store, registration: CredentialRegistration
) -> tuple[dict | None, str | None]:
    matches = store.find_by_prefix(registration.fingerprint_prefix)
    if not matches:
        return None, "no credential matches this prefix"
    if len(matches) > 1:
        return None, "prefix is ambiguous -- matches more than one credential"
    return matches[0], None


def _run_one(
    store,
    pepper: bytes,
    registration: CredentialRegistration,
    timeout: float,
    transport,
) -> CanaryRun | CanarySkip:
    value, error = _read_value(registration)
    if error is not None:
        return CanarySkip(registration.fingerprint_prefix, error)

    record, error = _resolve_credential(store, registration)
    if error is not None:
        return CanarySkip(registration.fingerprint_prefix, error)

    if compute_fingerprint(pepper, value) != record["fingerprint"]:
        return CanarySkip(
            registration.fingerprint_prefix,
            "value does not match the credential on record",
        )

    try:
        spec = get_provider(registration.provider)
    except KeyError as exc:
        return CanarySkip(registration.fingerprint_prefix, str(exc))

    try:
        outcome = run_probe(
            spec,
            value,
            config=registration.config,
            timeout=timeout,
            transport=transport,
        )
    except ValueError as exc:
        return CanarySkip(
            registration.fingerprint_prefix, f"bad provider config: {exc}"
        )

    ts = datetime.now(timezone.utc).isoformat()
    store.record_canary_evidence(
        record["fingerprint"],
        ts,
        outcome.verdict.value,
        outcome.latency_ms,
        outcome.http_class,
    )
    if outcome.verdict is Verdict.ALIVE:
        store.update_last_verified(record["fingerprint"], ts)
    return CanaryRun(
        record["fingerprint"], registration.provider, outcome.verdict.value
    )


def canary_all(
    store,
    pepper: bytes,
    registrations: list[CredentialRegistration],
    timeout: float = 5.0,
    transport=None,
) -> CanaryAllResult:
    result = CanaryAllResult()
    for registration in registrations:
        outcome = _run_one(store, pepper, registration, timeout, transport)
        if isinstance(outcome, CanarySkip):
            result.skips.append(outcome)
        else:
            result.runs.append(outcome)
    return result
