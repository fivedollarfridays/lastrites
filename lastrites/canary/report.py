"""Rendering one canary outcome for a human and for a machine.

Same rule as `lastrites/scan/report.py`: no raw value, ever -- there is
none in a `ProbeOutcome` to begin with -- and the fingerprint is
truncated so a terminal scrollback does not become reconnaissance.
"""

from __future__ import annotations

import json

from lastrites.canary.models import ProbeOutcome

FINGERPRINT_PREFIX = 12


def short(digest: str) -> str:
    return f"{digest[:FINGERPRINT_PREFIX]}..."


def to_dict(fingerprint: str, provider: str, outcome: ProbeOutcome, ts: str) -> dict:
    return {
        "fingerprint": short(fingerprint),
        "provider": provider,
        "verdict": outcome.verdict.value,
        "http_class": outcome.http_class,
        "latency_ms": round(outcome.latency_ms, 1),
        "ts": ts,
    }


def render_text(fingerprint: str, provider: str, outcome: ProbeOutcome, ts: str) -> str:
    payload = to_dict(fingerprint, provider, outcome, ts)
    return (
        f"lastrites canary -- {provider} [{payload['fingerprint']}]\n"
        f"  verdict:     {payload['verdict']}\n"
        f"  http_class:  {payload['http_class']}\n"
        f"  latency_ms:  {payload['latency_ms']}\n"
        f"  ts:          {payload['ts']}"
    )


def render_json(fingerprint: str, provider: str, outcome: ProbeOutcome, ts: str) -> str:
    return json.dumps(
        to_dict(fingerprint, provider, outcome, ts), indent=2, sort_keys=True
    )
