"""The shapes the canary layer passes around.

`Verdict` is the vocabulary THREAT-MODEL.md pins: the instrument being
blind (`UNOBSERVABLE`) is never conflated with the surface being dead
(`DEAD`). `ProbeOutcome` carries no response body and no credential
value -- only what an evidence row is allowed to hold.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    ALIVE = "alive"
    DEAD = "dead"
    UNOBSERVABLE = "unobservable"


@dataclass(frozen=True)
class ProbeOutcome:
    """What one canary run learned. Never a body, never a value."""

    verdict: Verdict
    latency_ms: float
    http_class: str
