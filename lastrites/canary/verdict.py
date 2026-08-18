"""The three-way verdict distinction, in one place.

Only an authenticated 401/403 is DEAD. Every other unreadable outcome --
a timeout, a DNS failure, a 5xx, an ambiguous status, a predicate that
did not confirm success -- is UNOBSERVABLE. The instrument being blind
is never reported as the surface being dead.
"""

from __future__ import annotations

from lastrites.canary.models import Verdict
from lastrites.canary.transport import ProbeDNSError, ProbeTimeout

_DEAD_STATUSES = (401, 403)


def classify_response(status: int, predicate_ok: bool) -> tuple[Verdict, str]:
    if status in _DEAD_STATUSES:
        return Verdict.DEAD, str(status)
    if 200 <= status < 300 and predicate_ok:
        return Verdict.ALIVE, str(status)
    return Verdict.UNOBSERVABLE, str(status)


def classify_error(exc: Exception) -> tuple[Verdict, str]:
    if isinstance(exc, ProbeTimeout):
        return Verdict.UNOBSERVABLE, "timeout"
    if isinstance(exc, ProbeDNSError):
        return Verdict.UNOBSERVABLE, "dns"
    return Verdict.UNOBSERVABLE, "network-error"
