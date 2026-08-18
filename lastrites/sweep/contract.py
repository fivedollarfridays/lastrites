"""The environment contract: how a sweep learns who invoked it.

Per docs/WATCH-TOPOLOGY.md, heartbeats are provenance-stamped so a
hand-run check can never impersonate the scheduler. The contract is a
single env var the scheduler sets; its mere presence, not its value,
means "scheduler" -- a crontab line only has to export it, not agree
with us on a sentinel value. Absent means interactive. There is no
third state.
"""

from __future__ import annotations

import os

ENV_VAR = "LASTRITES_SCHEDULED"
SCHEDULER = "scheduler"
INTERACTIVE = "interactive"


def invoked_by() -> str:
    return SCHEDULER if ENV_VAR in os.environ else INTERACTIVE
