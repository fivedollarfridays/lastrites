"""Writing a scan report into the LR1.1 graph store.

The store's API takes fingerprints only, and a `ScanReport` holds nothing
else, so this module is structurally incapable of persisting a value.

Two things it has to get right, because LR1.4 will run it on a schedule:

**Idempotence.** `add_consumer`/`add_copied_at` are unconditional INSERTs
with no uniqueness constraint, so a naive re-persist multiplies the graph
every sweep. "This token feeds 3 jobs on 2 machines" quietly becomes "300
jobs" and the blast-radius page turns into noise -- alert fatigue, which
THREAT-MODEL §4 counts as a security failure rather than a cosmetic one.

**No classification downgrade.** `add_credential` is INSERT OR REPLACE, so
a later scan that happens not to see the well-named copy would overwrite a
known provider with `unknown`. Evidence accumulates across scans the same
way `cluster._absorb` accumulates it within one.

Two gaps, named rather than hidden, both needing LR1.1 schema columns and
so belonging with the sweep daemon (LR1.4) rather than here:

- The `scans` table records a surface *class* (`env-file`), not the
  individual file, so per-file freshness is not recoverable from the store.
  DESIGN's dead-man layer wants per-surface freshness.
- Idempotence prevents duplicate edges, but nothing RETIRES an edge. A copy
  that moves from `/a/.env:1` to `/a/.env:7` leaves both consumers in the
  graph forever, so the blast radius over-reports as the estate drifts.
  Retiring needs a `last_seen` column on `copied_at` to be safe -- deleting
  on absence would erase copies on a machine that merely did not scan.
"""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from pathlib import Path

from lastrites.core.store import GraphStore
from lastrites.scan.classify import UNKNOWN
from lastrites.scan.models import Credential, ScanReport

__all__ = ["persist"]


def _merged(existing: dict | None, credential: Credential) -> dict:
    """Keep whatever the graph already knows when this scan knows less.

    `add_credential` is INSERT OR REPLACE across all six columns, so every
    field this scan cannot observe has to be carried forward explicitly --
    a scan only knows kind and provider, and LR1.3/LR1.4 own the rest.
    Letting a scheduled rescan NULL `last_verified` would stale exactly the
    evidence the dead-man layer reads to prove the graph is warm.
    """
    fields = {
        "kind": credential.kind,
        "provider": credential.provider,
        "rotation_class": credential.rotation_class,
        "expiry": None,
        "last_verified": None,
    }
    if existing is None:
        return fields
    for name in ("kind", "provider", "rotation_class"):
        if fields[name] in (UNKNOWN, None) and existing[name]:
            fields[name] = existing[name]
    for name in ("expiry", "last_verified"):
        fields[name] = existing[name]
    return fields


def _persist_credential(
    store: GraphStore, credential: Credential, observed_at: str
) -> None:
    fields = _merged(store.get_credential(credential.fingerprint), credential)
    store.add_credential(credential.fingerprint, **fields)

    known = {
        (consumer["machine"], consumer["locator"], consumer["format"])
        for consumer in store.list_consumers_for(credential.fingerprint)
    }
    machine = platform.node()
    for copy in credential.copies:
        if (machine, copy.locator, copy.fmt) in known:
            continue
        consumer_id = store.add_consumer(machine, copy.locator, copy.fmt)
        store.add_copied_at(credential.fingerprint, consumer_id, observed_at)
        known.add((machine, copy.locator, copy.fmt))


def persist(report: ScanReport, path, invoked_by: str = "cli") -> None:
    observed_at = datetime.now(timezone.utc).isoformat()
    store = GraphStore(Path(path))
    try:
        for credential in report.credentials:
            _persist_credential(store, credential, observed_at)
        # Scan rows DO accumulate: each is a distinct freshness event, and
        # the dead-man layer reads the newest one to prove the graph is warm.
        for scan in report.surfaces:
            store.record_scan(scan.surface, observed_at, invoked_by, scan.skip_count)
        # Discovery skips are skips too. Without this row a mistyped --root
        # is loud on stdout and invisible to everything reading the graph,
        # and the persisted skip total silently disagrees with the report's.
        if report.discovery_skips:
            store.record_scan(
                "discovery", observed_at, invoked_by, len(report.discovery_skips)
            )
    finally:
        store.close()
