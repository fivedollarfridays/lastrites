"""Capture-based, provenance-stamped heartbeat.

Written only by `sweep.run_sweep`'s caller, and only after a sweep has
fully completed -- never speculatively, never for a partial run. A dead
worker must look dead (docs/WATCH-TOPOLOGY.md). `invoked_by` is STRICT
from birth: every heartbeat this writer produces carries the field, and
`read_heartbeat` refuses to interpret one that does not, so a reader can
fail closed on absence rather than assume "hand-run" -- treating a
tampered or half-written file as trustworthy evidence is worse than
refusing to read it at all.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_HEARTBEAT_PATH = Path.home() / ".lastrites" / "heartbeat.json"


@dataclass(frozen=True)
class Heartbeat:
    last_success: str
    invoked_by: str
    counts: dict = field(default_factory=dict)


def write_heartbeat(heartbeat: Heartbeat, path: Path = DEFAULT_HEARTBEAT_PATH) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(asdict(heartbeat), indent=2, sort_keys=True)

    # Write to a sibling temp file and rename into place: a crash mid-write
    # must never leave a half-written file where a reader expects either
    # "no heartbeat" or "a complete one", never a third, corrupt state.
    tmp_path = path.with_name(path.name + ".tmp")
    fd = os.open(tmp_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp_path, path)


def read_heartbeat(path: Path = DEFAULT_HEARTBEAT_PATH) -> Heartbeat:
    payload = json.loads(Path(path).read_text())
    if "invoked_by" not in payload:
        raise ValueError(
            "heartbeat missing invoked_by -- refusing to trust an unstamped heartbeat"
        )
    return Heartbeat(
        last_success=payload["last_success"],
        invoked_by=payload["invoked_by"],
        counts=payload.get("counts", {}),
    )
