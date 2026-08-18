"""Loading the sweep's credential registrations.

The graph store never holds a raw value (THREAT-MODEL SS2/SS3), so a sweep
that canaries "all registered credentials" needs an explicit, external
declaration of which fingerprint maps to which provider and where its raw
value lives -- the same value-env/value-file discipline `lastrites canary`
already enforces on the command line, just declared once instead of typed
per run. This file is operator-owned config: it belongs outside the repo,
next to the pepper and the graph store, never committed alongside them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from lastrites.sweep.channel import require_private_config


@dataclass(frozen=True)
class CredentialRegistration:
    fingerprint_prefix: str
    provider: str
    value_env: str | None = None
    value_file: str | None = None
    config: dict = field(default_factory=dict)


def load_registrations(path: Path) -> list[CredentialRegistration]:
    payload = json.loads(require_private_config(path).read_text())
    return [
        CredentialRegistration(
            fingerprint_prefix=entry["fingerprint_prefix"],
            provider=entry["provider"],
            value_env=entry.get("value_env"),
            value_file=entry.get("value_file"),
            config=entry.get("config", {}),
        )
        for entry in payload
    ]
