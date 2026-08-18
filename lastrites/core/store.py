"""The credential graph store.

SQLite, WAL, 0600. The public API accepts fingerprints only — raw
values are unrepresentable here by construction: no parameter takes a
value or secret, and every fingerprint-shaped argument is validated as
a 64-character lowercase hex HMAC-SHA256 digest before it touches disk.
"""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    fingerprint TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    rotation_class TEXT NOT NULL,
    provider TEXT,
    expiry TEXT,
    last_verified TEXT
);

CREATE TABLE IF NOT EXISTS consumers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine TEXT NOT NULL,
    locator TEXT NOT NULL,
    format TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS copied_at (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL REFERENCES credentials(fingerprint),
    consumer_id INTEGER NOT NULL REFERENCES consumers(id),
    observed_at TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    surface TEXT NOT NULL,
    ts TEXT NOT NULL,
    invoked_by TEXT NOT NULL,
    skip_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS canary_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL REFERENCES credentials(fingerprint),
    ts TEXT NOT NULL,
    verdict TEXT NOT NULL,
    latency_ms REAL,
    http_class TEXT
);
"""

_PREFIX_RE = re.compile(r"^[0-9a-f]+$")


def _require_fingerprint(fingerprint: str) -> None:
    if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.match(fingerprint):
        raise ValueError(f"not a valid HMAC-SHA256 fingerprint: {fingerprint!r}")


class GraphStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Pre-create 0600 BEFORE sqlite touches it: connect-then-chmod leaves
        # a umask-default window, and the -wal/-shm sidecars sqlite creates at
        # connect would keep whatever mode they were born with.
        fd = os.open(self.path, os.O_CREAT, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        self._conn = sqlite3.connect(self.path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        for sidecar in (f"{self.path}-wal", f"{self.path}-shm"):
            if os.path.exists(sidecar):
                os.chmod(sidecar, 0o600)

    def close(self) -> None:
        self._conn.close()

    def add_credential(
        self,
        fingerprint: str,
        kind: str,
        rotation_class: str,
        provider: str | None = None,
        expiry: str | None = None,
        last_verified: str | None = None,
    ) -> None:
        _require_fingerprint(fingerprint)
        self._conn.execute(
            """
            INSERT OR REPLACE INTO credentials
                (fingerprint, kind, rotation_class, provider, expiry, last_verified)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (fingerprint, kind, rotation_class, provider, expiry, last_verified),
        )
        self._conn.commit()

    def get_credential(self, fingerprint: str) -> dict | None:
        row = self._conn.execute(
            """
            SELECT fingerprint, kind, rotation_class, provider, expiry, last_verified
            FROM credentials WHERE fingerprint = ?
            """,
            (fingerprint,),
        ).fetchone()
        if row is None:
            return None
        keys = (
            "fingerprint",
            "kind",
            "rotation_class",
            "provider",
            "expiry",
            "last_verified",
        )
        return dict(zip(keys, row))

    def list_credentials(self) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT fingerprint, kind, rotation_class, provider, expiry, last_verified
            FROM credentials
            """
        ).fetchall()
        keys = (
            "fingerprint",
            "kind",
            "rotation_class",
            "provider",
            "expiry",
            "last_verified",
        )
        return [dict(zip(keys, row)) for row in rows]

    def add_consumer(self, machine: str, locator: str, fmt: str) -> int:
        cursor = self._conn.execute(
            "INSERT INTO consumers (machine, locator, format) VALUES (?, ?, ?)",
            (machine, locator, fmt),
        )
        self._conn.commit()
        return cursor.lastrowid

    def add_copied_at(
        self, fingerprint: str, consumer_id: int, observed_at: str | None = None
    ) -> None:
        _require_fingerprint(fingerprint)
        self._conn.execute(
            "INSERT INTO copied_at (fingerprint, consumer_id, observed_at) VALUES (?, ?, ?)",
            (fingerprint, consumer_id, observed_at),
        )
        self._conn.commit()

    def list_consumers_for(self, fingerprint: str) -> list[dict]:
        rows = self._conn.execute(
            """
            SELECT consumers.id, consumers.machine, consumers.locator, consumers.format
            FROM copied_at
            JOIN consumers ON consumers.id = copied_at.consumer_id
            WHERE copied_at.fingerprint = ?
            """,
            (fingerprint,),
        ).fetchall()
        keys = ("id", "machine", "locator", "format")
        return [dict(zip(keys, row)) for row in rows]

    def record_scan(
        self, surface: str, ts: str, invoked_by: str, skip_count: int = 0
    ) -> None:
        self._conn.execute(
            "INSERT INTO scans (surface, ts, invoked_by, skip_count) VALUES (?, ?, ?, ?)",
            (surface, ts, invoked_by, skip_count),
        )
        self._conn.commit()

    def record_canary_evidence(
        self,
        fingerprint: str,
        ts: str,
        verdict: str,
        latency_ms: float,
        http_class: str,
    ) -> None:
        _require_fingerprint(fingerprint)
        self._conn.execute(
            """
            INSERT INTO canary_evidence (fingerprint, ts, verdict, latency_ms, http_class)
            VALUES (?, ?, ?, ?, ?)
            """,
            (fingerprint, ts, verdict, latency_ms, http_class),
        )
        self._conn.commit()

    def list_canary_evidence(self, fingerprint: str) -> list[dict]:
        _require_fingerprint(fingerprint)
        rows = self._conn.execute(
            """
            SELECT ts, verdict, latency_ms, http_class FROM canary_evidence
            WHERE fingerprint = ? ORDER BY id
            """,
            (fingerprint,),
        ).fetchall()
        keys = ("ts", "verdict", "latency_ms", "http_class")
        return [dict(zip(keys, row)) for row in rows]

    def update_last_verified(self, fingerprint: str, ts: str) -> None:
        _require_fingerprint(fingerprint)
        self._conn.execute(
            "UPDATE credentials SET last_verified = ? WHERE fingerprint = ?",
            (ts, fingerprint),
        )
        self._conn.commit()

    def find_by_prefix(self, prefix: str) -> list[dict]:
        if not isinstance(prefix, str) or not prefix or not _PREFIX_RE.match(prefix):
            raise ValueError(f"not a valid fingerprint prefix: {prefix!r}")
        rows = self._conn.execute(
            """
            SELECT fingerprint, kind, rotation_class, provider, expiry, last_verified
            FROM credentials WHERE fingerprint LIKE ?
            """,
            (prefix + "%",),
        ).fetchall()
        keys = (
            "fingerprint",
            "kind",
            "rotation_class",
            "provider",
            "expiry",
            "last_verified",
        )
        return [dict(zip(keys, row)) for row in rows]
