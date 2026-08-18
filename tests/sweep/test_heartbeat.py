"""Capture-based, provenance-stamped heartbeat: write/read discipline.

Strict from birth per docs/WATCH-TOPOLOGY.md -- `read_heartbeat` refuses
to interpret a payload missing `invoked_by` rather than default it, so a
reader fails closed instead of quietly treating an old or hand-edited
file as trustworthy evidence.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from lastrites.sweep.heartbeat import Heartbeat, read_heartbeat, write_heartbeat


def test_write_then_read_roundtrips(tmp_path):
    path = tmp_path / "heartbeat.json"
    heartbeat = Heartbeat(
        last_success="2026-08-18T07:00:00+00:00",
        invoked_by="scheduler",
        counts={"credentials_found": 3, "alive": 2, "dead": 0, "unobservable": 1},
    )
    write_heartbeat(heartbeat, path)
    loaded = read_heartbeat(path)
    assert loaded == heartbeat


def test_write_creates_parent_directory(tmp_path):
    path = tmp_path / "nested" / "dir" / "heartbeat.json"
    write_heartbeat(
        Heartbeat(last_success="ts", invoked_by="interactive", counts={}), path
    )
    assert path.exists()


def test_file_mode_is_0600(tmp_path):
    path = tmp_path / "heartbeat.json"
    write_heartbeat(
        Heartbeat(last_success="ts", invoked_by="interactive", counts={}), path
    )
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_write_is_valid_json_on_disk(tmp_path):
    path = tmp_path / "heartbeat.json"
    write_heartbeat(
        Heartbeat(last_success="ts", invoked_by="scheduler", counts={"x": 1}), path
    )
    payload = json.loads(path.read_text())
    assert payload["invoked_by"] == "scheduler"
    assert payload["last_success"] == "ts"
    assert payload["counts"] == {"x": 1}


def test_read_heartbeat_missing_invoked_by_raises(tmp_path):
    """A payload without invoked_by must never be silently trusted as interactive."""
    path = tmp_path / "heartbeat.json"
    path.write_text(json.dumps({"last_success": "ts", "counts": {}}))
    with pytest.raises(ValueError, match="invoked_by"):
        read_heartbeat(path)


def test_read_heartbeat_missing_file_raises(tmp_path):
    with pytest.raises(OSError):
        read_heartbeat(tmp_path / "does-not-exist.json")
