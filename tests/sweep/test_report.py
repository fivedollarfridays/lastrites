"""Rendering a sweep report for a human and for a machine.

Same leak discipline as `canary/report.py`: fingerprints are truncated,
never full.
"""

from __future__ import annotations

import json

from lastrites.sweep.escalation import Alert
from lastrites.sweep.heartbeat import Heartbeat
from lastrites.sweep.report import render_json, render_text


class _FakeCanary:
    skips = []
    counts = {"alive": 1, "dead": 0, "unobservable": 0}


class _FakeScan:
    surface_count = 2
    readable_count = 2
    skip_count = 0
    credentials = []


class _FakeReport:
    scan = _FakeScan()
    canary = _FakeCanary()
    alerts = [
        Alert(
            rule="verdict-dead",
            fingerprint="a" * 64,
            message="credential a... canary verdict is DEAD",
        )
    ]


def _heartbeat():
    return Heartbeat(
        last_success="2026-08-18T12:00:00+00:00",
        invoked_by="scheduler",
        counts={"alive": 1},
    )


def test_render_text_includes_invoked_by_and_alerts():
    text = render_text(_heartbeat(), _FakeReport())
    assert "scheduler" in text
    assert "verdict-dead" in text
    assert "a" * 64 not in text  # fingerprint must be truncated, never full


def test_render_json_is_valid_and_has_expected_shape():
    payload = json.loads(render_json(_heartbeat(), _FakeReport()))
    assert payload["invoked_by"] == "scheduler"
    assert payload["last_success"] == "2026-08-18T12:00:00+00:00"
    assert len(payload["alerts"]) == 1
    assert payload["alerts"][0]["rule"] == "verdict-dead"
    assert "a" * 64 not in json.dumps(payload)
