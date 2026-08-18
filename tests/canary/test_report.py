"""Rendering a canary outcome. Same rule as the scan renderer: no raw
value, ever, and a truncated fingerprint so a terminal scrollback is not
reconnaissance."""

from __future__ import annotations

import json

from lastrites.canary.models import ProbeOutcome, Verdict
from lastrites.canary.report import render_json, render_text

FULL_FINGERPRINT = "a" * 64
OUTCOME = ProbeOutcome(verdict=Verdict.ALIVE, latency_ms=42.567, http_class="200")


def test_render_text_reports_the_verdict_and_provider():
    out = render_text(FULL_FINGERPRINT, "cloudflare", OUTCOME, "2026-08-18T00:00:00Z")
    assert "cloudflare" in out
    assert "alive" in out


def test_render_text_truncates_the_fingerprint():
    out = render_text(FULL_FINGERPRINT, "cloudflare", OUTCOME, "2026-08-18T00:00:00Z")
    assert FULL_FINGERPRINT not in out
    assert out.count("a") < len(FULL_FINGERPRINT)


def test_render_json_is_valid_json_and_carries_the_fields():
    out = render_json(FULL_FINGERPRINT, "cloudflare", OUTCOME, "2026-08-18T00:00:00Z")
    payload = json.loads(out)
    assert payload["provider"] == "cloudflare"
    assert payload["verdict"] == "alive"
    assert payload["http_class"] == "200"
    assert payload["ts"] == "2026-08-18T00:00:00Z"


def test_render_json_never_carries_the_full_fingerprint():
    out = render_json(FULL_FINGERPRINT, "cloudflare", OUTCOME, "2026-08-18T00:00:00Z")
    assert FULL_FINGERPRINT not in out
