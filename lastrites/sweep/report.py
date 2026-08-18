"""Rendering one sweep's outcome for a human and for a machine.

Same rule as `lastrites/canary/report.py`: fingerprints are truncated so
a terminal scrollback or a JSON log line does not become reconnaissance.
"""

from __future__ import annotations

import json

FINGERPRINT_PREFIX = 12


def _short(fp: str) -> str:
    return f"{fp[:FINGERPRINT_PREFIX]}..."


def to_dict(heartbeat, report) -> dict:
    return {
        "last_success": heartbeat.last_success,
        "invoked_by": heartbeat.invoked_by,
        "counts": heartbeat.counts,
        "alerts": [
            {
                "rule": alert.rule,
                "fingerprint": _short(alert.fingerprint),
                "message": alert.message,
            }
            for alert in report.alerts
        ],
        "canary_skips": [
            {"fingerprint_prefix": skip.fingerprint_prefix, "reason": skip.reason}
            for skip in report.canary.skips
        ],
    }


def render_text(heartbeat, report) -> str:
    payload = to_dict(heartbeat, report)
    lines = [
        f"lastrites sweep -- invoked_by={payload['invoked_by']}",
        f"  last_success: {payload['last_success']}",
    ]
    for key in sorted(payload["counts"]):
        lines.append(f"  {key}: {payload['counts'][key]}")
    if payload["canary_skips"]:
        lines.append("  canary skips:")
        for skip in payload["canary_skips"]:
            lines.append(f"    {skip['fingerprint_prefix']}: {skip['reason']}")
    if payload["alerts"]:
        lines.append("  alerts:")
        for alert in payload["alerts"]:
            lines.append(
                f"    [{alert['rule']}] {alert['fingerprint']} -- {alert['message']}"
            )
    return "\n".join(lines)


def render_json(heartbeat, report) -> str:
    return json.dumps(to_dict(heartbeat, report), indent=2, sort_keys=True)
