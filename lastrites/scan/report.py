"""Rendering a scan report for a human and for a machine.

Two rules govern both renderers:

1. No raw values, ever -- there are none in a `ScanReport` to begin with,
   and fingerprints are truncated so a terminal scrollback does not become
   the reconnaissance artifact THREAT-MODEL §3 warns about.
2. Skips and blind spots are printed unconditionally, including when the
   scan found nothing. Absence of findings is not evidence of absence.
"""

from __future__ import annotations

import json

from lastrites.scan.models import ScanReport

FINGERPRINT_PREFIX = 12


def short(digest: str) -> str:
    return f"{digest[:FINGERPRINT_PREFIX]}..."


def _surface_lines(report: ScanReport) -> list[str]:
    unreadable = report.surface_count - report.readable_count
    header = f"Surfaces scanned: {report.surface_count}"
    if unreadable:
        header += f" ({unreadable} could not be read at all)"
    lines = [header]
    for scan in report.surfaces:
        marks = []
        if not scan.readable:
            marks.append("UNREADABLE")
        if scan.skip_count:
            marks.append(f"{scan.skip_count} skipped")
        note = f"  ({', '.join(marks)})" if marks else ""
        lines.append(f"  {scan.surface:<14} {scan.source}{note}")

    lines.append(f"Skipped (unparseable, counted not hidden): {report.skip_count}")
    for skip in report.discovery_skips:
        lines.append(f"  {skip.locator} -- {skip.reason}")
    for scan in report.surfaces:
        lines.extend(f"  {skip.locator} -- {skip.reason}" for skip in scan.skips)
    return lines


def _credential_lines(report: ScanReport) -> list[str]:
    lines = [f"Credentials found: {len(report.credentials)}"]
    for credential in report.credentials:
        count = credential.copy_count
        lines.append(
            f"  {credential.provider}/{credential.kind} "
            f"[{short(credential.fingerprint)}] -- {count} {'copy' if count == 1 else 'copies'}"
        )
        lines.extend(
            f"      {copy.surface:<14} {copy.locator} ({copy.key})"
            for copy in credential.copies
        )
    return lines


def _blind_spot_lines(report: ScanReport) -> list[str]:
    lines = ["Blind spots (surface classes this scan cannot see):"]
    lines.extend(f"  {spot.name}: {spot.detail}" for spot in report.blind_spots)
    return lines


def render_text(report: ScanReport) -> str:
    sections = [
        ["lastrites scan -- estate summary", ""],
        _surface_lines(report),
        [""],
        _credential_lines(report),
        [""],
        _blind_spot_lines(report),
    ]
    return "\n".join(line for section in sections for line in section)


def to_dict(report: ScanReport) -> dict:
    return {
        "surface_count": report.surface_count,
        "readable_count": report.readable_count,
        "skip_count": report.skip_count,
        "discovery_skips": [
            {"locator": s.locator, "reason": s.reason} for s in report.discovery_skips
        ],
        "surfaces": [
            {
                "surface": scan.surface,
                "source": scan.source,
                "readable": scan.readable,
                "skip_count": scan.skip_count,
                "skips": [
                    {"locator": s.locator, "reason": s.reason} for s in scan.skips
                ],
            }
            for scan in report.surfaces
        ],
        "credentials": [
            {
                "fingerprint": credential.fingerprint,
                "provider": credential.provider,
                "kind": credential.kind,
                "rotation_class": credential.rotation_class,
                "copies": [
                    {
                        "surface": copy.surface,
                        "locator": copy.locator,
                        "key": copy.key,
                        "format": copy.fmt,
                    }
                    for copy in credential.copies
                ],
            }
            for credential in report.credentials
        ],
        "blind_spots": [
            {"name": spot.name, "detail": spot.detail} for spot in report.blind_spots
        ],
    }


def render_json(report: ScanReport) -> str:
    return json.dumps(to_dict(report), indent=2, sort_keys=True)
