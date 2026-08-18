"""Env-file scanning: `.env`, `.envrc`, and shell files full of `export`.

The loosest format on the estate, so the skip accounting matters most
here: a line we cannot read is reported, not rounded down to zero.
"""

from __future__ import annotations

from lastrites.scan.assignments import candidate_from, is_identifier, split_assignment
from lastrites.scan.models import Skip, SurfaceScan
from lastrites.scan.redact import describe_key
from lastrites.scan.surfaces._reading import open_surface

SURFACE = "env-file"


def _scan_lines(scan: SurfaceScan, text: str) -> None:
    for lineno, raw in enumerate(text.splitlines(), start=1):
        _scan_line(scan, raw, f"{scan.source}:{lineno}")


def scan_text(text: str, source: str) -> SurfaceScan:
    scan = SurfaceScan(surface=SURFACE, source=source)
    _scan_lines(scan, text)
    return scan


def scan_file(path) -> SurfaceScan:
    scan, text = open_surface(path, SURFACE)
    if text is not None:
        _scan_lines(scan, text)
    return scan


def _scan_line(scan: SurfaceScan, raw: str, locator: str) -> None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return

    assignment = split_assignment(line)
    if assignment is None:
        scan.skips.append(Skip(locator, "not an assignment: no '=' found"))
        return

    key, value = assignment
    if not is_identifier(key):
        # Never quote `key` -- it is raw file text, and on a PEM body line
        # or a padded JWT that text is the secret. See scan/redact.py.
        scan.skips.append(Skip(locator, f"invalid identifier: {describe_key(key)}"))
        return

    candidate = candidate_from(key, value, SURFACE, locator)
    if candidate is not None:
        scan.candidates.append(candidate)
