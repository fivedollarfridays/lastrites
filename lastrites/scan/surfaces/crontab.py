"""Crontab scanning.

Two places a secret hides in a crontab: a bare `KEY=value` environment
assignment above the schedule block, and a `KEY=value` prefix on the
command of a job. Both are collected. Anything that is neither a comment,
an assignment, nor a recognisable schedule line is a counted skip -- we do
not get to pretend we understood it.
"""

from __future__ import annotations

import re

from lastrites.scan.assignments import (
    candidate_from,
    inline_candidates,
    is_identifier,
    split_assignment,
)
from lastrites.scan.models import Skip, SurfaceScan
from lastrites.scan.surfaces._reading import open_surface

SURFACE = "crontab"

SPECIAL_SCHEDULES = frozenset(
    {
        "@reboot",
        "@yearly",
        "@annually",
        "@monthly",
        "@weekly",
        "@daily",
        "@midnight",
        "@hourly",
    }
)

_NAMES = (
    r"(?:MON|TUE|WED|THU|FRI|SAT|SUN|JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)"
)
_ATOM = rf"(?:\*|\d+|{_NAMES})"
_RANGE = rf"{_ATOM}(?:-{_ATOM})?(?:/\d+)?"
CRON_FIELD = re.compile(rf"^{_RANGE}(?:,{_RANGE})*$", re.IGNORECASE)

SCHEDULE_FIELDS = 5


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
    if assignment is not None and is_identifier(assignment[0]):
        candidate = candidate_from(*assignment, SURFACE, locator)
        if candidate is not None:
            scan.candidates.append(candidate)
        return

    command = _command_of(line)
    if command is None:
        scan.skips.append(Skip(locator, _why_not_cron(line)))
        return
    scan.candidates.extend(inline_candidates(command, SURFACE, locator))


def _command_of(line: str) -> str | None:
    """Return the command portion of a schedule line, or None if it is not one."""
    fields = line.split()
    if fields[0].lower() in SPECIAL_SCHEDULES:
        return " ".join(fields[1:]) if len(fields) > 1 else None
    if len(fields) <= SCHEDULE_FIELDS:
        return None
    if not all(CRON_FIELD.match(field) for field in fields[:SCHEDULE_FIELDS]):
        return None
    return " ".join(fields[SCHEDULE_FIELDS:])


def _why_not_cron(line: str) -> str:
    fields = line.split()
    if fields[0].lower() in SPECIAL_SCHEDULES:
        return f"cron entry has a {fields[0]} schedule but no command"
    if len(fields) <= SCHEDULE_FIELDS:
        return f"not a cron entry: only {len(fields)} whitespace-separated fields"
    bad = next(
        (
            index
            for index, field in enumerate(fields[:SCHEDULE_FIELDS], start=1)
            if not CRON_FIELD.match(field)
        ),
        None,
    )
    if bad is None:  # pragma: no cover -- guards against the two rules drifting
        return "not a cron entry"
    return f"not a cron entry: field {bad} is not a schedule field"
