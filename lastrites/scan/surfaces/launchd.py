"""launchd plist scanning.

Secrets live in the `EnvironmentVariables` dict and, occasionally, as
`KEY=value` arguments in `ProgramArguments`. plistlib raises a small zoo
of exception types on damaged files; a scanner that dies on one of them
stops scanning the rest of the estate, so parse failure is caught broadly
and recorded as a skip rather than propagated.
"""

from __future__ import annotations

import plistlib
from pathlib import Path

from lastrites.scan.assignments import candidate_from, inline_candidates
from lastrites.scan.models import Skip, SurfaceScan
from lastrites.scan.redact import describe_exception

SURFACE = "launchd-plist"
ENV_BLOCK = "EnvironmentVariables"
ARGS_BLOCK = "ProgramArguments"


def scan_file(path) -> SurfaceScan:
    scan = SurfaceScan(surface=SURFACE, source=str(path))
    data = _load(scan, path)
    if data is None:
        return scan
    if not isinstance(data, dict):
        # The file read and parsed fine; it is just not a launchd job. That
        # is a skip, not an unreadable surface -- marking it unreadable would
        # make a scan of one such file raise the "saw nothing" alarm.
        scan.skips.append(Skip(str(path), "plist root is not a dictionary"))
        return scan
    _scan_environment(scan, data, str(path))
    _scan_arguments(scan, data, str(path))
    return scan


def _load(scan: SurfaceScan, path):
    try:
        with Path(path).open("rb") as handle:
            return plistlib.load(handle)
    except OSError as exc:
        scan.skips.append(
            Skip(str(path), f"unreadable: {exc.strerror or type(exc).__name__}")
        )
    except Exception as exc:  # noqa: BLE001 -- tolerant by design; see module docstring
        # Type name only: plistlib error strings embed the element that
        # failed to parse, which can be secret material. See scan/redact.py.
        scan.skips.append(
            Skip(str(path), f"plist parse failed: {describe_exception(exc)}")
        )
    scan.readable = False
    return None


def _scan_environment(scan: SurfaceScan, data: dict, source: str) -> None:
    if ENV_BLOCK not in data:
        return
    block = data[ENV_BLOCK]
    if not isinstance(block, dict):
        scan.skips.append(
            Skip(f"{source}:{ENV_BLOCK}", f"{ENV_BLOCK} is not a dictionary")
        )
        return
    for key, value in block.items():
        if not isinstance(key, str):
            # Binary plists can carry non-string dict keys; plistlib does not
            # reject them. We cannot name the consumer, so we cannot record it.
            scan.skips.append(
                Skip(f"{source}:{ENV_BLOCK}", "environment key is not a string")
            )
            continue
        # A non-string (<integer>, <true/>) cannot carry a secret. Understood,
        # not skipped -- skips mean "could not read", not "read and dismissed".
        if not isinstance(value, str):
            continue
        candidate = candidate_from(key, value, SURFACE, f"{source}:{ENV_BLOCK}/{key}")
        if candidate is not None:
            scan.candidates.append(candidate)


def _scan_arguments(scan: SurfaceScan, data: dict, source: str) -> None:
    block = data.get(ARGS_BLOCK)
    if not isinstance(block, list):
        return
    for index, argument in enumerate(block):
        if not isinstance(argument, str):
            continue
        scan.candidates.extend(
            inline_candidates(argument, SURFACE, f"{source}:{ARGS_BLOCK}[{index}]")
        )
