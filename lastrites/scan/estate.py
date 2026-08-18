"""The whole-estate scan: open every named surface, cluster, report.

Deliberately explicit about targets rather than clever about them --
`scan_estate` scans exactly what it is handed, so `surface_count` means
"surfaces attempted" and a zero there is a real, reportable alarm rather
than a bug in a discovery heuristic. A file that could not be opened still
counts as an attempt: it contributes a skip, which is the loud signal, and
dropping it from the count would quietly shrink the denominator.
"""

from __future__ import annotations

from collections.abc import Iterable

from lastrites.scan.blindspots import DEFAULT_BLIND_SPOTS
from lastrites.scan.cluster import cluster_candidates
from lastrites.scan.models import BlindSpot, ScanReport, Skip, SurfaceScan
from lastrites.scan.redact import describe_exception
from lastrites.scan.surfaces import crontab, envfile, launchd


def _guarded(scanner, path) -> SurfaceScan:
    """Contain a scanner crash to the one surface that caused it.

    Each parser is written to be tolerant, but "tolerant" is a property of
    code, and code has bugs. Without this, one damaged file out of forty
    discards the surfaces already scanned AND the ones never reached, and
    the operator gets a traceback instead of a report -- THREAT-MODEL §5's
    failure mode at maximum blast radius.
    """
    try:
        return scanner.scan_file(path)
    except Exception as exc:  # noqa: BLE001 -- last line of defence, by design
        scan = SurfaceScan(surface=scanner.SURFACE, source=str(path), readable=False)
        scan.skips.append(
            Skip(str(path), f"scanner crashed: {describe_exception(exc)}")
        )
        return scan


def scan_estate(
    pepper: bytes,
    *,
    crontabs: Iterable = (),
    plists: Iterable = (),
    env_files: Iterable = (),
    blind_spots: Iterable[BlindSpot] | None = None,
    discovery_skips: Iterable[Skip] = (),
) -> ScanReport:
    surfaces: list[SurfaceScan] = []
    for scanner, paths in (
        (crontab, crontabs),
        (launchd, plists),
        (envfile, env_files),
    ):
        surfaces.extend(_guarded(scanner, path) for path in paths)

    candidates = [candidate for scan in surfaces for candidate in scan.candidates]
    declared = DEFAULT_BLIND_SPOTS if blind_spots is None else blind_spots
    return ScanReport(
        credentials=cluster_candidates(candidates, pepper),
        surfaces=surfaces,
        blind_spots=list(declared),
        discovery_skips=list(discovery_skips),
    )
