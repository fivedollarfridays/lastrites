"""Opening a file is itself a step that can fail, and failing it silently
is the §5 bug: an unreadable `.env` is not an absent `.env`."""

from __future__ import annotations

from pathlib import Path

from lastrites.scan.models import Skip, SurfaceScan


def open_surface(path, surface: str) -> tuple[SurfaceScan, str | None]:
    """Start a SurfaceScan and read the file, or record why we could not."""
    scan = SurfaceScan(surface=surface, source=str(path))
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        # strerror is a fixed OS string ("No such file or directory"), not
        # file content, so it is safe to include; the path is already public.
        scan.skips.append(
            Skip(str(path), f"unreadable: {exc.strerror or type(exc).__name__}")
        )
        scan.readable = False
        return scan, None
    return scan, text
