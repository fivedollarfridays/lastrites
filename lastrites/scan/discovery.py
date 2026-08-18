"""Finding scannable files under a root.

Discovery decides which surfaces the parsers ever get to see, so THREAT-MODEL
§5 binds it as much as it binds them: a mistyped `--root` that quietly
yields nothing is the same false "no copies here", one level up. Every root
we cannot enumerate, and every directory we cannot descend, comes back as a
counted skip alongside the files.

`os.walk` is used rather than `Path.rglob` for exactly this reason -- glob
swallows `OSError` internally and offers no way to learn what it could not
read.
"""

from __future__ import annotations

import os
from pathlib import Path

from lastrites.scan.models import Skip

SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"})

BUCKETS = ("crontabs", "plists", "env_files")


def _classify_file(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".plist"):
        return "plists"
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return "env_files"
    if "crontab" in name:
        return "crontabs"
    return None


def _record_walk_error(skips: list[Skip]):
    def record(error: OSError) -> None:
        where = error.filename or "<unknown path>"
        why = error.strerror or type(error).__name__
        skips.append(Skip(str(where), f"could not enumerate: {why}"))

    return record


def _prune(dirpath: str, dirnames: list[str], skips: list[Skip]) -> None:
    """Drop noise directories, and report symlinked ones we decline to follow.

    `os.walk(followlinks=False)` would otherwise pass over a symlinked
    directory in total silence -- neither walked nor reported, which is the
    §5 failure the whole module is written to avoid. Following them instead
    would risk cycles and double-counting, so we decline loudly.
    """
    keep = []
    for name in sorted(dirnames):
        if name in SKIP_DIRS:
            continue
        path = Path(dirpath) / name
        if path.is_symlink():
            skips.append(Skip(str(path), "symlinked directory, not followed"))
            continue
        keep.append(name)
    dirnames[:] = keep


def _collect(root: Path, found: dict[str, list[Path]], skips: list[Skip]) -> None:
    for dirpath, dirnames, filenames in os.walk(
        root, onerror=_record_walk_error(skips)
    ):
        # Prune noise by directory NAME under the root, never by full path --
        # an ancestor named `venv` above the root must not hide the root.
        _prune(dirpath, dirnames, skips)
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            bucket = _classify_file(path)
            if bucket is None:
                continue
            if path.is_file():
                found[bucket].append(path)
            else:
                skips.append(Skip(str(path), "not a readable file (broken symlink?)"))


def discover(root) -> tuple[dict[str, list[Path]], list[Skip]]:
    """Group scannable files under `root`, and report what could not be walked."""
    found: dict[str, list[Path]] = {bucket: [] for bucket in BUCKETS}
    skips: list[Skip] = []

    path = Path(root)
    if not path.is_dir():
        skips.append(Skip(str(path), "root is not a directory"))
        return found, skips

    _collect(path, found, skips)
    return found, skips


def _deduped(paths: list[Path]) -> list[Path]:
    """Overlapping --root arguments must not inflate the surface and skip totals."""
    seen: dict[Path, None] = {}
    for path in paths:
        seen.setdefault(Path(path).resolve(), None)
    return list(seen)


def resolve_targets(args) -> tuple[dict[str, list], list[Skip]]:
    """Merge explicit --crontab/--plist/--env-file args with --root discovery.

    Shared by both `scan` and `sweep`, which take identical target flags.
    """
    targets = {
        "crontabs": [Path(p) for p in args.crontab],
        "plists": [Path(p) for p in args.plist],
        "env_files": [Path(p) for p in args.env_file],
    }
    discovery_skips: list[Skip] = []
    for root in args.root:
        found, skips = discover(root)
        discovery_skips.extend(skips)
        for bucket, paths in found.items():
            targets[bucket].extend(paths)
    return {
        bucket: _deduped(paths) for bucket, paths in targets.items()
    }, discovery_skips
