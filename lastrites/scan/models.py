"""The shapes the scan layer passes around.

`Candidate` is the only one that ever holds a raw value, and it is
in-memory only: it is consumed by the clusterer, which keeps the
fingerprint and drops the value. Nothing downstream of `cluster_candidates`
can represent a secret.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Skip:
    """Something the parser could not read. Counted, never swallowed."""

    locator: str
    reason: str


@dataclass(frozen=True)
class Candidate:
    """A possible secret, still holding its value. In-memory only."""

    key: str
    value: str
    surface: str
    locator: str
    fmt: str = "plain"


@dataclass
class SurfaceScan:
    """One file, opened once: what came out and what would not parse."""

    surface: str
    source: str
    candidates: list[Candidate] = field(default_factory=list)
    skips: list[Skip] = field(default_factory=list)
    #: False when the surface could not be read or parsed AT ALL, as opposed
    #: to being read fine with some unparseable parts. An estate where every
    #: surface is unreadable looks identical to a clean one unless we can
    #: tell those two states apart.
    readable: bool = True

    @property
    def skip_count(self) -> int:
        return len(self.skips)


@dataclass(frozen=True)
class Copy:
    """A `copied-at` edge: a place this credential was found."""

    surface: str
    locator: str
    key: str
    fmt: str


@dataclass
class Credential:
    """A fingerprint cluster. Carries no value, by construction."""

    fingerprint: str
    provider: str
    kind: str
    rotation_class: str
    copies: list[Copy] = field(default_factory=list)

    @property
    def copy_count(self) -> int:
        return len(self.copies)


@dataclass(frozen=True)
class BlindSpot:
    """A surface class this scan structurally cannot see."""

    name: str
    detail: str


@dataclass
class ScanReport:
    credentials: list[Credential] = field(default_factory=list)
    surfaces: list[SurfaceScan] = field(default_factory=list)
    blind_spots: list[BlindSpot] = field(default_factory=list)
    #: Roots and directories that could not be enumerated. Discovery is a
    #: surface-enumeration step, so a `--root` typo that silently finds
    #: nothing is the same false "no copies here" one level up.
    discovery_skips: list[Skip] = field(default_factory=list)

    @property
    def surface_count(self) -> int:
        """Surfaces ATTEMPTED, including ones that could not be opened."""
        return len(self.surfaces)

    @property
    def readable_count(self) -> int:
        return sum(1 for scan in self.surfaces if scan.readable)

    @property
    def skip_count(self) -> int:
        return sum(scan.skip_count for scan in self.surfaces) + len(
            self.discovery_skips
        )
