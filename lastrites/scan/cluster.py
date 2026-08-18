"""Fingerprint clustering -- the trick that builds the graph without a registry.

Identical fingerprints across surfaces are, by definition, copies of one
credential (DESIGN §Discovery step 4). This is the step that finds the
copy you forgot: the old crontab line, the second machine, the `.env` from
two migrations ago.

It is also where raw values stop existing. A `Candidate` goes in carrying
its value; a `Credential` comes out carrying a fingerprint. Nothing
downstream can leak what nothing downstream holds.
"""

from __future__ import annotations

from lastrites.core.fingerprint import fingerprint
from lastrites.scan.classify import UNKNOWN, Classification, classify
from lastrites.scan.models import Candidate, Copy, Credential


def _absorb(credential: Credential, evidence: Classification) -> None:
    """Let a well-named copy document its anonymous twins.

    First non-unknown evidence wins and is never overwritten, so one
    `CLOUDFLARE_API_TOKEN=` in a crontab labels the same value found under
    `BLOB=` somewhere else -- but a later, vaguer copy cannot un-label it.
    """
    if credential.provider == UNKNOWN:
        credential.provider = evidence.provider
    if credential.kind == UNKNOWN:
        credential.kind = evidence.kind


def cluster_candidates(candidates: list[Candidate], pepper: bytes) -> list[Credential]:
    clusters: dict[str, Credential] = {}
    for candidate in candidates:
        digest = fingerprint(pepper, candidate.value, fmt=candidate.fmt)
        credential = clusters.get(digest)
        if credential is None:
            credential = Credential(
                fingerprint=digest,
                provider=UNKNOWN,
                kind=UNKNOWN,
                rotation_class=UNKNOWN,
            )
            clusters[digest] = credential
        credential.copies.append(
            Copy(
                surface=candidate.surface,
                locator=candidate.locator,
                key=candidate.key,
                fmt=candidate.fmt,
            )
        )
        _absorb(credential, classify(candidate.key, candidate.value))
    return list(clusters.values())
