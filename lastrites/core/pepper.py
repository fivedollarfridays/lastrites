"""Pepper management.

A machine-local secret that peppers every fingerprint HMAC. Created once,
kept out of the credential graph and out of the repo, and never logged or
printed.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

PEPPER_BYTES = 32
DEFAULT_PEPPER_PATH = Path.home() / ".lastrites" / "pepper"


def load_or_create_pepper(path: Path = DEFAULT_PEPPER_PATH) -> bytes:
    path = Path(path)
    try:
        return _create(path)
    except FileExistsError:
        return _read(path)


class PepperError(Exception):
    """The pepper file is unusable — refusing to fingerprint with it."""


def _create(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    value = secrets.token_bytes(PEPPER_BYTES)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        written = os.write(fd, value)
        if written != PEPPER_BYTES:
            raise PepperError(
                f"short write creating pepper ({written}/{PEPPER_BYTES} bytes)"
            )
        os.fsync(fd)
    finally:
        os.close(fd)
    return value


def _read(path: Path) -> bytes:
    """A truncated pepper (crash between create and write) would silently
    degrade every fingerprint to HMAC-with-a-trivial-key — the exact
    bare-hash posture THREAT-MODEL §2 exists to prevent. Refuse it loudly;
    never fingerprint with less pepper than was promised.
    """
    value = path.read_bytes()
    if len(value) < PEPPER_BYTES:
        raise PepperError(
            f"pepper at {path} is {len(value)} bytes, expected {PEPPER_BYTES} — "
            "refusing to fingerprint. Recover the original healthy pepper if "
            "this machine already has fingerprints; a fresh one orphans every "
            "existing fingerprint."
        )
    os.chmod(path, 0o600)
    return value
