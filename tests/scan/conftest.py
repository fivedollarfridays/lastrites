"""Shared locations for the scanner fixtures.

Every planted value in `tests/fixtures/` is a `mock-*` string. Nothing in
this tree is, or resembles closely enough to be mistaken for, a live
credential.
"""

from pathlib import Path

import pytest

ESTATE = Path(__file__).resolve().parents[1] / "fixtures" / "estate"

# The one value planted in all three surfaces -- the clustering AC.
SHARED_TOKEN = "mock-cf-7f3a2b91c4d6e805a1b2c3d4e5f60718"

PEPPER = b"\x2a" * 32


@pytest.fixture
def estate():
    return ESTATE


@pytest.fixture
def pepper():
    return PEPPER
