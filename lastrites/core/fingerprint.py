"""Fingerprinting: HMAC-SHA256(pepper, canonicalized_value).

Never a bare hash (THREAT-MODEL.md #2) — a bare hash of a low-entropy
secret is a dictionary attack waiting politely. The pepper makes the
fingerprint useless without it.
"""

from __future__ import annotations

import hashlib
import hmac

from lastrites.core.canonicalize import canonicalize


def fingerprint(pepper: bytes, value: str, fmt: str = "plain") -> str:
    canonical = canonicalize(value, fmt=fmt)
    return hmac.new(pepper, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
