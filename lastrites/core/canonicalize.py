"""Per-format canonicalizers.

Normalize a raw scanned value to the form that gets fingerprinted, so
the same credential copied in different surface conventions (quoted vs
bare, pretty-printed vs compact JSON) clusters to one fingerprint.
"""

from __future__ import annotations

import json

_QUOTE_CHARS = ("'", '"')


def canonicalize_plain(value: str) -> str:
    stripped = value.strip()
    if (
        len(stripped) >= 2
        and stripped[0] == stripped[-1]
        and stripped[0] in _QUOTE_CHARS
    ):
        stripped = stripped[1:-1]
    return stripped.strip()


def canonicalize_json(value: str) -> str:
    parsed = json.loads(value)
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"))


_CANONICALIZERS = {
    "plain": canonicalize_plain,
    "json": canonicalize_json,
}


def canonicalize(value: str, fmt: str = "plain") -> str:
    try:
        canonicalizer = _CANONICALIZERS[fmt]
    except KeyError:
        raise ValueError(f"unknown canonicalizer format: {fmt!r}") from None
    return canonicalizer(value)
