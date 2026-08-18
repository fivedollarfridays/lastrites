"""Shared assignment parsing for the line-oriented surfaces.

Crontabs and env files disagree about almost everything except this: a
secret shows up as `NAME=value`. One parser, one identifier rule, so the
two surfaces cannot drift apart on what counts as malformed.
"""

from __future__ import annotations

import re

from lastrites.scan.models import Candidate
from lastrites.scan.screen import screen_candidate

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: `KEY=value` embedded in a command line: a crontab job prefix, or a flag
#: like `--token=...`. The lookbehind rejects mid-word and mid-path matches
#: (`./out=`, `a.b=`) but deliberately ALLOWS a preceding `-`, because
#: `curl --token=...` is a mainstream way to leak a credential into the
#: process table and is exactly the forgotten copy the graph exists to find.
INLINE_ASSIGNMENT = re.compile(r"(?<![\w./])([A-Za-z_][A-Za-z0-9_]*)=(\S+)")


def split_assignment(line: str) -> tuple[str, str] | None:
    """Split `[export ]KEY=value`. Returns None when there is no `=` at all."""
    text = line.strip()
    if text.startswith("export "):
        text = text[len("export ") :].lstrip()
    key, sep, value = text.partition("=")
    if not sep:
        return None
    return key.strip(), value.strip()


def is_identifier(key: str) -> bool:
    return bool(IDENTIFIER.match(key))


def candidate_from(
    key: str, value: str, surface: str, locator: str
) -> Candidate | None:
    """Screen an assignment and promote it to a Candidate, or drop it.

    A drop here is NOT a skip: the parser understood the line perfectly
    and decided the value is not a secret. Only unparseable input is a
    skip -- conflating the two would bury the signal §5 exists to protect.
    """
    if not screen_candidate(key, value).accepted:
        return None
    return Candidate(key=key, value=value, surface=surface, locator=locator)


def inline_candidates(text: str, surface: str, locator: str) -> list[Candidate]:
    """Pull `KEY=value` prefixes out of a command line."""
    found = []
    for match in INLINE_ASSIGNMENT.finditer(text):
        candidate = candidate_from(match.group(1), match.group(2), surface, locator)
        if candidate is not None:
            found.append(candidate)
    return found
