"""Describing malformed input without reproducing it.

Skip reasons are printed to a terminal and serialized into `--json`, so
they are an output channel like any other and invariant 1 binds them: no
raw values. The temptation is to quote the offending text back at the
operator, which is exactly wrong here, because on the surfaces lastrites
reads the offending text is routinely the secret itself:

- a PEM body line ends in `=` padding, so "the text left of the first `=`"
  is a chunk of private key;
- a bare JWT does the same;
- plistlib's own error strings embed the element that failed to parse.

So skip reasons are a closed vocabulary plus non-reversible shape facts --
a length and an offset are enough to find the line, and reveal nothing.
"""

from __future__ import annotations

from string import ascii_letters, digits


_LEAD = set(ascii_letters + "_")
_REST = _LEAD | set(digits)


def _valid_at(index: int, char: str) -> bool:
    # ASCII-only, matching assignments.IDENTIFIER exactly. `str.isalnum()`
    # accepts non-ASCII, which would report "no invalid character" for a key
    # the parser had just rejected for one.
    return char in (_LEAD if index == 0 else _REST)


def describe_key(key: str) -> str:
    """Say why a key is not an identifier, using only its shape."""
    if not key:
        return "empty"
    for index, char in enumerate(key):
        if not _valid_at(index, char):
            return f"{len(key)} chars, first invalid character at offset {index}"
    return f"{len(key)} chars"


def describe_exception(exc: BaseException) -> str:
    """Name the failure by type only -- parser messages quote their input."""
    return type(exc).__name__
