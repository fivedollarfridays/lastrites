"""Shannon entropy, in bits per character.

Per-character rather than total, so the measure does not simply reward
length -- a 40-character filesystem path is long, not secret.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )
