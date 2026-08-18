"""No alerting endpoint or topic literal anywhere in the repo.

THREAT-MODEL SS4 treats the escalation channel as part of the attack
surface; WATCH-TOPOLOGY names the push topic itself as the sensitive
credential. The channel is config, never code -- this is the grep-proof
enforcement of that rule, run across every .py and .md file in the repo,
not just lastrites/sweep/. Mirrors the verification command in the task
spec exactly, so a change here is a change to that command too.
"""

from __future__ import annotations

import re
from pathlib import Path

_PATTERN = re.compile(r"ntfy\.sh/[A-Za-z0-9_-]+|hooks\.slack|discord\.com/api/webhooks")
_EXCLUDED_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "dist",
    "build",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _candidate_files():
    root = _repo_root()
    this_file = Path(__file__).resolve()
    for suffix in ("*.py", "*.md"):
        for path in root.rglob(suffix):
            if path == this_file:
                continue
            if any(part in _EXCLUDED_DIR_NAMES for part in path.parts):
                continue
            yield path


def test_no_alerting_endpoint_literals_anywhere_in_the_repo():
    hits = []
    for path in _candidate_files():
        text = path.read_text(errors="ignore")
        if _PATTERN.search(text):
            hits.append(str(path.relative_to(_repo_root())))
    assert not hits, f"alerting endpoint/topic literal found in: {hits}"
