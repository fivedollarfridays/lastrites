#!/usr/bin/env python3
"""Git-native pre-push hook: public-repo tracked-doctrine guard.

Refuses to push when THE REMOTE BEING PUSHED TO is PUBLIC and any of a fixed set
of internal-doctrine path classes (operating context, task documents,
their archives, agent-memory notes) are currently `git`-tracked. The
default posture -- track these on purpose -- is correct for a private
repo and a leak risk for a public one; this hook closes that gap at the
one place every push has to pass through, regardless of how it was
invoked (a raw shell, a script, a GUI client), the same way the
protected-base-branch guard's git-layer half closes the analogous gap for
commits.

Semantics mirror `bpsai_pair.commands.public_repo_guard.check_public_tracked_doctrine`
(the same logic backing `bpsai-pair audit public-repo-tracked`) exactly:
nothing tracked -> clean, regardless of visibility; PUBLIC + tracked ->
violation; visibility indeterminate + tracked -> a distinct unknown case,
never silently identical to clean. `DOCTRINE_TRACKED_PREFIXES` and the
visibility-cache mechanics are RESTATED here rather than imported: this
script runs on operator machines with a bare `python3` -- no `bpsai_pair`
import, no venv -- the same stdlib-only constraint every other script
under this directory carries. A parity test asserts the two prefix lists
stay identical so they cannot drift apart.

UNKNOWN-VISIBILITY POSTURE: fail OPEN, loudly. `audit public-repo-tracked`
(the CI-runnable command) fails closed on an indeterminate visibility
check, which is the right posture for a pipeline that can retry -- but a
`git push` typed by hand on an unreliable connection, or a laptop with no
network at all, would otherwise never be able to push AT ALL once any
doctrine path is tracked (the ordinary, intended state for a managed
repo). Bricking every offline push is worse than the risk this guard
exists to catch, which is the confirmed PUBLIC case, not the unconfirmed
one -- so this hook allows the push and prints a warning naming exactly
which paths could not be ruled out, pointing at the fail-closed CI
command for the authoritative check.

PUSH TARGET, NOT `origin`: git invokes a pre-push hook with the remote's
name (`$1`) and URL (`$2`), and this script resolves visibility for THAT
remote (see `push_target_slug`). Asking `gh repo view` from the working
directory answers for the DEFAULT remote instead -- so a private `origin`
alongside a public mirror would wave every doctrine path straight through
to the public one, which is precisely the leak this guard exists to stop.
The visibility cache is keyed per remote for the same reason: one
repo-wide cached verdict would re-open the same hole one push later. A
target whose URL is not a github.com repository (a local path, another
forge, GitHub Enterprise) resolves to no slug at all and is reported as
the UNKNOWN case below rather than silently answered from `origin`.

Runtime contract: stdlib only, plain `python3`, no `bpsai_pair` import --
this runs on operator machines with no PairCoder venv, same as every
other script in this directory.

CACHED ALLOWS ARE AUDITED: an allow decided from a CACHED non-public
verdict (rather than a live `gh` check) appends a
`cached_visibility_allow` record to the same bypass ledger the marker
disarm writes to. A cached verdict is the one way this guard can be
disarmed with no operator action at all -- a private->public flip inside
the TTL window looks exactly like a clean push -- so it leaves a trace.
Unlike the marker bypass, an unwritable ledger does not deny here: it
falls back to a LIVE, cache-bypassing check and decides on that, which is
strictly safer than either allowing on stale data or bricking the push.

ESCAPE HATCH (audited bypass): create
`.paircoder/hooks/public_repo_push_guard.off` in the repo root (an empty
file is enough) to push through a confirmed PUBLIC+tracked refusal
anyway. The marker is untracked, per-repo state, so its presence is
visible in `git status` -- that visibility IS the audit, same convention
the base-branch guard's own opt-out marker uses. Every push the marker
disarms appends one record to
`<repo_root>/.paircoder/history/bypass_log.jsonl` (the same unified
ledger every other guard in this project writes); the append is
best-effort and, on failure, the push is DENIED rather than silently
allowed unaudited -- an audited bypass that could not be audited is not
one this hook may grant. A symlink at the marker path is tampering, not
an opt-out, and is never honored.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Mirrors the CLI's public_repo_guard module DOCTRINE_TRACKED_PREFIXES,
# restated here (stdlib-only constraint -- see module docstring). A
# parity test asserts these two lists stay byte-identical.
DOCTRINE_TRACKED_PREFIXES = frozenset({
    ".paircoder/context/",
    ".paircoder/tasks/",
    ".paircoder/history/archived-tasks/",
    ".claude/agent-memory/",
})

# Same asymmetric TTL as bpsai_pair.commands.public_repo_guard: a PUBLIC
# verdict only gets safer by rechecking less; a PRIVATE/INTERNAL verdict's
# staleness is what hides a private -> public flip, so it expires sooner.
VISIBILITY_CACHE_TTL_SECONDS = 24 * 60 * 60
PRIVATE_VISIBILITY_CACHE_TTL_SECONDS = 15 * 60
_VISIBILITY_CACHE_FILENAME = "repo-visibility.json"

OPT_OUT_MARKER = Path(".paircoder/hooks/public_repo_push_guard.off")
BYPASS_LOG_REL = Path(".paircoder/history/bypass_log.jsonl")

# `OWNER/REPO` out of any GitHub remote URL shape git accepts:
# `https://github.com/o/r(.git)`, `ssh://git@github.com/o/r.git`,
# `git@github.com:o/r.git`, `github.com/o/r`. Deliberately github.com-only
# -- a non-GitHub (or GitHub Enterprise) remote's visibility is not
# something `gh repo view` can answer, and pretending otherwise is how the
# guard ends up reporting on the WRONG repository.
_GITHUB_URL_RE = re.compile(
    r"^(?:(?:https?|ssh|git)://)?(?:[^@/]+@)?github\.com[:/]+"
    r"(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+?)(?:\.git)?/?$"
)

DENY_TEMPLATE = (
    "Refusing push: this remote is PUBLIC and the following doctrine-"
    "tracked path(s) are currently tracked:\n{paths}\n\nUntrack these "
    "(`git rm --cached`) or move the repo private before pushing. To "
    "bypass (audited), create {marker}."
)

UNKNOWN_WARNING_TEMPLATE = (
    "public_repo_push_guard: remote visibility could not be determined "
    "(gh unavailable/unauthenticated, not a GitHub remote, or offline) "
    "and the following doctrine-tracked path(s) are present:\n{paths}\n\n"
    "This could NOT be ruled out as a violation -- verify manually "
    "(`gh repo view --json visibility`). Push allowed (fail-open on "
    "unknown visibility avoids bricking offline pushes); see `bpsai-pair "
    "audit public-repo-tracked` for the fail-closed, CI-runnable check.\n"
)

ADVISORY_TEMPLATE = (
    "public_repo_push_guard: disabled by {marker} -- this push to a "
    "PUBLIC remote carrying tracked doctrine path(s) was NOT refused.\n"
)

SYMLINK_WARNING_TEMPLATE = (
    "public_repo_push_guard: {marker} is a symlink -- treating as "
    "tampering, not an opt-out. Refusing the push.\n"
)

AUDIT_FAILURE_TEMPLATE = (
    "Refusing push: the bypass at {marker} could not be recorded to "
    "{log_path} ({error}), so it was not honored -- an unauditable "
    "bypass is denied rather than granted silently. Fix the log path's "
    "permissions and retry."
)


def find_tracked_doctrine_paths(repo_root: Path) -> list[str]:
    """Currently `git`-tracked paths under a `DOCTRINE_TRACKED_PREFIXES`
    class. Empty (never raises) when *repo_root* is not a git checkout.

    Uses `git ls-files -z` (NUL-terminated), not the plain newline-
    terminated form: git's `core.quotePath` (default on) makes a bare
    `git ls-files` emit the whole line as a C-style quoted escape string
    whenever a path contains a non-ASCII or otherwise unusual byte, which
    a plain `startswith(prefix)` check would never match. `-z` disables
    the quoting entirely (raw bytes, NUL-separated).
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-z"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    return [
        rel for rel in (part.strip() for part in result.stdout.split("\0"))
        if rel and any(rel.startswith(prefix) for prefix in DOCTRINE_TRACKED_PREFIXES)
    ]


def _remote_slug(url: str) -> str | None:
    """`OWNER/REPO` for a github.com *url*, else None (see
    `_GITHUB_URL_RE`)."""
    match = _GITHUB_URL_RE.match((url or "").strip())
    if match is None:
        return None
    return f"{match.group('owner')}/{match.group('repo')}"


def _configured_remote_url(repo_root: Path, name: str) -> str:
    """The URL configured for remote *name*, empty when there is none.

    Reads `remote.<name>.url` rather than `git remote get-url`: the latter
    applies `url.<base>.insteadOf` rewriting, which can turn the
    GitHub URL an operator configured into a protocol-swapped or mirrored
    address the slug parser cannot read. Only consulted when git's own
    `$2` (the post-rewrite URL) is not itself github.com-shaped.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "config", "--get", f"remote.{name}.url"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def push_target_slug(repo_root: Path, argv: list[str]) -> str | None:
    """`OWNER/REPO` for the remote this push is going to, or None.

    *argv* is git's own pre-push argument pair: `[remote_name, remote_url]`
    (a bare `git push <url>` passes the URL in both). None means "no
    per-remote target could be resolved" -- either the hook was invoked
    with no arguments at all (a legacy wrapper, or a direct run), or the
    target is not a github.com repository. `repo_visibility` treats the
    two differently; see its docstring.
    """
    name = argv[0].strip() if len(argv) > 0 and argv[0] else ""
    url = argv[1].strip() if len(argv) > 1 and argv[1] else ""
    slug = _remote_slug(url) or _remote_slug(name)
    if slug is not None:
        return slug
    if name:
        return _remote_slug(_configured_remote_url(repo_root, name))
    return None


def _visibility_cache_path(paircoder_dir: Path) -> Path:
    return paircoder_dir / "cache" / _VISIBILITY_CACHE_FILENAME


def _load_cache_document(paircoder_dir: Path) -> dict:
    """The whole cache file as a dict -- `{}` when missing or unreadable."""
    try:
        data = json.loads(_visibility_cache_path(paircoder_dir).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_visibility_cache(paircoder_dir: Path, slug: str | None = None) -> str | None:
    """The cached visibility for *slug* (or the default remote when None),
    or None on a miss/stale/corrupt/unusable entry.

    A `checked_at` that parses but carries no timezone is a cache MISS,
    not an error: subtracting a naive `datetime` from an aware one raises
    `TypeError`, which -- uncaught -- propagates all the way to `main`'s
    blanket fail-open and turns one malformed cache file into a guard that
    silently allows every push. `TypeError` is caught alongside
    `ValueError` here so the entry is simply re-checked live instead.
    """
    document = _load_cache_document(paircoder_dir)
    entry: object = document
    if slug is not None:
        remotes = document.get("remotes")
        entry = remotes.get(slug) if isinstance(remotes, dict) else None
    if not isinstance(entry, dict):
        return None
    checked_at, visibility = entry.get("checked_at"), entry.get("visibility")
    if not isinstance(checked_at, str) or not isinstance(visibility, str):
        return None
    try:
        checked = datetime.fromisoformat(checked_at)
        age = (datetime.now(timezone.utc) - checked).total_seconds()
    except (TypeError, ValueError):
        return None
    ttl = (
        VISIBILITY_CACHE_TTL_SECONDS if visibility == "PUBLIC"
        else PRIVATE_VISIBILITY_CACHE_TTL_SECONDS
    )
    return visibility if 0 <= age <= ttl else None


def _write_visibility_cache(
    paircoder_dir: Path, visibility: str, slug: str | None = None,
) -> None:
    """Best-effort cache write -- never raises (a read-only `.paircoder/`
    must not fail the check it is only trying to speed up). Shares the
    cache file `bpsai_pair.commands.public_repo_guard` uses, so this hook
    and `audit public-repo-tracked` do not double the `gh` call rate.

    A per-remote verdict is stored under `remotes[<slug>]`, leaving the
    top-level `visibility`/`checked_at` pair (the default-remote verdict
    the CLI module reads and writes) untouched -- one repo-wide verdict
    answering for every remote is the cache half of the mis-targeting bug.
    """
    path = _visibility_cache_path(paircoder_dir)
    record = {
        "visibility": visibility,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    document = _load_cache_document(paircoder_dir)
    if slug is None:
        document.update(record)
    else:
        remotes = document.get("remotes")
        document["remotes"] = {**remotes, slug: record} if isinstance(remotes, dict) else {slug: record}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document), encoding="utf-8")
    except OSError:
        pass


def _fetch_visibility(repo_root: Path, slug: str | None = None) -> str | None:
    """`gh repo view [<slug>] --json visibility` -> "PUBLIC"/"PRIVATE"/
    "INTERNAL", or None when the check could not be performed (not a
    GitHub remote, `gh` missing/unauthenticated, network down) -- never
    raises. Without *slug* this asks about the working directory's DEFAULT
    remote, which is only the right question when no push target could be
    resolved at all."""
    command = ["gh", "repo", "view"]
    if slug:
        command.append(slug)
    command += ["--json", "visibility"]
    try:
        result = subprocess.run(
            command, cwd=repo_root, capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    visibility = data.get("visibility")
    return visibility if isinstance(visibility, str) else None


def repo_visibility(
    repo_root: Path,
    paircoder_dir: Path,
    *,
    slug: str | None = None,
    have_target: bool = False,
    use_cache: bool = True,
) -> tuple[str | None, bool]:
    """`(visibility, from_cache)` for the push target, fetched at most once
    per TTL. An indeterminate result (None) is never cached, so a transient
    `gh` failure gets retried next push rather than sticking for the window.

    *have_target* True with *slug* None means git DID name a push target
    and it is not a github.com repository: `gh repo view` from the working
    directory would then answer for a different repo entirely, so the
    result is reported indeterminate (the loud fail-open case) rather than
    borrowed from `origin`. With *have_target* False (no arguments at all)
    the default-remote check still runs, preserving the behavior of an
    older installed wrapper that forwards nothing.
    """
    if slug is None and have_target:
        return None, False
    if use_cache:
        cached = _read_visibility_cache(paircoder_dir, slug)
        if cached is not None:
            return cached, True
    visibility = _fetch_visibility(repo_root, slug)
    if visibility is not None:
        _write_visibility_cache(paircoder_dir, visibility, slug)
    return visibility, False


def _marker_kind(marker: Path) -> str:
    """One `lstat` read of *marker*: `"symlink"`, `"file"` (a regular
    file -- the only shape a legitimate marker takes), or `"absent"`.
    Never follows a symlink -- a symlinked marker is tampering, not an
    opt-out."""
    import stat

    try:
        mode = os.lstat(marker).st_mode
    except OSError:
        return "absent"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    return "absent"


def _log_bypass(
    repo_root: Path, *, target: object, action: str = "marker_disarm",
) -> str | None:
    """Best-effort append one *action* record; return an error string on
    failure. The caller decides what a failure means -- `marker_disarm`
    fails closed, `cached_visibility_allow` re-checks live."""
    entry = {
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "command": "public_repo_push_guard",
        "target": str(target),
        "bypass_type": f"public_repo_push_guard_{action}",
        "gate": "public_repo_push_guard",
        "action": action,
        "branch": "",
        "tool": "git-push",
    }
    log_path = repo_root / BYPASS_LOG_REL
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except OSError as exc:
        return str(exc)
    return None


def check_public_tracked_doctrine(
    repo_root: Path,
    paircoder_dir: Path,
    *,
    slug: str | None = None,
    have_target: bool = False,
    use_cache: bool = True,
):
    """`(violations, unknown_tracked, from_cache)` for *repo_root* --
    mirrors `bpsai_pair.commands.public_repo_guard.check_public_tracked_doctrine`'s
    result shape (minus the dataclass, this script is stdlib-only and
    self-contained), plus the cache provenance this hook audits on:
    `violations` is populated only for a confirmed PUBLIC + tracked match;
    `unknown_tracked` only when visibility could not be determined but
    doctrine paths ARE tracked; `from_cache` says whether the verdict came
    from the TTL cache rather than a live `gh` check. Both lists are empty
    on a genuine clean result."""
    tracked = find_tracked_doctrine_paths(repo_root)
    if not tracked:
        return [], [], False
    visibility, from_cache = repo_visibility(
        repo_root, paircoder_dir,
        slug=slug, have_target=have_target, use_cache=use_cache,
    )
    if visibility == "PUBLIC":
        return tracked, [], from_cache
    if visibility is None:
        return [], tracked, from_cache
    return [], [], from_cache


def evaluate(
    repo_root: Path, remote_args: list[str] | None = None,
) -> tuple[str | None, str | None]:
    """Return `(deny_reason, warning)`. `deny_reason` set -> refuse the
    push (nonzero exit); `warning` set -> printed to stderr but the push
    proceeds. Never both at once.

    *remote_args* is git's pre-push argument pair (`[name, url]`); it is
    what makes this a check of the remote being pushed TO rather than of
    whatever `origin` happens to be.
    """
    paircoder_dir = repo_root / ".paircoder"
    have_target = bool(remote_args)
    slug = push_target_slug(repo_root, remote_args or [])
    violations, unknown_tracked, from_cache = check_public_tracked_doctrine(
        repo_root, paircoder_dir, slug=slug, have_target=have_target,
    )
    if from_cache and not violations and not unknown_tracked:
        # A cached non-public verdict is the one disarm no operator ever
        # took: it must leave a trace. If it cannot, re-decide LIVE rather
        # than allow on unauditable stale data (or brick the push).
        if _log_bypass(
            repo_root, target=slug or "<default remote>",
            action="cached_visibility_allow",
        ) is not None:
            violations, unknown_tracked, _ = check_public_tracked_doctrine(
                repo_root, paircoder_dir,
                slug=slug, have_target=have_target, use_cache=False,
            )
    if violations:
        paths = "\n".join(f"  - {p}" for p in violations)
        marker = repo_root / OPT_OUT_MARKER
        kind = _marker_kind(marker)
        if kind == "symlink":
            sys.stderr.write(SYMLINK_WARNING_TEMPLATE.format(marker=OPT_OUT_MARKER))
            return DENY_TEMPLATE.format(paths=paths, marker=OPT_OUT_MARKER), None
        if kind == "file":
            error = _log_bypass(repo_root, target=marker)
            if error is not None:
                return (
                    AUDIT_FAILURE_TEMPLATE.format(
                        marker=OPT_OUT_MARKER, log_path=BYPASS_LOG_REL, error=error,
                    ),
                    None,
                )
            return None, ADVISORY_TEMPLATE.format(marker=OPT_OUT_MARKER)
        return DENY_TEMPLATE.format(paths=paths, marker=OPT_OUT_MARKER), None
    if unknown_tracked:
        paths = "\n".join(f"  - {p}" for p in unknown_tracked)
        return None, UNKNOWN_WARNING_TEMPLATE.format(paths=paths)
    return None, None


def main() -> int:
    """Fail OPEN on the guard's own errors; fail CLOSED on a confirmed
    PUBLIC + tracked match. A pre-push hook aborts the push on any
    nonzero exit -- git's own convention, matching `git_commit_guard.py`'s
    pre-commit posture."""
    try:
        repo_root = Path.cwd()
        if not (repo_root / ".paircoder").is_dir():
            return 0
        # git's own pre-push arguments: remote name, then remote URL.
        deny_reason, warning = evaluate(repo_root, sys.argv[1:3])
    except Exception as exc:  # fail open: never brick a push on our own bug
        sys.stderr.write(f"public_repo_push_guard: fail-open ({exc})\n")
        return 0
    if warning:
        sys.stderr.write(warning)
    if deny_reason is None:
        return 0
    sys.stderr.write(f"BLOCKED BY ENFORCEMENT GATE\n\n{deny_reason}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
