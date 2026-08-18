#!/usr/bin/env python3
"""Git-native pre-commit hook: protected base-branch enforcement.

``base_branch_guard.py`` (the PreToolUse hook) matches COMMAND TEXT emitted
by Claude tool calls -- a ``git commit`` typed into a shell it never sees,
or run through a wrapper its regex does not match, sails through
ungoverned. It also evaluates at command START, before the command has
actually done anything, so state can drift between the check and the
operation it was checking.

This script closes both gaps by moving enforcement into git's OWN commit
lifecycle instead of guessing at it from text: installed as
``.git/hooks/pre-commit`` (see ``bpsai_pair.commands.upgrade_git_hook``), it
fires on every commit regardless of how it was invoked -- Claude, a raw
shell, a script, a GUI client -- because git itself is calling it, evaluated
against the ACTUAL branch at the ACTUAL moment of the commit. The
PreToolUse guard still runs too, as fast-path advice; this is the
enforcement.

Reuses ``base_branch_guard.py``'s branch/marker/bypass-log primitives (same
directory, imported as a sibling module) rather than re-implementing them,
so the marker opt-out, bypass logging, and ``BPSAI_ENGAGE_MODE`` exemption
stay byte-compatible with the PreToolUse guard's semantics -- one source of
truth for what "protected" and "opted out" mean, enforced at two layers.

KNOWN SOFT SPOT: the ``BPSAI_ENGAGE_MODE`` exemption is a plain
environment variable, readable and settable by the very process this
enforcement layer exists to constrain -- a raw shell that can set env
vars can set this one too. It stays (it is a REQUIRED, ratified-AC
exemption: engage drivers must never be blocked by this guard, and it
must stay byte-compatible with ``base_branch_guard.py``'s own exemption),
but it is now AUDITED: every commit it exempts on an otherwise-protected
branch appends a ``gate: "git_commit_guard", action: "engage_mode_exempt"``
record to the bypass log, so the exemption's use stays visible even
though its trigger is self-reported. Stronger run-binding (an identity
this script cannot spoof from inside the same process) is tracked
follow-up work, not a gap this audit-only mitigation closes.

No "target is the marker file itself" case here, unlike the PreToolUse
guard: by the time ``pre-commit`` fires, a marker the operator created
already exists on disk (however it got there), so the ordinary disarm
check already covers committing the marker's own creation. There is no
chicken-and-egg problem to special-case at this layer.

Runtime contract: stdlib only, plain ``python3``, no ``bpsai_pair``
import -- same as ``base_branch_guard.py``; this runs on operator machines
with no PairCoder venv.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import base_branch_guard as guard  # noqa: E402
except Exception as _sibling_import_error:  # noqa: E402
    # Fail OPEN: this import sits outside main()'s own try/except, so a
    # missing, unreadable, or syntax-broken sibling would otherwise raise
    # before main() is ever entered -- an uncaught exception here exits
    # nonzero, which git treats as a hook FAILURE and BLOCKS the commit,
    # contradicting main()'s own deliberate fail-open posture (a bug in
    # this script must never brick every commit fleet-wide).
    sys.stderr.write(
        f"git_commit_guard: fail-open (sibling import failed: "
        f"{_sibling_import_error})\n"
    )
    sys.exit(0)

# `bpsai-pair init` writes this ONE-SHOT marker when the checkout is
# already sitting on a protected branch at init time (the common case --
# the operator has not created a feature branch yet), so the very first
# scaffolding commit is not denied out-of-box. Unlike
# `base_branch_guard.OPT_OUT_MARKER` (permanent by design), this one is
# consumed -- deleted -- immediately after its bypass is durably logged,
# so a second commit on the same protected branch is guarded normally
# again. It is scoped to this git-native hook only; it has no bearing on
# the PreToolUse guard's Edit/Write checks.
INIT_ONCE_MARKER = Path(".paircoder/hooks/git_commit_guard.init-once")

INIT_ONCE_SYMLINK_WARNING = (
    "git_commit_guard: {marker} is a symlink -- treating as tampering, "
    "not a bypass. Guard remains ARMED.\n"
)

INIT_ONCE_CONSUMED_ADVISORY = (
    "git_commit_guard: one-shot init bypass consumed ({marker}) -- "
    "protected branch ({branch}) is guarded normally starting with the "
    "next commit.\n"
)


def _stage_bypass_log(repo_root: Path) -> None:
    """Best-effort `git add` of the bypass log this hook just wrote to.

    `git add -A` (the smoke/adopt-scaffolding sequence) snapshots the index
    BEFORE this hook runs, so the audit record it appends is invisible to
    that commit unless the hook stages it itself -- the same technique any
    pre-commit auto-fixer uses to fold its own edits into the commit it is
    gating. Never raises: a failed `git add` here still leaves the write
    already durable on disk (the bypass IS audited); it only means the log
    surfaces as a new untracked file instead of riding this commit.
    """
    try:
        subprocess.run(
            ["git", "add", "--", str(guard.BYPASS_LOG_REL)],
            cwd=str(repo_root),
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def _consume_init_once_marker(repo_root: Path, *, branch: str, marker: Path) -> str | None:
    """Return a deny reason, or None to allow -- consuming *marker* on the
    allow path.

    The bypass-log append happens BEFORE the marker is deleted: a write
    failure denies the commit (an unauditable bypass is not one this hook
    may grant) but leaves the marker in place for a retry, rather than
    spending the one shot on a bypass nothing recorded. A symlink at the
    marker path is tampering, never honored, and is left untouched.
    """
    if guard._marker_kind(marker) == "symlink":
        sys.stderr.write(INIT_ONCE_SYMLINK_WARNING.format(marker=INIT_ONCE_MARKER))
        return guard.DENY_TEMPLATE.format(branch=branch)
    error = guard._log_marker_bypass(
        repo_root, action="init_first_commit", branch=branch,
        tool="git-commit", target=marker,
    )
    if error is not None:
        return guard.AUDIT_FAILURE_TEMPLATE.format(
            branch=branch, action="init_first_commit",
            marker=INIT_ONCE_MARKER, log_path=guard.BYPASS_LOG_REL, error=error,
        )
    _stage_bypass_log(repo_root)
    try:
        marker.unlink()
    except OSError:
        pass
    sys.stderr.write(
        INIT_ONCE_CONSUMED_ADVISORY.format(marker=INIT_ONCE_MARKER, branch=branch)
    )
    return None


def _log_engage_exemption(repo_root: Path, *, branch: str) -> None:
    """Best-effort audit of the ``BPSAI_ENGAGE_MODE`` exemption, appended
    only when it actually flips THIS commit from denied to allowed.

    Deliberately NOT fail-closed on a write failure, unlike the marker
    disarm path: the exemption is a REQUIRED, ratified-AC guarantee (an
    engage driver's commit must never be blocked by this guard), so an
    unauditable exemption is still honored here rather than turned into a
    block -- the audit trail is best-effort visibility, not a condition
    of the exemption itself.

    Routed through ``guard._write_bypass_entry`` (the sibling module's
    shared writer) rather than opening ``guard.BYPASS_LOG_REL`` directly,
    so the unified-sink + one-time legacy-ledger migration note live in
    exactly one place, reused by both hook scripts.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "command": "git_commit_guard",
        "target": str(repo_root),
        "bypass_type": "engage_mode_commit_exempt",
        "gate": "git_commit_guard",
        "action": "engage_mode_exempt",
        "branch": branch,
        "tool": "git-commit",
    }
    guard._write_bypass_entry(repo_root, entry)


def evaluate_commit(repo_root: Path, git_dir: Path, env: dict) -> str | None:
    """Return a deny reason, or None to allow this commit.

    Allowed without further checks when: the checkout is not
    paircoder-managed, or HEAD is not on a protected branch -- checked
    FIRST, before the engage exemption or either marker's on-disk
    presence is consulted, so none of it is audited for a commit that
    would have been allowed anyway (mirrors ``base_branch_guard.py``'s own
    "unprotected branches short-circuit before any marker logic"
    doctrine). Once a branch is confirmed protected: the engage exemption
    (audited when it fires), then the one-shot init marker (scoped to
    exactly one commit, checked before the persistent opt-out so it is
    never shadowed by it), then the persistent opt-out marker via the
    same audited disarm path ``base_branch_guard.py`` uses for every
    non-marker-write edit.
    """
    if not (repo_root / ".paircoder").is_dir():
        return None
    branch = guard.current_branch(git_dir)
    if branch is None or branch not in guard.protected_branches(git_dir):
        return None
    if env.get(guard.ENGAGE_MARKER) == "1":
        _log_engage_exemption(repo_root, branch=branch)
        return None
    init_marker = repo_root / INIT_ONCE_MARKER
    if guard._marker_kind(init_marker) != "absent":
        return _consume_init_once_marker(repo_root, branch=branch, marker=init_marker)
    marker = repo_root / guard.OPT_OUT_MARKER
    return guard._evaluate_marker_disarm(
        repo_root, branch=branch, tool="git-commit", target=marker, marker=marker,
        shape="ambiguous",
    )


def main() -> int:
    """Fail OPEN on the guard's own errors; fail CLOSED on a policy match.

    A pre-commit hook blocks on any nonzero exit -- this returns 1 on a
    deny (git's own convention), not the PreToolUse guard's exit-2
    convention, since the two run under different protocols.

    This is a deliberate, tested trade-off: an unhandled bug in THIS
    script must never brick every commit fleet-wide, so enforcement at the
    git layer is best-effort, not airtight, by design. That is acceptable
    only because it is not the only line of defense -- the PreToolUse
    guard (``base_branch_guard.py``) still runs first, as fast-path
    advisory enforcement over the tool-call text Claude Code sees, before
    a write ever reaches ``git commit`` at all. This script closes the
    gap that advisory layer cannot (a raw shell, a script, a GUI client),
    it does not replace it.
    """
    try:
        checkout = guard.find_checkout(Path.cwd())
        reason = (
            evaluate_commit(checkout[0], checkout[1], dict(os.environ))
            if checkout is not None
            else None
        )
    except Exception as exc:  # fail open: never brick a commit on our own bug
        sys.stderr.write(f"git_commit_guard: fail-open ({exc})\n")
        return 0
    if reason is None:
        return 0
    sys.stderr.write(f"BLOCKED BY ENFORCEMENT GATE\n\n{reason}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
