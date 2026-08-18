#!/usr/bin/env python3
"""PreToolUse hook: protected base-branch guard.

Denies file mutations and git commits while a paircoder-managed checkout is
sitting on its default branch or ``dev``, unless the session carries the
engage-driver dispatch marker. That single gate catches the wrong-role,
wrong-branch and wrong-session-type failures at once -- including an
orchestrator session drifting into inline implementation on dev.

Two-sided failure posture:
  * fail CLOSED on the policy match itself -- a matched violation is denied,
    exit 2, reason on stderr (the convention `bpsai_pair.commands.enforce`
    already uses).
  * fail OPEN on the guard's own errors -- a hook that bricks all editing
    because of an odd filesystem or a malformed event is worse than the
    violation it guards. Errors are logged to stderr and the tool is allowed.

The engage driver marker is ``BPSAI_ENGAGE_MODE=1``, set on every headless
driver subprocess by ``ClaudeCodeAdapter._build_env``. Engage owns
branch-cutting for its drivers, so its sessions are exempt by construction.

Runtime contract: stdlib only, plain ``python3``, no ``bpsai_pair`` import --
this runs on operator machines with no PairCoder venv.

ESCAPE HATCH (audited bypass): create ``.paircoder/hooks/base_branch_guard.off``
in the repo root (an empty file is enough). Writing that specific path is
itself exempted from this guard, so the hatch is reachable even from a
session the guard has already blocked -- unlike editing
``.claude/settings.json``, which is a mutating call the guard would deny on
the very branch it is meant to rescue you from. The marker is untracked,
per-repo state (not payload), so its presence is visible in ``git status``
-- that visibility IS the audit. Do not add a silent env kill switch. The
guard prints an advisory to stderr whenever the marker actually disarms a
match, so opt-out use stays visible even when nothing is denied.

PERSISTENCE IS INTENTIONAL: the marker does not expire and survives
``upgrade``/config-sync (``upgrade_session_hooks.guard_opted_out`` skips
re-asserting the guard's ``settings.json`` wiring while it is present, and
prints a line naming the repo and the marker path whenever it does). The
use case is ops-journal repos that are legitimately, permanently exempt --
not a one-shot unblock. The compensating control for that permanence is
audit logging, below; do not add an expiry to "fix" the persistence
without also removing the logging that makes it safe to leave alone.

AUDITED, NOT JUST VISIBLE: ``git status``
visibility is necessary but not sufficient -- nothing previously recorded
*when* a bypass happened or *what* it exempted. Both places the marker
disarms an outcome (creating/editing the marker itself, and the marker
being present when it flips an otherwise-denied edit to allowed) now
append one record to ``<repo_root>/.paircoder/history/bypass_log.jsonl``
-- the SAME ledger the CLI's own ``core.bypass_log`` writes (unified sink;
this hook previously wrote a second, split sink at the repo-root
``.paircoder/bypass_log.jsonl``, which went unignored and blocked the
fleet transactional sweep's clean-tree precheck):
``{ts, gate: "base_branch_guard", action: "marker_write" | "marker_disarm",
branch, tool, target}``. The append is best-effort (a read-only
``.paircoder/`` must not brick every edit) -- but on failure the guard
does NOT fall back to exempting unaudited: it denies instead, since an
audited bypass that could not be audited is not one this hook may grant.
A pre-existing legacy ledger at the old root-level path is never read,
moved, or deleted -- the first write to the unified ledger notes its
presence with one ``gate: "ledger_migration"`` record and leaves it alone.

TAMPERING, NOT AN OPT-OUT: a symlink AT the
marker path is never honored as the marker, in either direction. Resolving
symlinks before comparing paths would let a symlink planted at the marker
path make an edit of whatever it points at read as "writing the marker
itself"; and ``Path.is_file()`` on a symlinked marker resolves through it
too, so a symlink pointing at any existing file would read as "the opt-out
marker is present" and disarm the guard for every protected edit. Both are
treated as tampering: the guard stays ARMED, a warning goes to stderr, and
no bypass is logged (nothing was exempted). The symlink check is a single
``lstat`` read taken fresh at the point of use, not a flag computed once
and reused later -- two separate stat calls leave a window where a marker
swapped for a symlink in between is read by the stale, pre-swap flag.

UNPROTECTED BRANCHES SHORT-CIRCUIT BEFORE ANY MARKER LOGIC: the marker
(present, absent, written, or tampered) has zero effect on the outcome of
a call on a branch this guard does not protect, so none of it -- the
symlink check, the bypass log, the advisory -- is consulted or written to
on one. Doing so anyway was itself a bug: it polluted the bypass log with
spurious ``marker_write`` records for edits nothing was ever exempting,
and could deny a write on an inert branch if the log happened to be
unwritable. The disarm advisory is also deferred until AFTER the bypass
log append succeeds -- printing "guard disabled, not being guarded"
immediately before "BLOCKED" (on an append failure) is self-contradictory.

EVERY PRESENT PATH KEY IS JUDGED, NOT JUST ONE: ``NotebookEdit``
carries both ``file_path`` and ``notebook_path`` in its ``tool_input``, and
only ``notebook_path`` is the actual write target -- but a malformed or
adversarial event can populate both. Collapsing them with
``tool_input.get("file_path") or tool_input.get("notebook_path")`` judged
only whichever key won the ``or`` (``file_path``, always, when both are
present), so a marker planted at ``file_path`` disarmed the guard for a
real mutation at ``notebook_path`` -- and logged the allow as
``marker_write``, a label ``NotebookEdit`` can never legitimately earn (it
cannot write a plain non-notebook file), corrupting the one artifact this
guard's audit doctrine leans on. ``mutating_targets`` now returns every
present key, and the marker-write arm requires ALL of them to resolve to
the marker; any disagreement is judged as an ordinary mutation (denied,
or allowed-and-logged-as-``marker_disarm`` only if the opt-out marker
file is actually present on disk) -- never granted, and never logged, as
``marker_write``.

EVERY PRESENT PATH KEY RESOLVES ITS OWN CHECKOUT, NOT JUST ONE: the fix
above made ``mutating_targets`` return every present key, but ``evaluate``
originally still derived the checkout, management check,
branch check, and marker short-circuit from a SINGLE directory --
``touched_directory``'s first-present-key pick. A malformed/adversarial
``NotebookEdit`` can pair an unmanaged, no-checkout decoy at ``file_path``
with the real managed-repo write at ``notebook_path``: the decoy's
directory resolved no checkout, so the whole call was allowed even though
``notebook_path`` writes a protected branch in a real managed checkout.
Every present key now gets its own ``find_checkout``/management/branch
resolution via ``_resolve_checkout``; the call is denied if ANY of them
independently names a protected-branch mutation, regardless of what any
other key resolves to. A key that resolves to no checkout, an unmanaged
checkout, or an unprotected branch imposes no constraint -- it is simply
not one of the keys the marker-write agreement or the deny loop below
considers.

ONE AUDIT ENTRY PER REPO THE ALLOW ACTUALLY BYPASSED: the fix above let a
single event's path keys resolve to genuine opt-out markers in TWO
DIFFERENT managed repos at once, and the marker-write arm allowed such a
call correctly -- but it audited only the first key's repo, via
``protected[0]``. The second repo's ledger then had no record that an
opt-out write occurred against it, even though the guard was, in fact,
disarmed there too. The marker-write arm now writes one audit entry per
DISTINCT repo among the agreeing keys (deduped by repo root, so a
same-repo dual-key event such as `NotebookEdit`'s `file_path`/
`notebook_path` pair still yields exactly one entry, unchanged from
before). If any one repo's ledger write fails, the call is denied overall
per the audited-bypass doctrine above -- but a repo whose write already
succeeded keeps its record; there is no log to roll back an append to.

AGENT-MEMORY WRITES ARE EXEMPT -- A DIRECTORY-PREFIX MATCH, NOT AN
EXACT PATH: writes strictly inside a repo's ``.claude/agent-memory/`` are
allowed on a protected branch (agents write their own memory notes there
without needing a feature branch first). This is deliberately unlike
``_marker_kind``'s single ``lstat`` of one known, fixed path -- agent-memory
notes can sit anywhere under an open-ended subtree, so ``is_agent_memory_write``
walks every path prefix from the ``.claude``/``agent-memory`` boundary down
to the target, not just the target itself, checking two things: (1) the
boundary components match EXACTLY and ADJACENTLY (never a substring --
``evil.claude/agent-memory-backup/`` stays denied), and (2) no prefix along
the way is a symlink (a fresh ``lstat`` per prefix, never ``resolve()``,
which would follow the very links this is checking for -- same reasoning
``_marker_kind`` uses for the opt-out marker). A symlink traversed FORWARD
out of the boundary (``agent-memory/escape -> <repo>``) leaves every path
component intact, so the lexical match alone would still say "inside
agent-memory" while the write lands on arbitrary source; only the walk
catches that. ``FileNotFoundError`` on a prefix means that component
doesn't exist yet -- the normal case for a brand-new note in an unmade
subdirectory -- so the walk stops and reports no symlink; any OTHER
``OSError`` (permission denied, ``ELOOP``, a file where a directory was
expected) DECLINES the exemption instead, since a bypass this hook cannot
verify is not one it may grant. The exemption is writes-only and judged
per present path key under the SAME multi-key agreement the marker-write
arm uses: every present key must independently be an agent-memory write,
or a real edit could ride through under cover of an in-memory-looking key.
``mutating_targets`` is empty for a Bash ``git commit`` event, so this
exemption never reaches, and cannot weaken, the commit gate.

CONTEXT-AWARE REMEDY, KEYED ON CHANGE SHAPE: the deny message used
to name BOTH remedies -- ``bpsai-pair engage <backlog>`` and "create a
feature branch first" -- unconditionally. Field specimen: an operator
committing ``bpsai-pair upgrade`` artifacts (``.claude``/config payload) on
a protected branch was told to dispatch with engage, but there IS no
backlog for an upgrade commit -- that half of the remedy was unexecutable
in the situation that triggered it. ``classify_change_shape`` buckets a
denied call as ``"upgrade"`` (``.claude/**``, ``.paircoder/config.yaml``,
``CLAUDE.md``/``AGENTS.md``, the pinned payload manifest), ``"bookkeeping"``
(``.paircoder/context/state.md``, ``.paircoder/tasks/**``,
``.paircoder/history/**``), or ``"code"`` (everything else) -- derived
SOLELY from the same path data ``evaluate()`` already resolves for each
protected target, never a second source of truth (no ``git diff --cached``
subprocess to discover staged files). Only ``"code"`` keeps the engage
prescription; ``"upgrade"``/``"bookkeeping"`` get a shape-named,
feature-branch-only remedy. Every OTHER case -- targets that disagree in
shape, or a call with no per-target path data at all (a Bash
``git commit`` invocation, which this guard recognizes but never resolves
to specific staged files) -- degrades to ``GENERIC_DENY_TEMPLATE``: the
plain, always-executable feature-branch remedy, never the engage
prescription. This is a deny path throughout; an unclassifiable shape
never becomes an allow.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

ENGAGE_MARKER = "BPSAI_ENGAGE_MODE"
MUTATING_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
# Every key a MUTATING_TOOLS tool_input might carry a write-target path
# under. `NotebookEdit` is the only tool that populates both today, but a
# future tool with its own alternate path field reproduces the shape --
# `mutating_targets` judges whichever of these are present, not just one.
PATH_KEYS = ("file_path", "notebook_path")
DEFAULT_PROTECTED = ("main", "master", "dev")

# Adjacent EXACT path components, never a substring: `.claude`/`agent-memory`
# must sit back-to-back so `evil.claude/agent-memory-backup/` stays denied.
AGENT_MEMORY_BOUNDARY = (".claude", "agent-memory")

# `git [global-opts...] commit`. The option alternation deliberately excludes
# subcommands, so `git log --grep commit` is not mistaken for a commit. Kept
# as `touched_directory`'s fallback for text it cannot tokenize (unbalanced
# quotes) -- see that function's docstring for why it is no longer the
# primary detector.
GIT_COMMIT_RE = re.compile(
    r"\bgit\b(?:\s+(?:-C\s+\S+|-c\s+\S+|--git-dir=\S+|--work-tree=\S+|--\w[\w-]*))*"
    r"\s+commit\b"
)
GIT_DASH_C_RE = re.compile(r"\bgit\b\s+(?:-c\s+\S+\s+)*-C\s+(\S+)")

# Option tokens `touched_directory`'s tokenized git-commit detection treats
# as belonging BEFORE `commit`, not as a distinct subcommand -- kept in
# exact correspondence with `GIT_COMMIT_RE`'s alternation so the tokenized
# detector accepts exactly the same shapes the regex detector did.
_GIT_VALUE_FLAGS = ("-C", "-c")

DENY_TEMPLATE = (
    "Protected base branch ({branch}). Run `bpsai-pair engage <backlog>` to "
    "dispatch this work, or create a feature branch first."
)

UPGRADE_DENY_TEMPLATE = (
    "Protected base branch ({branch}). This looks like `bpsai-pair upgrade` "
    "artifacts (`.claude`/config payload) -- there is no backlog to dispatch "
    "for an upgrade commit. Create a feature branch first."
)

BOOKKEEPING_DENY_TEMPLATE = (
    "Protected base branch ({branch}). This looks like bookkeeping "
    "(state/task/history updates) -- there is no backlog to dispatch for a "
    "bookkeeping commit. Create a feature branch first."
)

GENERIC_DENY_TEMPLATE = (
    "Protected base branch ({branch}). Create a feature branch first."
)

# `classify_change_shape` buckets a denied call's targets into one of
# these keys; `"code"` is the only shape that keeps the engage
# prescription -- any key absent here (an unrecognized or ambiguous
# shape) falls back to `GENERIC_DENY_TEMPLATE` in `_deny_reason`.
_DENY_TEMPLATE_BY_SHAPE = {
    "code": DENY_TEMPLATE,
    "upgrade": UPGRADE_DENY_TEMPLATE,
    "bookkeeping": BOOKKEEPING_DENY_TEMPLATE,
}

# Upgrade-artifact paths, relative to a repo root: the whole `.claude`
# payload tree plus the handful of top-level files `bpsai-pair upgrade`
# also refreshes.
UPGRADE_SHAPE_ROOT = ".claude"
UPGRADE_SHAPE_FILES = (".paircoder/config.yaml", "CLAUDE.md", "AGENTS.md")
UPGRADE_SHAPE_SUFFIXES = ("claude_payload_manifest.json",)

# Bookkeeping paths: the state/task/history subtrees `bpsai-pair`'s own
# task-completion workflow writes -- none of these is backlog-dispatchable
# code either.
BOOKKEEPING_SHAPE_FILES = (".paircoder/context/state.md",)
BOOKKEEPING_SHAPE_ROOTS = (".paircoder/tasks", ".paircoder/history")

OPT_OUT_MARKER = Path(".paircoder/hooks/base_branch_guard.off")

# Unified sink: same ledger `bpsai_pair.core.bypass_log` writes.
# `LEGACY_BYPASS_LOG_REL` is the pre-unification root-level path this hook
# used to write -- never read, moved, or deleted, only noted once (see
# `_write_bypass_entry`) if still present on a repo mid-transition.
BYPASS_LOG_REL = Path(".paircoder/history/bypass_log.jsonl")
LEGACY_BYPASS_LOG_REL = Path(".paircoder/bypass_log.jsonl")

# Every row this hook (or its sibling git_commit_guard.py) appends carries
# the CLI's own record shape (`timestamp`/`command`/`bypass_type`, matching
# `bpsai_pair.core.bypass_log.log_bypass`) ALONGSIDE its own extra fields
# (`gate`/`action`/`branch`/`tool`/`target`) -- both writers share this one
# ledger, so `bpsai-pair audit bypasses`/`audit summary` must be able to
# read, filter, and display a row from either one. `bypass_type` values
# below are registered in `core.bypass_log.KNOWN_BYPASS_TYPES`.
_BYPASS_TYPE_BY_ACTION = {
    "marker_write": "base_branch_guard_marker_write",
    "marker_disarm": "base_branch_guard_marker_disarm",
    "init_first_commit": "git_commit_guard_init_first_commit",
    "engage_mode_exempt": "base_branch_guard_engage_mode_exempt",
}

ADVISORY_TEMPLATE = (
    "base_branch_guard: disabled by {marker} -- protected branch ({branch}) "
    "edits are NOT being guarded.\n"
)

SYMLINK_WARNING_TEMPLATE = (
    "base_branch_guard: {marker} is a symlink -- treating as tampering, "
    "not an opt-out. Guard remains ARMED.\n"
)

AUDIT_FAILURE_TEMPLATE = (
    "Protected base branch ({branch}). The {action} bypass at {marker} "
    "could not be recorded to {log_path} ({error}), so it was not "
    "honored -- an unauditable bypass is denied rather than granted "
    "silently. Fix the log path's permissions and retry."
)


def find_checkout(start: Path) -> tuple[Path, Path] | None:
    """Return ``(repo_root, git_dir)`` for *start*, or None if not in a repo.

    Handles the worktree layout, where ``.git`` is a file pointing at
    ``<common>/worktrees/<name>`` rather than a directory.
    """
    for directory in (start, *start.parents):
        marker = directory / ".git"
        if marker.is_dir():
            return directory, marker
        if marker.is_file():
            text = marker.read_text(encoding="utf-8").strip()
            if text.startswith("gitdir:"):
                gitdir = Path(text.split(":", 1)[1].strip())
                if not gitdir.is_absolute():
                    gitdir = directory / gitdir
                return directory, gitdir
    return None


def _strip_prefix(ref: str, prefix: str) -> str | None:
    """The part of *ref* after *prefix*, or None if it does not start there.

    Branch names are paths: ``feature/main`` is not ``main``. Taking the last
    path segment instead collapses them, and a guard that reads a feature
    branch as a base branch denies every edit on it.
    """
    return ref[len(prefix):] if ref.startswith(prefix) and len(ref) > len(prefix) else None


def current_branch(git_dir: Path) -> str | None:
    """Branch name from ``HEAD``, or None when detached/unreadable."""
    head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    if not head.startswith("ref:"):
        return None
    return _strip_prefix(head.split(":", 1)[1].strip(), "refs/heads/")


def protected_branches(git_dir: Path) -> set[str]:
    """``dev`` + the usual defaults + this remote's actual default branch."""
    protected = set(DEFAULT_PROTECTED)
    common = git_dir
    commondir = git_dir / "commondir"
    if commondir.is_file():
        candidate = Path(commondir.read_text(encoding="utf-8").strip())
        common = candidate if candidate.is_absolute() else git_dir / candidate
    origin_head = common / "refs" / "remotes" / "origin" / "HEAD"
    if origin_head.is_file():
        text = origin_head.read_text(encoding="utf-8").strip()
        if text.startswith("ref:"):
            default = _strip_prefix(
                text.split(":", 1)[1].strip(), "refs/remotes/origin/"
            )
            if default:
                protected.add(default)
    return protected


def _resolve_checkout(directory: Path) -> tuple[Path, Path, str] | None:
    """``(repo_root, git_dir, branch)`` if *directory* sits inside a
    paircoder-managed checkout currently on a PROTECTED branch, else None.

    Takes *directory* as-is -- no file-to-parent normalization. Callers
    starting from a path key that might name a file (rather than an
    already-resolved directory) do that conversion themselves before
    calling this, so a single shared helper serves both the per-target
    loop in `evaluate` and the Bash git-commit directory, which
    was already a directory and must not be re-adjusted.
    """
    checkout = find_checkout(directory)
    if checkout is None:
        return None
    repo_root, git_dir = checkout
    if not (repo_root / ".paircoder").is_dir():
        return None
    branch = current_branch(git_dir)
    if branch is None or branch not in protected_branches(git_dir):
        return None
    return repo_root, git_dir, branch


def mutating_targets(event: dict) -> list[Path]:
    """Every absolute path key an Edit/Write-family tool call would write.

    A `NotebookEdit` `tool_input` can carry both `file_path` and
    `notebook_path`; only `notebook_path` is the real write target, but a
    malformed/adversarial event can populate both. Returning
    every present key -- instead of collapsing to one with `.get(a) or
    .get(b)` -- lets `evaluate` judge each independently rather than
    silently trusting whichever key happened to win the `or`.
    """
    tool = str(event.get("tool_name", ""))
    if tool not in MUTATING_TOOLS:
        return []
    tool_input = event.get("tool_input") or {}
    cwd = str(event.get("cwd") or os.getcwd())
    targets: list[Path] = []
    for key in PATH_KEYS:
        raw = tool_input.get(key)
        if not raw:
            continue
        candidate = Path(str(raw))
        targets.append(candidate if candidate.is_absolute() else Path(cwd) / candidate)
    return targets


def mutating_target(event: dict) -> Path | None:
    """One write-target path for callers that only need somewhere to look.

    Thin wrapper over `mutating_targets` for `touched_directory`, which
    only needs A path to resolve the touched checkout -- which present
    key wins here carries no security meaning, unlike in `evaluate`,
    where EVERY present key must be judged independently.
    """
    targets = mutating_targets(event)
    return targets[0] if targets else None


def classify_change_shape(protected: list[tuple[Path, tuple[Path, Path, str]]]) -> str:
    """The shared change shape across every entry in *protected* (each
    ``(target, (repo_root, git_dir, branch))`` pair `evaluate()` already
    resolved): ``"upgrade"`` (`.claude/**`, `.paircoder/config.yaml`,
    `CLAUDE.md`/`AGENTS.md`, the pinned payload manifest), ``"bookkeeping"``
    (`.paircoder/context/state.md`, `.paircoder/tasks/**`,
    `.paircoder/history/**`), ``"code"`` (everything else), or
    ``"ambiguous"`` when different entries disagree.

    Path-only, derived from the same data `evaluate()` already resolves for
    every protected key -- never a second source of truth. Matched by whole
    path segments (via `Path.parts`), same reasoning as
    `is_agent_memory_write`'s boundary check: `evil.claude/` or
    `.paircoder/tasks-backup/` must never false-match a real boundary.
    `_deny_reason` treats an unrecognized OR ambiguous shape identically
    (the generic, always-executable remedy) -- a mixed-shape call must not
    guess which half of the context is the "real" one.
    """
    shapes = set()
    for target, (repo_root, _git_dir, _branch) in protected:
        try:
            rel = os.path.relpath(os.path.normpath(str(target)), str(repo_root))
        except ValueError:
            shapes.add("code")
            continue
        parts = Path(rel).parts
        if not parts or parts[0] == os.pardir:
            shapes.add("code")
            continue
        if parts[0] == UPGRADE_SHAPE_ROOT:
            shapes.add("upgrade")
            continue
        posix_rel = "/".join(parts)
        if posix_rel in UPGRADE_SHAPE_FILES or parts[-1] in UPGRADE_SHAPE_SUFFIXES:
            shapes.add("upgrade")
        elif posix_rel in BOOKKEEPING_SHAPE_FILES:
            shapes.add("bookkeeping")
        elif len(parts) >= 2 and "/".join(parts[:2]) in BOOKKEEPING_SHAPE_ROOTS:
            shapes.add("bookkeeping")
        else:
            shapes.add("code")
    return shapes.pop() if len(shapes) == 1 else "ambiguous"


def _deny_reason(branch: str, shape: str) -> str:
    """The deny message for *branch*, worded for *shape*.

    ``"code"`` keeps the original engage-or-feature-branch dual remedy;
    every other shape (including an unrecognized or ambiguous one) gets
    the plain, always-executable feature-branch-only remedy -- see the
    module docstring's "CONTEXT-AWARE REMEDY" section.
    """
    template = _DENY_TEMPLATE_BY_SHAPE.get(shape, GENERIC_DENY_TEMPLATE)
    return template.format(branch=branch)


def is_agent_memory_write(target: Path) -> bool:
    """True when *target* is a file strictly inside a ``.claude/agent-memory``.

    See the module docstring's "AGENT-MEMORY WRITES ARE EXEMPT" section for
    the full rationale; the short version is two hard-won details:

    1. **Adjacent EXACT components, never a substring.** ``.claude`` and
       ``agent-memory`` must sit back-to-back in ``target``'s normalised
       parts. ``os.path.normpath`` collapses ``.``/``..`` lexically before
       the walk, so ordinary path variance (``a/../a/file``) is not mistaken
       for an escape -- but that normalisation is ``..``-safe only; see (2).

    2. **A symlink at or below the boundary declines the exemption.** A
       ``..`` segment is caught lexically above, but a symlink traversed
       FORWARD leaves every component intact -- ``agent-memory/escape ->
       <repo>`` would otherwise smuggle a write to arbitrary source through a
       path that matches component-for-component. Every prefix from the
       ``.claude`` boundary down to *target* is walked with a fresh
       ``lstat`` (never ``resolve()``, which would follow the very links
       this is checking for). ``FileNotFoundError`` on a prefix means that
       component doesn't exist yet -- the normal case for a brand-new note,
       and nothing can exist below a missing component -- so the walk stops
       and reports no symlink. Any OTHER ``OSError`` (permission denied,
       ``ELOOP``, a file where a directory was expected) DECLINES the
       exemption instead: this hook fails open on its own bugs, but a bypass
       it cannot verify is not one it may grant. Declining is not a brick --
       it is exactly the pre-exemption behaviour, a denied write on a
       protected branch.
    """
    parts = Path(os.path.normpath(str(target))).parts
    boundary, name = AGENT_MEMORY_BOUNDARY
    for index in range(len(parts) - 2):
        if parts[index] != boundary or parts[index + 1] != name:
            continue
        for end in range(index + 1, len(parts) + 1):
            try:
                mode = os.lstat(Path(*parts[:end])).st_mode
            except FileNotFoundError:
                return True
            except OSError:
                return False
            if stat.S_ISLNK(mode):
                return False
        return True
    return False


def touched_directory(event: dict) -> Path | None:
    """Directory whose checkout this tool call would mutate, if any.

    The Bash-command git-commit check tokenizes with ``shlex`` first,
    inline here rather than a separate function -- this stdlib-only
    payload module sits at the architecture function-count cap (see
    ``_write_bypass_entry``'s docstring). A quoted argument that
    merely SPELLS "git commit" -- a ``gh issue comment`` body quoting
    this guard's own message, for instance -- collapses to ONE opaque
    shlex token (the whole dequoted argument), never the two adjacent
    bare ``git``/``commit`` words a real invocation produces, so this no
    longer mistakes quoted text for a command.

    Tokenizes with ``punctuation_chars=True`` (a ``shlex.shlex`` instance,
    not the plain ``shlex.split`` convenience function): a shell control
    operator (``;``/``&&``/``||``/``|``/``&``) with NO surrounding
    whitespace otherwise glues onto the adjacent word -- plain
    ``shlex.split("true;git commit -m x")`` yields ``"true;git"`` as ONE
    token, so no token ever equals the bare word ``git`` and the command
    sails through. ``punctuation_chars=True`` always splits an operator
    out as its own token, attached or not, while still leaving operator
    characters INSIDE a quoted argument alone (so the quoted-text fix
    above is unaffected). Falls back to ``GIT_COMMIT_RE`` on
    unparsable input (unbalanced quotes): a malformed command cannot be
    tokenized reliably, so this stays fail-closed (the pre-fix behavior)
    rather than silently exempting something that might still commit.

    The flag-skip loop between ``git`` and its subcommand treats ANY
    dash-prefixed token (short, bare ``--``, or long, one dash or two) as
    a skippable global option, not just ``--long-flags`` -- a review
    finding: a short global flag ahead of the subcommand (``git -q
    commit``, ``git -v commit``, ``git -p commit``) previously broke the
    scan before it ever reached ``commit`` and evaded detection entirely.
    Git's own syntax puts every global option (dash-prefixed, by
    definition) before the subcommand, so the first NON-dash token after
    ``git`` (once any known value-flag's value is also consumed) is
    always the subcommand itself -- skipping every dash-prefixed token
    cannot false-positive onto an unrelated subcommand's bare argument.
    """
    target = mutating_target(event)
    if target is not None:
        return target if target.is_dir() else target.parent
    tool = str(event.get("tool_name", ""))
    if tool != "Bash":
        return None
    tool_input = event.get("tool_input") or {}
    cwd = str(event.get("cwd") or os.getcwd())
    command = str(tool_input.get("command", ""))
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        tokens = None
    invokes_commit = bool(GIT_COMMIT_RE.search(command)) if tokens is None else False
    for index, token in enumerate(tokens or ()):
        if token != "git":
            continue
        cursor = index + 1
        while cursor < len(tokens):
            candidate = tokens[cursor]
            if candidate in _GIT_VALUE_FLAGS and cursor + 1 < len(tokens):
                cursor += 2  # the flag AND its value, e.g. `-C <path>`
                continue
            if candidate.startswith("-") and candidate != "-":
                cursor += 1  # any other flag-shaped token: short (`-q`),
                # bare `--`, or long (`--no-pager`/`--git-dir=x`)
                continue
            break
        if cursor < len(tokens) and tokens[cursor] == "commit":
            invokes_commit = True
            break
    if not invokes_commit:
        return None
    dash_c = GIT_DASH_C_RE.search(command)
    if dash_c:
        named = Path(dash_c.group(1))
        return named if named.is_absolute() else Path(cwd) / named
    return Path(cwd)


def _same_path(a: Path, b: Path) -> bool:
    """Path equality WITHOUT resolving symlinks.

    ``Path.resolve()`` follows symlinks in every path component, so a
    symlink planted at *b* (the marker) would make an edit of whatever it
    points at compare equal to *b* itself. ``os.path.normpath`` still
    collapses ``.``/``..`` segments so ordinary path variance (a caller
    passing ``a/../a/file`` for ``a/file``) does not cause a false
    mismatch -- it just never follows a symlink to get there.
    """
    return os.path.normpath(str(a)) == os.path.normpath(str(b))


def _marker_kind(marker: Path) -> str:
    """One ``lstat`` read of *marker*, taken fresh at the point of use.

    Returns ``"symlink"``, ``"file"`` (a regular file -- the only shape a
    legitimate marker takes), or ``"absent"`` (covers both "does not
    exist" and any other file type). A caller that computes
    ``marker.is_symlink()`` once and later calls ``marker.is_file()``
    separately leaves a window between the two stat calls where a marker
    swapped for a symlink in between is read by the FIRST call's now-stale
    result -- a single read at the actual decision point has no such gap
    to race within.
    """
    try:
        mode = os.lstat(marker).st_mode
    except OSError:
        return "absent"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    return "absent"


def _migration_note(repo_root: Path) -> dict:
    """The one-time record noting a legacy ledger's presence.

    Never reads its content -- the legacy file is history, not a source
    to replay; this only records that it exists at migration time. Not a
    bypass itself (nothing was exempted), so it carries no ``bypass_type``.
    """
    return {
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "command": "ledger_migration",
        "target": str(LEGACY_BYPASS_LOG_REL),
        "gate": "ledger_migration",
        "action": "legacy_ledger_present",
        "branch": "",
        "tool": "",
    }


def _write_bypass_entry(repo_root: Path, entry: dict) -> str | None:
    """Best-effort append *entry* to the unified bypass ledger; return an
    error string on failure.

    Shared by both hook scripts (``git_commit_guard.py`` calls this via
    ``guard._write_bypass_entry``) so the unified-sink + migration-note
    mechanics live in exactly one place. A legacy pre-unification ledger
    still present at the repo root gets ONE ``ledger_migration`` record
    ahead of *entry* -- the legacy file itself is left untouched, never
    read, moved, or deleted.

    The trigger is "legacy ledger present AND the unified ledger does not
    already contain a migration note" -- NOT "the unified ledger file
    does not yet exist". ``bpsai_pair.core.bypass_log.log_bypass`` writes
    this SAME file; if the CLI creates it first (e.g. an upgrade run logs
    its own bypass before any hook ever fires), a file-nonexistence
    trigger would never fire again, silently losing the migration signal.
    Scanning for an existing note (inline below, not a separate helper --
    this stdlib-only payload module sits at the architecture function-count
    cap) keeps this correct regardless of which writer creates the file
    first, while staying idempotent -- one note per repo, however many
    bypasses (hook- or CLI-driven) precede it. Any read failure (missing
    file, malformed line, foreign schema) is simply "no note found yet",
    never raised.

    The write itself must never crash the caller (a read-only
    ``.paircoder/`` would then brick every edit); the caller decides
    whether to fail closed on a non-None return.
    """
    log_path = repo_root / BYPASS_LOG_REL
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        needs_migration_note = False
        if (repo_root / LEGACY_BYPASS_LOG_REL).is_file():
            needs_migration_note = True
            try:
                with open(log_path, "r", encoding="utf-8") as existing:
                    for line in existing:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            row = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if row.get("gate") == "ledger_migration":
                            needs_migration_note = False
                            break
            except OSError:
                pass
        with open(log_path, "a", encoding="utf-8") as handle:
            if needs_migration_note:
                handle.write(json.dumps(_migration_note(repo_root)) + "\n")
            handle.write(json.dumps(entry) + "\n")
    except OSError as exc:
        return str(exc)
    return None


def _ledger_writable(repo_root: Path) -> str | None:
    """Probe whether this repo's unified ledger could be appended to;
    return the same error string ``_write_bypass_entry`` would.

    Deliberately side-effect-free with respect to ENTRIES: it opens the
    ledger for append and writes nothing, so a call that is ultimately
    DENIED leaves no allow-side record behind in any repo. This is what
    lets ``evaluate`` decide a multi-repo call BEFORE committing any repo's
    entry -- the alternative (write, then discover a later repo cannot be
    audited) leaves a durable "allowed" record for a call that was refused,
    which is worse than either outcome it is made of.

    The empty file the probe may create is the same file
    ``_write_bypass_entry`` would have created; it carries no rows and no
    claim.
    """
    log_path = repo_root / BYPASS_LOG_REL
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8"):
            pass
    except OSError as exc:
        return str(exc)
    return None


def _log_marker_bypass(
    repo_root: Path, *, action: str, branch: str | None, tool: str, target: Path
) -> str | None:
    """Best-effort append one bypass record; return an error string on failure.

    Every allow-because-of-the-marker outcome is a workflow bypass under
    this project's fail-closed-audited-bypass doctrine, so it must be
    logged -- but the log write itself must never crash the hook (a
    read-only ``.paircoder/`` would then brick every edit). The caller is
    responsible for failing closed when this returns non-None: an audited
    bypass that could not be audited is not a bypass this hook may grant.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "command": "base_branch_guard",
        "target": str(target),
        "bypass_type": _BYPASS_TYPE_BY_ACTION.get(action, action),
        "gate": "base_branch_guard",
        "action": action,
        "branch": branch or "",
        "tool": tool,
    }
    return _write_bypass_entry(repo_root, entry)


def _log_engage_exemption(repo_root: Path, *, branch: str, tool: str, target: Path) -> None:
    """Best-effort audit of the ``BPSAI_ENGAGE_MODE`` exemption, appended
    only when it actually flips THIS call from denied to allowed (i.e.
    the call resolved to a protected checkout).

    Independent trio review remediation: this guard's own ``evaluate``
    used to check the marker before any checkout resolution at all, so
    the exemption fired -- unaudited -- for every call regardless of
    whether it would have been denied. ``git_commit_guard.py``'s sibling
    exemption was already audited this way; this closes the gap between
    the two enforcement layers.

    Deliberately NOT fail-closed on a write failure, mirroring
    ``git_commit_guard.py``'s own engage exemption: this is a REQUIRED,
    ratified-AC guarantee (an engage driver's call must never be blocked
    by this guard), so an unauditable exemption is still honored here
    rather than turned into a block -- the audit trail is best-effort
    visibility, not a condition of the exemption itself.
    """
    _log_marker_bypass(
        repo_root, action="engage_mode_exempt", branch=branch, tool=tool, target=target,
    )


def _decide_then_commit(plans: list, tool: str, arm) -> str | None:
    """Run *arm* over every participating repo in DECIDE mode, then -- only
    if not one of them refused -- in COMMIT mode.

    This ordering is the whole fix: an arm that writes as it goes leaves
    repo A's "allowed" record behind when repo B turns out to deny, so the
    ledger ends up asserting an allow for a call that was refused. Nothing
    is appended until every participating repo has agreed.

    Each marker is lstat'd exactly ONCE, here, at the decision point, and
    that single reading is handed to both passes: re-reading it for the
    commit pass would reopen exactly the TOCTOU window ``_marker_kind``'s
    single-read-at-point-of-use rule exists to close.
    """
    resolved = [(t, r, b, m, _marker_kind(m)) for t, r, b, m in plans]
    for commit in (False, True):
        for target, repo_root, branch, marker, kind in resolved:
            reason = arm(
                repo_root, branch=branch, tool=tool, target=target,
                marker=marker, kind=kind, commit=commit,
            )
            if reason is not None:
                return reason
    return None


def _evaluate_marker_write(
    repo_root: Path, *, branch: str, tool: str, target: Path, marker: Path,
    kind: str | None = None, commit: bool = True,
) -> str | None:
    """The write-exemption arm: *target* is the marker path itself.

    A symlinked marker is never exempted -- tampering, not an opt-out --
    so it falls through to the ordinary protected-branch deny, worded with
    the generic remedy: this is guard-mechanism tampering on the marker
    file itself, not a content commit, so no change-shape claim applies.

    *commit* False runs the DECIDE half only: the same symlink check and
    the same audit-writability requirement, via a probe that appends no
    row (``_ledger_writable``). ``evaluate`` runs every participating repo
    through that half first so a later repo's refusal cannot arrive after
    an earlier repo's entry is already durable. *kind* is that pass's
    single reading of the marker, reused rather than re-lstat'd (see
    ``_decide_then_commit``).
    """
    kind = _marker_kind(marker) if kind is None else kind
    if kind == "symlink":
        sys.stderr.write(SYMLINK_WARNING_TEMPLATE.format(marker=OPT_OUT_MARKER))
        return _deny_reason(branch, "ambiguous")
    error = (
        _log_marker_bypass(
            repo_root, action="marker_write", branch=branch, tool=tool, target=target,
        )
        if commit
        else _ledger_writable(repo_root)
    )
    if error is None:
        return None
    return AUDIT_FAILURE_TEMPLATE.format(
        branch=branch, action="marker_write",
        marker=OPT_OUT_MARKER, log_path=BYPASS_LOG_REL, error=error,
    )


def _evaluate_marker_disarm(
    repo_root: Path, *, branch: str, tool: str, target: Path, marker: Path, shape: str,
    kind: str | None = None, commit: bool = True,
) -> str | None:
    """The disarm arm: does the marker's presence flip this deny to allow?

    *shape* (see `classify_change_shape`) selects the deny wording when the
    marker does not disarm the call -- ``"code"`` keeps the engage-or-
    feature-branch dual remedy, every other shape gets the plain,
    feature-branch-only remedy (the module docstring's "CONTEXT-AWARE
    REMEDY" section).

    The advisory is written to stderr only AFTER the bypass-log append has
    succeeded -- printing "guard disabled, not being guarded" and then
    "BLOCKED" (on an append failure) would tell the operator two
    contradictory things in the same breath.

    *commit* False is the decide-only half (see ``_evaluate_marker_write``):
    every deny this arm can reach is reached, no row is appended, and no
    advisory is printed for a call that may still be refused by a later
    repo. *kind* is that pass's single reading of the marker, reused rather
    than re-lstat'd (see ``_decide_then_commit``).
    """
    kind = _marker_kind(marker) if kind is None else kind
    if kind == "symlink":
        sys.stderr.write(SYMLINK_WARNING_TEMPLATE.format(marker=OPT_OUT_MARKER))
        return _deny_reason(branch, shape)
    if kind != "file":
        return _deny_reason(branch, shape)
    if not commit:
        error = _ledger_writable(repo_root)
        if error is None:
            return None
        return AUDIT_FAILURE_TEMPLATE.format(
            branch=branch, action="marker_disarm", marker=OPT_OUT_MARKER,
            log_path=BYPASS_LOG_REL, error=error,
        )
    error = _log_marker_bypass(
        repo_root, action="marker_disarm", branch=branch, tool=tool, target=target,
    )
    if error is not None:
        return AUDIT_FAILURE_TEMPLATE.format(
            branch=branch, action="marker_disarm", marker=OPT_OUT_MARKER,
            log_path=BYPASS_LOG_REL, error=error,
        )
    sys.stderr.write(ADVISORY_TEMPLATE.format(marker=OPT_OUT_MARKER, branch=branch))
    return None


def evaluate(event: dict, env: dict) -> str | None:
    """Return a deny reason, or None to allow.

    Allowed without further checks when: the tool is not mutating, or --
    per present path key, each resolved independently -- a key is outside
    any git checkout, its checkout is not paircoder-managed, or its HEAD
    is not on a protected branch. That per-key check is done FIRST, before
    any marker logic (including the engage-driver exemption): a key this
    guard would allow anyway has nothing about it (symlink check, bypass
    log, advisory) consulted or written to. Only keys that DO resolve to a
    protected-branch checkout ("protected" below) reach the three further,
    AUDITED paths -- the engage-driver session exemption, writing the
    opt-out marker itself, and the marker being present when it would
    otherwise have denied the call -- all three denied instead if the
    audit record cannot be written, EXCEPT the engage exemption itself
    (see ``_log_engage_exemption``: a REQUIRED, ratified-AC guarantee that
    stays honored even when its own audit write fails). A symlink at the
    marker path is never honored as either marker arm: it is tampering,
    so the guard stays armed and a warning goes to stderr.

    A call with MULTIPLE present path keys takes the marker-write
    arm only when EVERY protected key resolves to ITS OWN checkout's
    marker -- a marker at one key and a real target at another (in the
    same or a different checkout) is judged through the ordinary
    disarm arm as the real mutation it is, never granted or logged as
    `marker_write`. The call is denied the moment ANY protected key names
    a real (non-marker) mutation; a key that never reaches a protected
    checkout at all imposes no constraint either way.

    Before the marker-write agreement is checked, every protected key is
    also tested against the writes-only agent-memory exemption (see
    ``is_agent_memory_write``): if EVERY protected key independently names
    a write inside a repo's ``.claude/agent-memory``, the call is allowed
    outright -- no marker, no audit log entry, since nothing was bypassed.
    """
    tool = str(event.get("tool_name", ""))
    targets = mutating_targets(event)
    if not targets:
        directory = touched_directory(event)
        if directory is None:
            return None
        resolved = _resolve_checkout(directory)
        if resolved is None:
            return None
        repo_root, _git_dir, branch = resolved
        if env.get(ENGAGE_MARKER) == "1":
            _log_engage_exemption(repo_root, branch=branch, tool=tool, target=directory)
            return None
        marker = repo_root / OPT_OUT_MARKER
        return _evaluate_marker_disarm(
            repo_root, branch=branch, tool=tool, target=directory, marker=marker,
            shape="ambiguous",
        )

    protected = []
    for target in targets:
        directory = target if target.is_dir() else target.parent
        resolved = _resolve_checkout(directory)
        if resolved is not None:
            protected.append((target, resolved))
    if not protected:
        return None

    # One audit entry per DISTINCT repo a protected key resolved into --
    # a dual-repo event (each key resolving its own checkout, per the
    # per-key resolution above) genuinely touches TWO ledgers, and each
    # must carry its own record if the call is exempted/allowed there.
    # Deduped by `repo_root` (not by target) so a same-repo dual-key
    # event, e.g. `NotebookEdit`'s `file_path`/`notebook_path` both
    # naming the same repo, still yields exactly one entry. Built once
    # here and reused by both the engage-marker exemption below and the
    # marker-write agreement further down.
    by_repo: dict[Path, tuple[Path, Path, Path, str]] = {}
    for target, (repo_root, git_dir, branch) in protected:
        by_repo.setdefault(repo_root, (target, repo_root, git_dir, branch))

    if env.get(ENGAGE_MARKER) == "1":
        for target, repo_root, _git_dir, branch in by_repo.values():
            _log_engage_exemption(repo_root, branch=branch, tool=tool, target=target)
        return None

    # Writes-only agent-memory exemption: every key that names a
    # protected-branch mutation must independently resolve inside
    # `.claude/agent-memory` (see `is_agent_memory_write`) or a real edit
    # elsewhere is happening under cover of an in-memory-looking key, same
    # reasoning as the marker-write agreement below.
    if all(is_agent_memory_write(t) for t, _ in protected):
        return None

    if all(_same_path(t, r[0] / OPT_OUT_MARKER) for t, r in protected):
        # DECIDE for every participating repo before COMMITTING any entry
        # (see `_decide_then_commit`): a denial reached on repo B must not
        # arrive after repo A's allow is already durable in repo A's
        # ledger.
        return _decide_then_commit(
            [
                (target, repo_root, branch, repo_root / OPT_OUT_MARKER)
                for target, repo_root, _git_dir, branch in by_repo.values()
            ],
            tool, _evaluate_marker_write,
        )

    # Same decide-then-commit ordering for the identically-shaped disarm
    # arm -- both can span repos, so both need it. *shape* (see
    # `classify_change_shape`) is a single value for the whole batch, bound
    # into the `arm` callable `_decide_then_commit` invokes per repo/pass.
    #
    # Round-2 trio review (F4): `_evaluate_marker_disarm`'s allow/deny
    # verdict for a repo depends ONLY on that repo's marker state (file /
    # absent / symlink) -- never on which specific target is being asked
    # about -- so it is a per-REPO decision, not a per-KEY one. Judging
    # every protected KEY independently (the pre-fix `for ... in
    # protected`) wrote one duplicate audit-log entry and advisory line
    # PER KEY for a same-repo dual-key event naming two different real
    # targets (e.g. `NotebookEdit`'s `file_path`/`notebook_path`), even
    # though it is one semantic bypass. Deduped by `repo_root` here, same
    # precedent as the marker-write arm above -- marker-path keys are
    # filtered out FIRST (a key naming the marker itself was never a
    # candidate for disarm judgment, unchanged from before this fix), so
    # a repo with both a marker-path key and a real-target key still
    # picks the real target as its one representative.
    shape = classify_change_shape(protected)
    disarm_by_repo: dict[Path, tuple[Path, Path, Path, str]] = {}
    for target, (repo_root, git_dir, branch) in protected:
        if _same_path(target, repo_root / OPT_OUT_MARKER):
            continue
        disarm_by_repo.setdefault(repo_root, (target, repo_root, git_dir, branch))
    return _decide_then_commit(
        [
            (target, repo_root, branch, repo_root / OPT_OUT_MARKER)
            for target, repo_root, _git_dir, branch in disarm_by_repo.values()
        ],
        tool,
        lambda repo_root, **kwargs: _evaluate_marker_disarm(
            repo_root, shape=shape, **kwargs
        ),
    )


def main() -> int:
    """Read the hook event on stdin; deny (2) on a policy match, else allow."""
    try:
        event = json.loads(sys.stdin.read() or "{}")
        reason = evaluate(event, dict(os.environ)) if isinstance(event, dict) else None
    except Exception as exc:  # fail open: never brick editing on our own bug
        sys.stderr.write(f"base_branch_guard: fail-open ({exc})\n")
        return 0
    if reason is None:
        return 0
    sys.stderr.write(f"BLOCKED BY ENFORCEMENT GATE\n\n{reason}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
