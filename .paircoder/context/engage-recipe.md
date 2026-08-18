---
name: engage-recipe
description: Workflow for executing backlog tasks via background dispatch
metadata:
  type: workflow
---

# Engage Workflow Recipe

The **engage** workflow is the primary mechanism for executing backlog tasks in PairCoder. It dispatches a backlog file to the background, where the orchestration system executes each task according to its specification.

## Workflow Steps

### 1. **CLI Invocation** (Required First Step)

The workflow begins with a CLI command, not inline chat execution:

```bash
bpsai-pair engage <backlog-file>
```

**Examples:**
```bash
bpsai-pair engage backlog-sprint-28.md
bpsai-pair engage ./docs/backlogs/sprint-29.md
bpsai-pair engage sprint-30
```

The command accepts:
- A file path (relative or absolute)
- A shorthand name (without `.md` extension)
- Paths with subdirectories

### 2. **Launch Confirmation: the Run-Started Contract Line**

The moment the run is genuinely underway — all pre-flight gates passed and
the FIRST task is actually being dispatched (not merely planned) — `engage`
prints one unmissable, stable, machine-greppable confirmation line so an
operator or wrapper can launch-verify before walking away:

```
ENGAGE-RUN-STARTED run_id=<run-id> first_task=<task-id> model=<model> target_repo=<repo>
```

**This is a contract.** The `ENGAGE-RUN-STARTED` marker is stable and the
four `key=value` fields are space-delimited, so a launch-verify wrapper can
grep the line and split the fields without parsing prose:

```bash
bpsai-pair engage backlog.md 2>&1 | grep -q '^ENGAGE-RUN-STARTED ' \
  || echo "ABORT: engage never confirmed a run started"
```

- `run_id` is the run's concurrency-lease id (the same id
  `commands/engage_concurrency_guard.py`'s `claim_run_slot` mints and holds
  in `~/.bpsai/engage-runs/<run-id>.lease` for the run's lifetime). It is
  distinct from the pause/`--resume-run` id in step 3, which only exists
  once a run pauses.
- `first_task` is the first task the executor actually dispatches (resolved
  from the execution graph, so a resumed run reports the first *incomplete*
  task, not a done one).
- `model` and `target_repo` are that task's dispatch model and effective
  target repo (the run repo's own name for a same-repo task).

Exactly one such line is printed per successful dispatch. A run that is
**refused** before dispatch, or previewed with `--dry-run`, prints no
`ENGAGE-RUN-STARTED` line at all — it prints an `ENGAGE-RUN-NOT-STARTED`
line instead (see "No-Run Contract" below).

Work then proceeds to the per-task lines and the sprint summary:

```
Task T1.1 DONE
Task T1.2 FAILED: <error detail>
Sprint complete: 2 done, 1 failed, 0 hook-failed, 0 blocked, 0 skipped
```

(`orchestration/headless_dispatch.py:544` prints the per-task `DONE` line;
the same module's `_terminal_echo_message` — called at lines 445, 452, and
531 — prints `FAILED`/`BLOCKED` with the failure detail; the `PR: <url>`
line, when present, and the `Sprint complete: ...` summary itself come from
`commands/engage_result.py:201-216`.)

**The `Sprint complete: ...` line is the completion criterion for a normal
run;** the `ENGAGE-RUN-STARTED` line above is its *launch* criterion.

#### No-Run Contract: refusal and `--dry-run`

When a dispatch is refused (a pre-flight gate, feasibility, or the
concurrency cap) OR previewed with `--dry-run`, the final line states
plainly that no run started, so a refused overnight dispatch pages rather
than reading like a successful log:

```
ENGAGE-RUN-NOT-STARTED reason=refused -- no run started; see the pre-flight report above (run `bpsai-pair engage doctor <lane>` for the full report).
ENGAGE-RUN-NOT-STARTED reason=dry-run -- --dry-run previews the plan only; no run is started.
```

`bpsai-pair engage doctor <lane>` re-runs the same gate battery and prints
the full pre-flight report the refusal points at.

### 3. **Run-State File — Written Only When a Run Pauses**

A run-state file is written ONLY when a run pauses on a human-gated task.
`orchestration/engage_run_state.py`'s `save_pause_state` is called
exclusively from `commands/engage_pause_resume.py` — no other call site
writes it, so an ordinary, non-paused run never creates one at all.

When a run does pause, the file lands at:

```
.paircoder/engage/runs/<run-id>.state.json
```

This **pause/resume** run id has the shape
`engage-sprint-<sprint>-<timestamp>-<suffix>`
(`orchestration/engage_run_state.py:190-192`) — not a `wf_...` id — and you
get it from the `PAUSED: ...` prompt described in step 5. It is a DIFFERENT
id from the `run_id` in the step-2 `ENGAGE-RUN-STARTED` line (that one is the
concurrency-lease handle, emitted at launch on every dispatch); only this
pause id is a durable handle for `--resume-run`.

### 4. **Background Execution**

While a dispatch is in progress, the orchestration system:
- Parses the backlog file
- Generates task files for each item
- Executes tasks according to their dependencies and specifications
- Prints the per-task `DONE`/`FAILED`/`BLOCKED` lines from step 2 as each
  task finishes

### 5. **If a Run Pauses: the Resume Prompt**

`bpsai-pair engage` has no `status` subcommand — watch the terminal output
described in step 2 instead. If a task requires human intervention, the CLI
prints (`commands/engage_guard_checks.py:178-189`):

```
PAUSED: Task <task-id> requires human intervention
Completed so far: <N> task(s)

To resume after completing the task:
  1. Complete the work described in the task file
  2. bpsai-pair task update <task-id> --status done
  3. bpsai-pair engage --resume-run <run-id>
```

That `<run-id>` is the durable *resume* handle, given only on a pause — as
distinct from the launch-time `run_id` in the step-2 `ENGAGE-RUN-STARTED`
line, which every dispatch emits.

## Design Rationale

**Why CLI-First?** The CLI invocation provides:
- Clear audit trail (visible in shell history and logs)
- Proper environment isolation (venv, PATH, etc.)
- Deterministic permissions and constraints
- Background execution without blocking the chat session

**Why two run ids?** The launch-time `run_id` in the `ENGAGE-RUN-STARTED`
line (step 2) is a *confirmation* handle: it exists so a wrapper or operator
can verify, at a glance, that a dispatch genuinely started before walking
away — a refused overnight dispatch must page, not read like a successful
log. Dispatch itself is deterministic and self-terminating (the CLI process
watches the sprint through to `Sprint complete: ...` and exits), so no run
id is needed to look anything up *afterward* for an ordinary run. The
separate *pause* run id (step 3) only becomes necessary when the process has
to hand control back to a human mid-sprint and needs a durable handle to
reattach to later via `--resume-run`.

## Common Tasks

### Resume a paused engagement

```bash
bpsai-pair engage --resume-run <run-id>
```

(No backlog argument — this is exactly what the `PAUSED: ...` prompt in
step 5 tells you to run.)

### Investigate a failed task

There is no separate failure record to query. The `Task <ID> FAILED: ...`
line printed at the time (step 2) carries the detail; the task's own file
under `.paircoder/tasks/` records its `status`, and `git log`/`git diff` on
the engage branch (see below) shows what, if anything, was committed before
the failure.

### Retrieve the full diff from an engagement

Engage branches are named `engage/<slug>`, derived from the backlog
filename (`commands/engage_guard_checks.py`'s `_derive_branch_slug`), not
from the run id:

```bash
git diff main..engage/<slug>
```

### Run engagement with dry-run to preview

```bash
bpsai-pair engage backlog.md --dry-run
```

## Detecting Incomplete Engagement Records

**Detectable violation, scoped to paused runs:** if a task file under
`.paircoder/tasks/` records a paused run id in its metadata but that run's
state file is missing, that is a genuine consistency violation — restore
the state file or treat the task as orphaned. This check does NOT apply to
ordinary, non-paused runs: as step 3 explains, a normal run never creates a
run-state file in the first place, so its absence proves nothing there.

**Concrete check (paused runs only):**

```bash
RUN_ID="engage-sprint-1-20260101T000000-abcdef"
grep -rl "$RUN_ID" .paircoder/tasks/*.task.md

if [ ! -f ".paircoder/engage/runs/${RUN_ID}.state.json" ]; then
  echo "ERROR: a task references paused run $RUN_ID but its state file is missing"
  exit 1
fi
```

## Inline Execution Is Not a Supported Escape Hatch

There is no flag that lets `bpsai-pair engage` run a backlog inline in the
current chat session instead of dispatching it to the background. Running a
backlog's tasks by hand in-session (rather than through `bpsai-pair engage
<backlog>`) is a contract violation, not a supported bypass.

The one file-based check this violation is detectable through is scoped to
paused runs — see "Detecting Incomplete Engagement Records" above: it
proves a specific paused run id never reached engage's dispatch path. It
does NOT generalize to non-paused runs, because (per step 3 above) an
ordinary successful dispatch never creates a run-state file either — its
absence is not, by itself, evidence of anything. The closest evidence for a
non-paused run is the terminal output itself (the `Task <ID> DONE/FAILED`
and `Sprint complete: ...` lines from step 2), which only exists if the CLI
actually ran.

If you need to preview what a run would do without dispatching it, use
`bpsai-pair engage <backlog> --dry-run` (see "Run engagement with dry-run to
preview" above) — that is the one CLI-supported way to inspect a plan before
committing to a real dispatch.
