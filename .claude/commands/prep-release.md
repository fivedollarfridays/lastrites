---
description: Enter Release Engineer role to prepare a release with validation
allowed-tools: Bash(bpsai-pair:*), Bash(git:*), Bash(pytest:*), Bash(pip:*), Bash(grep:*), Bash(diff:*), Bash(rm:*), Bash(cd:*), Bash(ls:*)
argument-hint: <version>
---

Enter **Release Engineer role** to prepare release. Dispatch `reviewer` and `security-auditor` agents as necessary.

**Version**: $ARGUMENTS (e.g., `v2.14.0` or `2.14.0`)

## Pre-Flight (Enforcement)

Run ALL of these — any failure is a **BLOCKER**:

```bash
bpsai-pair task list --status in_progress
bpsai-pair task list --status blocked
python -m pytest tools/cli/tests/ -v --tb=short
python -m pytest tools/cli/tests/ --cov=bpsai_pair --cov-fail-under=80
bpsai-pair security scan-secrets
bpsai-pair arch check
bpsai-pair template check --fail-on-drift
bpsai-pair skill validate
```

**BLOCKERS**: Incomplete tasks, failing tests, secrets, arch violations, template drift, or invalid skills = cannot release.

> **Also a BLOCKER — Skill & Command Drift Audit** (Phase 3.4 of the releasing-versions skill): audit the planning / task-execution / engage skills + slash commands + the CLI reference against the LIVE `bpsai-pair --help` surface. Fan out to parallel subagents to keep context lean. A doc referencing a non-existent command/flag, a changed default (e.g. Trello-by-default vs `pm.provider: none`), an undocumented new command group, or a deprecated command without its replacement = cannot release. The 2026-06 release found a mountain of this; do not skip it.

## Execute Workflow

Read and follow `.claude/skills/releasing-versions/SKILL.md` for the complete 10-phase workflow.

## Key Constraints

- Version format: `X.Y.Z` in files, `vX.Y.Z` for git tags
- Template sync is a **BLOCKER** — run `bpsai-pair template check --fix` if drift detected
- Security scans are **BLOCKERS**, not warnings
- User must explicitly approve the push
- All tests must pass with >= 80% coverage
- CHANGELOG follows Keep a Changelog format

## Cross-Repo Coordination

```bash
bpsai-pair workspace check-impact --since $(git describe --tags --abbrev=0)
bpsai-pair workspace status
```

Check workspace impact before finalizing. Website and API may need updates.

**Note**: `__init__.py` uses dynamic versioning — no manual update needed.
