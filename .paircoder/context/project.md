# Project Context

## What Is This Project?

**Project:** <!-- Add your project name -->
**Primary Goal:** <!-- Add your primary goal -->

## Repository Structure

```
project/
├── .paircoder/              # PairCoder system files
│   ├── config.yaml          # Project configuration
│   ├── capabilities.yaml    # LLM capability manifest
│   ├── context/             # Project memory (project.md, state.md, workflow.md)
│   ├── plans/               # Active plans
│   └── tasks/               # Task files by plan
├── .claude/                 # Claude Code integration
│   ├── agents/              # Custom agent definitions
│   ├── skills/              # Model-invoked skills
│   └── settings.json        # Hooks configuration
├── src/                     # Source code
├── tests/                   # Test files
└── docs/                    # Documentation
```

## Tech Stack

<!-- Update with your actual tech stack -->
- **Language:** TBD
- **Framework:** TBD
- **Database:** TBD
- **Testing:** TBD

## Key Constraints

| Constraint | Requirement |
|------------|-------------|
| **Test Coverage** | Minimum 80% coverage |
| **Dependencies** | Review required for new deps |
| **Secrets** | Never commit secrets or credentials |
| **Compatibility** | No breaking changes without major version |

## Architecture Principles

<!-- Update these to match your project's principles -->

1. **Simplicity First** — Start simple, add complexity only when needed
2. **Test-Driven** — Write tests before implementation
3. **Documentation** — Keep docs updated with code changes

## How to Work Here

1. Read `.paircoder/context/state.md` for current plan/task status
2. Check `.paircoder/capabilities.yaml` to understand available actions
3. Follow the active skill for structured work
4. Update `state.md` after completing significant work

## Key Files

| File | Purpose |
|------|---------|
| `.paircoder/config.yaml` | Project configuration |
| `.paircoder/capabilities.yaml` | What LLMs can do here |
| `.paircoder/context/state.md` | Current status and active work |
| `src/` | Source code |
| `tests/` | Test files |
