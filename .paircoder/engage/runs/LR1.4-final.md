status: done
ac_verified: true (6/6 checked)

---

LR1.4 is complete. Summary of what shipped:

**\`lastrites/sweep/\`** — the layer that turns detection into pages:
- \`contract.py\` — env-var presence (not value) decides \`invoked_by\` (scheduler vs interactive)
- \`heartbeat.py\` — atomic, strict-from-birth JSON heartbeat; \`read_heartbeat\` fails closed if \`invoked_by\` is missing
- \`registry.py\` — operator-owned credentials config (fingerprint → provider → value source) since the store never holds raw values
- \`canary_all.py\` — canaries every registration with per-registration resilience (a bad entry is skipped, never fatal)
- \`escalation.py\` — three rules against the graph store (DEAD verdict, N-consecutive-UNOBSERVABLE, expiry lead-time), with DEAD outranking an UNOBSERVABLE streak to avoid double-paging
- \`channel.py\` — pluggable alert channel as a configured command template, never a hardcoded endpoint
- \`sweep.py\` — orchestrator where the heartbeat write is the *last* statement, so any upstream exception leaves no heartbeat (capture-based)
- \`cli.py\` / \`report.py\` — the \`lastrites sweep\` subcommand, split out to keep \`lastrites/cli.py\` under its architecture limits

Also: added \`GraphStore.list_credentials()\`, added a repo-wide grep-proof no-endpoint-literal test (which caught and fixed a real pre-existing literal in an LR1.3 test), added a README "Running it scheduled" section with the env-contract, example configs, and the \`env -i\` install-proof step, and promoted THREAT-MODEL.md §7 to verified.

333 tests pass (63 new), arch check and ruff clean, all four spec verification commands succeed. Task marked \`done\`, state.md updated, LR1.5 (Contract conformance + CI) is next.