status: done
ac_verified: true (5/5 checked)

---

LR1.3 is complete. Summary:

**Implemented \`lastrites/canary/\`** — provider registry (cloudflare, github, generic-bearer, ntfy-write), a stdlib-\`urllib\` transport normalizing network failures into typed exceptions, an engine tying spec→transport→verdict together, and \`verdict.py\` pinning the estate doctrine: only authenticated 401/403 is \`DEAD\`, everything else unreadable (timeout/DNS/5xx/ambiguous status/failed predicate) is \`UNOBSERVABLE\`. Extended the LR1.1 graph store with a \`canary_evidence\` table and wired \`lastrites canary \<fingerprint-prefix\>\` into the CLI — raw values are read from \`--value-env\`/\`--value-file\` (never argv), verified against the looked-up fingerprint before probing, with distinct exit codes per verdict and per failure mode.

268 tests pass (\`pytest -n auto --dist=worksteal\`), arch check and ruff clean, \`check-wiring\` confirmed clean when scoped to the whole package. Task marked \`done\` with all ACs checked, THREAT-MODEL.md gained a verified §6, and \`state.md\` updated with the full session record. Next up: **LR1.4** (sweep daemon, heartbeat, escalation).