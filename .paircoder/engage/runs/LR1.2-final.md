status: done
ac_verified: true (6/6 checked)

---

**LR1.2 complete** — \`bpsai-pair task update LR1.2 --status done\` passed the strict AC gate ("✓ All acceptance criteria verified"). Changes are uncommitted; I left committing to you.

## What shipped

\`lastrites/scan/\` — three tolerant surface scanners (crontab, launchd plist, env file), candidate screening, fingerprint clustering, honest classification, declared blind spots — plus \`lastrites scan\` with optional persistence into the LR1.1 graph store. 191 tests green; \`arch check\` and \`ruff\` clean; \`lastrites scan --help\` verified from an installed console script.

All six acceptance criteria are checked off in the task file with the evidence attached.

## Two defects worth your attention

I ran two review passes, and each found a real way the tool could lie about the estate. Both were verified by execution before and after the fix:

**A raw credential leak in skip reasons.** On these surfaces the malformed text often *is* the secret — a PEM body line and a padded JWT both end in \`=\`, so "the text left of the first \`=\`" was being printed to stdout and serialized into \`--json\`. Reproduced with a real JWT echoed verbatim. Skip reasons are now a closed vocabulary plus non-reversible shape facts (\`invalid identifier: 69 chars, first invalid character at offset 20\`), with tests that plant secrets on the *left* of an assignment — the side every other leak test misses.

**A screen rule order that inverted the headline signal.** My first fix for a false-negative problem overcorrected: a key-name hint bypassed every shape rule, so \`AUTH_ENABLED=\[REDACTED_ENV\] and \`SESSION_TIMEOUT=\[REDACTED_ENV\] got collected. Identical literals fingerprint identically, so unrelated machines clustered into fake credentials whose copy counts outranked every real one — the blast-radius signal backwards, and permanently, since the graph has no delete path. Fixed with a config-literal rule no hint can bypass, token-boundary hint matching (\`AUTHOR\` is not \`AUTH\`), and a separator-counting path test that still admits base64 secrets like AWS's.

Also fixed: estate-level crash containment, discovery skip accounting, three distinct exit codes for the three ways of seeing nothing (\`0\`/\`2\`/\`3\`), and idempotent persistence — a scheduled rescan no longer multiplies the graph or NULLs columns it doesn't write, which matters because LR1.4 will run it on a timer.

## What I did not fix, and why

Three gaps need LR1.1 schema columns, so they belong with the sweep daemon rather than here. I named them in \`THREAT-MODEL.md\` rather than leaving them implicit: nothing yet *pages* on a skip; the store stamps a surface class, not the individual file, so per-file freshness isn't recoverable; and \`copied-at\` edges are never retired, so blast radius over-reports as the estate drifts. Safe retirement needs \`last_seen\` — deleting on absence would erase copies on a machine that merely didn't scan.

I promoted THREAT-MODEL §5 from design intent to **verified** per the repo's evidence discipline, with the command, date, and observed output attached, and the three caveats stated so they can't be read into the stamp.