# Field specimen — the credential that was never there

**Observed:** 2026-08-27, in the `ops` repo, by accident.
**Class:** NEVER-PRESENT (distinct from expired, revoked, or rotated-away).
**Why it is written down:** lastrites' thesis says *"nearly every credential
outage is a detection failure, not a rotation failure."* This specimen is a
detection failure the current design would **not** catch, because there was
never a credential to watch die.

---

## What happened

A new ingest rail was built in `ops` to read a weekly schedule email
(`scripts/ingest_hotschedules.py` → `scripts/triage_inbox.py:fetch_recent`,
which reads `IMAP_HOST`, `IMAP_USER`, `IMAP_PASS` from the environment).

The code shipped. Tests passed — they mock the fetch. Architecture checks
passed. A PR was opened and reviewed. The freshness rail was registered.

Then a bare-PATH install-proof smoke test was run before scheduling it:

```
env -i HOME="$HOME" PATH=/usr/bin:/bin SHELL=/bin/sh crons/hotschedules-ingest.sh --dry-run
→ IMAP fetch failed: IMAP_HOST, IMAP_USER, IMAP_PASS must be set to fetch real mail.
```

`ops/.env` holds **49 keys and not one of them is mail-related.** No
`IMAP_*`, no `MAIL_*`, no `ZOHO_*`. The credentials this feature depends on
have never existed on this machine.

## Why nobody noticed

Five other modules reference the same IMAP path — `triage_inbox.py`,
`scan_email_for_schedule_changes.py`, `email_drafter.py`,
`inbox_ingestors/email.py`, and the new ingest. **None of them is scheduled.**

So the estate contained a five-consumer dependency on a credential that was
never provisioned, and it produced no symptom for as long as nothing ran. The
gap was discovered only because someone ran a smoke test *before* installing a
cron, rather than after.

Had the cron been installed first, the observable behaviour would have been a
daily failure at a fixed hour — which is the good case. The bad case is the one
this estate has seen before: a scheduled job whose failure is swallowed, and a
green heartbeat above it.

## The detection principle this yields

> **A credential dependency that is never exercised is indistinguishable from a
> satisfied one.**

VERIFY is a canary call: it proves a credential authenticates *right now*. But
VERIFY presumes the credential is in the graph, and the graph is built by
scanning **config surfaces** — crontabs, plists, env files, CI secrets. A
credential that exists only as a *reference in code*, with no corresponding
secret anywhere, is invisible to a scanner that enumerates secrets. **You cannot
fingerprint a value that was never written.**

The graph currently answers *"which consumers hold a copy of this credential?"*
This specimen asks the mirror question, which is unanswered:

> **"which consumers reference a credential that no location provides?"**

## Proposed: a fourth surface, scanned from the consumer side

Discover credential *references* in code the way secrets are discovered in
config — then diff the two sets:

| Set | Source | Meaning |
|---|---|---|
| **provided** | env files, keychains, CI secrets, plists (today's scan) | secrets that exist |
| **required** | `os.environ[...]` / `getenv(...)` / documented `.env.example` keys | secrets code demands |

- `required − provided` → **NEVER-PRESENT**. Nothing to verify; nothing will
  ever page. This specimen.
- `provided − required` → **ORPHANED**. A live secret no consumer reads —
  blast radius zero, rotation free, and a plausible leak surface. Worth
  surfacing for the opposite reason.

Neither needs a canary call. Both are static, cheap, and run without touching a
provider's API or rate limits.

## Honest limits

- **False positives are certain.** Optional integrations, feature-flagged
  paths, and machine-specific tooling legitimately reference credentials a given
  host does not hold. The output has to be *reviewable*, not alarming — a
  report, not a page. An alarm that fires on every optional integration is one
  the operator mutes, and a muted alarm is worse than no alarm.
- **Reference discovery is heuristic.** `os.environ["X"]` is greppable;
  `os.environ[name]` where `name` is computed is not. Report what is found and
  be explicit that the set is a floor, never a complete inventory.
- **This does not replace VERIFY.** A provisioned-but-dead credential still
  needs a canary. NEVER-PRESENT is a gap *below* VERIFY, not a substitute for it.

## Provenance

Found while installing a cron in `ops`, 2026-08-27. Recorded at Kevin's
instruction: *"those credentials not sticking should be recorded for last
rites."*

**Consequence in ops:** the cron was **not** installed. Scheduling a job that
cannot authenticate would page daily via the shared cron preamble's ERR trap and
teach the operator to ignore it. The wrapper is built and its bare-PATH install
proof passes; it waits on credentials, which is a person's decision, not a
script's.
