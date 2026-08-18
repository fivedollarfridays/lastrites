# Threat model

lastrites handles the most sensitive class of data on a machine —
credentials and the map of where they live. This document states plainly
what it protects against, what it deliberately does not, and where the
sharp edges are. If a claim here stops being true, that is a bug of the
highest severity.

## What lastrites protects against

- **Silent credential death.** A key that stops authenticating and nothing
  notices. The canary layer exists solely to convert silent death into a
  page.
- **Silent watchdog death.** The watcher itself dying quietly — the
  second-order failure that makes every first-order guarantee a lie.
  Heartbeats are capture-based and provenance-stamped; external dead-man
  watching is a first-class deployment requirement, not an option.
- **Half-completed rotation.** The failure mode a rotator *introduces*:
  new key minted, consumers partially updated, old key revoked — an outage
  manufactured by the tool that promised to prevent one. Rotation is
  two-phase with overlap and fails CLOSED: any verification failure halts
  with both keys valid and pages a human.
- **Forgotten copies.** The `.env` on the old laptop path, the crontab
  line from two migrations ago. The credential graph exists to find copies
  you did not remember distributing.

## What lastrites deliberately does NOT protect against

- **A compromised host.** lastrites runs local-first with local
  privileges. An attacker on the box already has what lastrites has. It is
  an availability and hygiene tool, not an intrusion defense.
- **Malicious insiders with the parent credentials.** See blast radius.
- **Secrets it cannot see.** Values inside compiled binaries, OS keychains
  it is not granted, or derived/transformed secrets (base64 wrappers,
  KDF outputs) may evade fingerprint clustering. The graph is honest about
  its own coverage: unscanned surface classes are reported as blind spots,
  never as absence of copies.

## The sharp edges, named

**1. The parent-credential blast radius.** Rotation requires credentials
that can mint credentials (an AWS key with `iam:CreateAccessKey`, a
Cloudflare token that can roll tokens). These parents are the crown
jewels: strictly scoped, stored outside the graph store, never
fingerprinted into it, and their own health is watched by the same canary
machinery. A deployment that gives lastrites broad admin credentials has
misread this document.

**2. Fingerprints are peppered HMACs, never bare hashes.** The graph
stores locations and fingerprints, never values. A bare SHA-256 of a
low-entropy secret is a dictionary attack waiting politely; fingerprints
are HMAC(machine-local pepper, value), with the pepper stored separately
from the graph. Stealing the graph alone yields a map of *where* secrets
live — bad — but not an oracle for *what* they are.

**3. The graph is itself sensitive.** A list of every credential location
on your estate is reconnaissance gold, even though it holds fingerprints
and locations rather than values. v1's at-rest posture is honest, not
aspirational: the graph is a local SQLite file, mode `0600`, WAL journal,
readable only by the owning user account — it is **not encrypted at
rest**. Encryption at rest is tracked as an open issue, not implied by
anything shipped today. The pepper that makes fingerprints unforgeable is
a separate `0600` file outside the graph, created once and never logged.
Nothing in lastrites phones home; there is nothing to phone home to, and
nothing leaves the machine.

*Verified: `pytest -n auto --dist=worksteal` (30 passed) exercises file
permissions (`0600` on both the pepper and the graph store), WAL journal
mode, and a store-file-bytes check proving no raw credential value is
ever written to disk — `lastrites/core/{pepper,fingerprint,store}.py`,
2026-08-18.*

**4. Escalation channels are part of the attack surface.** A pager that
anyone can write to can drown real alarms in noise (alert fatigue is a
security failure). Deployment docs treat the alerting channel's
authentication with the same seriousness as the credentials themselves.

**5. Scan-surface enumeration must fail loud.** A parser that silently
skips a malformed plist or an unreadable file undercounts the estate and
reports false confidence. Skips are counted, surfaced, and alarmed on —
drift-tolerant parsing, never silent dropping.

*Verified: `python -m lastrites scan --root tests/fixtures/estate
--pepper-file <tmp>` against a fixture estate containing a malformed
crontab line pair, a truncated plist,
a plist whose `EnvironmentVariables` is not a dictionary, and three
unparseable env-file lines. Observed: `Skipped (unparseable, counted not
hidden): 7`, each skip printed with its own locator and reason, each
surface line annotated with its own count, and no parse raising. Three
distinct ways of seeing nothing get three distinct exit codes: zero
surfaces attempted → `2`, surfaces attempted but none readable → `3`,
a real scan → `0`. Silence and safety are not allowed to share an exit
code. Tolerance is enforced at the orchestration level too — a scanner
that raises is contained to its own surface as a counted skip, so one
damaged file cannot discard the surfaces already scanned. Discovery is
held to the same standard: an unwalkable `--root`, an undescendable
directory and a symlinked directory we decline to follow are all counted
skips, not empty results. Blind spots (`os-keychain`, `compiled-binaries`,
`derived-copies`, `runtime-injected`, `remote-hosts`, `ci-secret-stores`)
are printed unconditionally, including on an empty scan. `pytest -n auto
--dist=worksteal` (191 passed) pins both directions —
`lastrites/scan/`, 2026-08-18.*

*Also verified, and worth stating separately because it is the rule that
is easiest to break by accident: skip reasons never quote the input they
describe. On these surfaces the malformed text IS often the secret — a PEM
body line and a padded JWT both end in `=`, so "the text left of the first
`=`" is credential material, and plistlib's error strings embed the
element that failed to parse. Skip reasons are therefore a closed
vocabulary plus non-reversible shape facts (`invalid identifier: 69 chars,
first invalid character at offset 20`), pinned by tests that plant secrets
on the left-hand side of an assignment — `lastrites/scan/redact.py`,
`tests/scan/test_no_leaks.py`, 2026-08-18.*

**6. The canary layer's verdict vocabulary is the doctrine, not a
suggestion.** "Silent credential death" (§ What lastrites protects
against) is only converted into a page if the instrument being blind is
never mistaken for the surface being dead. `lastrites/canary/verdict.py`
is the single place that distinction is made: only an authenticated
401/403 response classifies as `DEAD`; a timeout, a DNS failure, a 5xx,
any other ambiguous status, or a success predicate that did not confirm
are all `UNOBSERVABLE`. An evidence row carries a verdict, a latency, and
an HTTP class — never a response body, never the credential value that
was probed.

*Verified: `pytest -n auto --dist=worksteal` (268 passed) pins the
three-way distinction directly — every status in `{401, 403}` classifies
`DEAD`, `{400, 404, 429, 500, 502, 503}` and every `ProbeTimeout` /
`ProbeDNSError` / `ProbeNetworkError` classify `UNOBSERVABLE`, and no path
through `classify_error` can ever produce `DEAD`
(`tests/canary/test_verdict.py`, `tests/canary/test_engine.py`). A
structural check confirms `ProbeOutcome` has no body- or value-shaped
field at all, and an end-to-end run plants both a raw credential value
and a response body containing a marker, then greps CLI stdout/stderr and
the graph store's raw file bytes for both, run through the real
`lastrites canary` CLI against a mocked transport
(`tests/canary/test_no_leaks.py`) — `lastrites/canary/`, 2026-08-18.*

**7. The sweep's heartbeat and escalation rules are what make the earlier
sections actually page a human.** Detection lives in scan and canary;
without a heartbeat that is capture-based and strictly provenance-stamped,
plus rules that convert stored evidence into a page, neither section does
more than log locally. `lastrites/sweep/heartbeat.py` writes JSON where
`invoked_by` is present on every heartbeat this writer produces, and
`read_heartbeat` refuses to interpret a payload missing the field rather
than defaulting it to "hand-run" — a reader fails closed instead of
trusting a corrupted or hand-edited file. The write is atomic (a sibling
temp file, then `os.replace`) and it is the LAST statement
`lastrites/sweep/sweep.py`'s `run_sweep` executes: any exception anywhere
upstream — scan, persist, canary, escalation, or the alert channel —
propagates uncaught, and no heartbeat is written, so a sweep that dies
mid-way looks exactly like a sweep that never ran.

Escalation (`lastrites/sweep/escalation.py`) evaluates three rules against
the graph store: a DEAD canary verdict, N consecutive UNOBSERVABLE
verdicts, and a credential inside its expiry lead time. A DEAD verdict
outranks an UNOBSERVABLE streak for the same credential, so a known-dead
surface does not also fire a second, weaker page about the same fact —
§4's alert-fatigue concern, made concrete. The alert channel
(`lastrites/sweep/channel.py`) is a configured command template, never a
hardcoded endpoint: no alerting endpoint or topic literal exists anywhere
in this repo, enforced by a test that greps every `.py` and `.md` file in
the tree, not just the sweep package.

*Verified: `pytest -n auto --dist=worksteal` (333 passed, 63 new in
`tests/sweep/`) pins: a heartbeat absent after a sweep injected with a
mid-sweep failure, and present with `invoked_by` after a completed one;
`invoked_by=scheduler` only when `LASTRITES_SCHEDULED` is present in the
environment (by presence, not by value) and `interactive` otherwise; each
escalation rule firing through a stubbed channel runner — dead verdict,
expiry within lead time, N-consecutive-unobservable, and dead outranking
an unobservable streak for the same credential so it doesn't double-page;
and the repo-wide no-endpoint-literal test, which also caught and fixed a
pre-existing literal `ntfy.sh/<topic>` URL assertion in
`tests/canary/test_providers.py` from LR1.3 — `lastrites/sweep/`,
2026-08-18.*

## Evidence discipline

Docs in this repo mark claims as **verified** only with the command, the
date, and the observed output attached. Everything else is design intent.
As of 2026-08-18 this file has four verified sections — §3 (at-rest
posture), backed by the core fingerprint/graph-store implementation, §5
(scan-surface enumeration), backed by the estate scanner and its fixture
estate, §6 (canary verdict vocabulary), backed by the canary engine and
provider registry, and §7 (sweep heartbeat and escalation), backed by the
sweep daemon. Every other claim here remains design intent, the contract
the rest of the implementation will be held to.

Three caveats the §5 evidence does *not* cover, stated so they are not
read into it. LR1.4 (the sweep daemon) shipped the heartbeat and
escalation layer but deliberately did not close these three — they stay
open:

1. Skips are counted and surfaced, but nothing yet *alarms* on them in the
   §5 sense of paging a human. Today a skip is loud on stdout and in the
   persisted scan record, and silent everywhere else.
2. The persisted scan record stamps a surface *class* (`env-file`), not the
   individual file, so per-file freshness is not yet recoverable from the
   graph — the dead-man layer wants it and does not have it.
3. Re-scanning never *retires* a `copied-at` edge. A copy that moves
   locations leaves both edges in the graph, so blast radius over-reports
   as the estate drifts. Safe retirement needs a `last_seen` column, since
   deleting on absence would erase copies on a machine that merely did not
   scan.
