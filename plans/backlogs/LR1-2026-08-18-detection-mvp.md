# LR1 — Detection MVP

**Plan type:** feature
**Base:** main

First code sprint. Scope is the locked public-v1 boundary: detection and
escalation only — a read-only daemon that cannot hurt the estate it watches.
No rotation code in this sprint. The contracts already committed in
`THREAT-MODEL.md` and `docs/WATCH-TOPOLOGY.md` are LAW for every task:
values never persisted, fingerprints are peppered HMACs, heartbeats are
capture-based and strict-provenance from birth, skips counted loudly.
Python 3.12+, stdlib-lean (httpx acceptable; no heavy frameworks), pytest.

### Phase 1: the graph

### LR1.1 — Fingerprint core + graph store | Cx: 3 | P0

**Description:** `lastrites/core/`: pepper management (create-once file,
0600, stored OUTSIDE the graph store, loaded never printed), fingerprinting
(`HMAC-SHA256(pepper, canonicalized_value)` with per-format canonicalizers:
strip quotes/whitespace, structured-secret inner-material handling for JSON
service accounts), and the graph store (sqlite, 0600, WAL): tables for
credentials (fingerprint PK, kind, rotation_class, provider, expiry,
last_verified), consumers (machine, locator, format), copied_at edges,
scans (surface, ts, invoked_by, skip_count). Raw values must be
unrepresentable in the store layer's API — fingerprint at the boundary,
discard immediately. Update THREAT-MODEL.md §3 to state v1 at-rest posture
honestly (0600 + WAL, encryption-at-rest tracked as an issue) — the doc
tracks reality, never ahead of it.

**AC:**
- [ ] Pepper file created 0600 on first run, never inside the graph store or repo, load path never logs the value
- [ ] Fingerprints are HMAC-SHA256 with the pepper; test proves identical values across formats cluster and a bare-SHA path does not exist
- [ ] Store API accepts fingerprints only — a test proves no public store method persists a raw value and a repo-wide grep of fixtures finds no mock secret in any store file after the test suite runs
- [ ] Structured-secret canonicalizer: same service-account JSON re-serialized differently yields the same fingerprint
- [ ] THREAT-MODEL.md §3 updated to the implemented at-rest posture
- [ ] pytest green via `pytest -n auto --dist=worksteal`

**Depends on:** None
**Model:** claude-sonnet-5

### LR1.2 — Estate scanner + fingerprint clustering | Cx: 4 | P0

**Description:** `lastrites/scan/`: surface scanners for crontab text,
launchd plists, and env files (`.env`, shell `export` lines), each parsing
TOLERANTLY with per-surface skip counters surfaced in the scan record — a
silently skipped surface is a false "no copies here" (THREAT-MODEL §5).
Candidate extraction: assignment parsing + key-name hints + Shannon-entropy
screen, tuned to over-collect. Clustering: identical fingerprints across
surfaces become one credential with copied_at edges; classification
(provider/kind from key names and value shape) falls back to `unknown`
honestly. Blind-spot reporting: unscannable surface classes are named in
scan output, never omitted. CLI: `lastrites scan` prints the estate summary
(credentials found, copies per credential, blind spots, skips). Fresh
implementation — no code vendored from private repos; fixtures use mock-*
values only.

**AC:**
- [ ] Crontab, plist, and env-file scanners each parse valid fixtures and count+report (not raise, not hide) malformed ones
- [ ] The same mock value planted in a fixture crontab line, a plist EnvironmentVariables block, and an env file clusters to ONE credential with three copied_at edges
- [ ] Entropy screen: low-entropy non-secrets (PATH fragments, words) excluded; test pins both directions
- [ ] Classification test: a CLOUDFLARE_API_TOKEN-named value classifies provider=cloudflare; an unmatchable value classifies unknown, never guessed
- [ ] `lastrites scan` output includes skip counts and named blind spots; exit nonzero on zero-surface scans (a scan that saw nothing must not look like a clean estate)
- [ ] pytest green via `pytest -n auto --dist=worksteal`

**Depends on:** LR1.1
**Model:** claude-opus-5

### Phase 2: canaries and the watch contract

### LR1.3 — Canary engine + provider registry | Cx: 3 | P1

**Description:** `lastrites/canary/`: provider registry mapping provider →
verify spec (endpoint, auth style, success predicate — the cheapest
side-effect-free authenticated call). Ship three concrete providers:
Cloudflare (`GET /client/v4/user/tokens/verify`), GitHub token
(`GET /user`), and a generic bearer/header probe configurable per
credential; plus an ntfy-topic write-probe (the motivating credential
class). Canary execution writes evidence rows (fingerprint, ts, verdict
alive|dead|unobservable, latency, http class — never bodies, never values).
Verdict vocabulary matches the estate doctrine: network failure/timeouts
are UNOBSERVABLE, an authenticated 401/403 is DEAD — the instrument being
blind is never reported as the surface being dead.

**AC:**
- [ ] Provider registry with cloudflare, github, generic-bearer, ntfy-write probes; each spec unit-tested against mocked responses
- [ ] 401/403 → dead; timeout/DNS/5xx → unobservable; 2xx+predicate → alive; the three-way distinction pinned by tests
- [ ] Evidence rows carry no response bodies and no credential values (grep-proof test)
- [ ] `lastrites canary <fingerprint-prefix>` runs one credential's probe and prints the verdict with evidence
- [ ] pytest green via `pytest -n auto --dist=worksteal`

**Depends on:** LR1.1
**Model:** claude-sonnet-5

### LR1.4 — Sweep daemon, heartbeat, escalation | Cx: 3 | P1

**Description:** `lastrites/sweep/`: `lastrites sweep` = scan + canary all
registered credentials + evaluate escalation rules. Heartbeat per
WATCH-TOPOLOGY: written ONLY on a fully completed sweep (capture-based),
JSON with `last_success`, counts, and `invoked_by` read from the
environment contract (scheduler-set env var; absent = interactive) —
STRICT from birth: the heartbeat always carries the field, and downstream
docs say readers must fail closed on its absence. Escalation:
expiry-ledger rules (page at lead-time thresholds before known expiry) and
verdict rules (page on dead, page on N consecutive unobservable) through a
pluggable alert channel (command template — e.g. a curl to a push service —
configured, not hardcoded; no topic literals in the repo). Include the
install-proof doc section: a scheduled sweep is not installed until it has
run under `env -i` semantics.

**AC:**
- [ ] Heartbeat absent after a sweep that failed mid-way; present with invoked_by after a completed sweep (both pinned by tests)
- [ ] invoked_by = scheduler only when the contract env var is set; hand-run sweeps stamp interactive (test)
- [ ] Escalation fires through the configured channel command on: dead verdict, expiry within lead time, N consecutive unobservable; each rule tested with a stubbed channel
- [ ] No alerting endpoint/topic literal anywhere in the repo (grep-proof test); channel comes from config
- [ ] README gains a "running it scheduled" section with the env-contract and install-proof steps
- [ ] pytest green via `pytest -n auto --dist=worksteal`

**Depends on:** LR1.2, LR1.3
**Model:** claude-sonnet-5

### LR1.5 — Contract conformance + CI | Cx: 2 | P2

**Description:** The doctrine-as-tests task. A conformance suite that reads
like the threat model: no-raw-values-persisted (plant mock secrets through
every public API path, grep every artifact file), peppered-fingerprint-only
(no unsalted hash call sites), skip-loudness (every scanner surfaces its
skip count), heartbeat-capture-basis, strict-provenance. GitHub Actions CI:
pytest (sharded), ruff check + format, and a secret-scan step (gitleaks or
equivalent) — the public repo never ships a commit that would have failed
its own doctrine. Badge in README.

**AC:**
- [ ] Conformance suite exists as tests/test_threat_model_conformance.py and every THREAT-MODEL sharp-edge maps to at least one test, referenced by section number
- [ ] CI workflow runs pytest + ruff (check and format) + secret scan on push/PR; all green on this branch
- [ ] README carries the CI badge and links the conformance suite as proof
- [ ] pytest green via `pytest -n auto --dist=worksteal`

**Depends on:** LR1.4
**Model:** claude-haiku-4-5

## Delivery Summary

| Task | Title | Cx | Priority | Model |
|------|-------|----|----------|-------|
| LR1.1 | Fingerprint core + graph store | 3 | P0 | claude-sonnet-5 |
| LR1.2 | Estate scanner + fingerprint clustering | 4 | P0 | claude-opus-5 |
| LR1.3 | Canary engine + provider registry | 3 | P1 | claude-sonnet-5 |
| LR1.4 | Sweep daemon, heartbeat, escalation | 3 | P1 | claude-sonnet-5 |
| LR1.5 | Contract conformance + CI | 2 | P2 | claude-haiku-4-5 |

## Priority Order

1. LR1.1 — everything fingerprints through it
2. LR1.2 — the graph is the product's spine
3. LR1.3 — canaries make the graph live
4. LR1.4 — the daemon ties it into the watch triangle
5. LR1.5 — the doctrine becomes executable
