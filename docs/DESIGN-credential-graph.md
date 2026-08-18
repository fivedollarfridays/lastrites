# Design: the credential graph

Status: design, pre-implementation. This is the load-bearing novelty of
lastrites — the artifact no vault builds — so it gets specified before any
code exists.

## The problem it solves

Secret managers rotate secrets that live inside them, for consumers that
fetch from them. A real estate's credentials live in crontab lines, launchd
plists, `.env` files across a dozen repos, CI secret stores, a phone, a
second machine, and six SaaS dashboards. Rotation is only safe if every
consumer of a credential is updated atomically — **and no registry of those
consumers exists anywhere**, because nobody maintains registries. The graph
replaces declaration with discovery.

## The model

Four node types, three edge types:

```
Provider   —issues→        Credential
Credential —copied-at→     Consumer      (location, format, machine)
Canary     —verifies→      Credential
```

**Credential** — identity is a *fingerprint* (see below), never a value.
Carries: provider, kind (`api-key` | `oauth-refresh` | `token` | `password`),
rotation class (`rotatable` | `refreshable` | `portal-only`), expiry when
knowable, last-verified evidence.

**Consumer** — a place a copy lives and the thing that reads it: a crontab
line's env assignment, a plist `EnvironmentVariables` block, an env-file
key, a CI secret name, a remote host's file. Carries: machine, path/locator,
format (how to rewrite it), and the job(s) that read it when derivable.

**Provider** — the issuing service and its capabilities: verify endpoint
(the canary call), rotation API if any, expiry semantics.

**Canary** — the standing probe definition: the cheapest authenticated call
that proves liveness without side effects, its cadence, and its evidence
history.

## Discovery: fingerprint clustering

The trick that makes the graph buildable without a registry:

1. **Scan** the estate's config surfaces. The scanner lineage is a
   scheduled-jobs auditor: enumerate crontabs, launchd/systemd units, env
   files, CI configs; parse them tolerantly; count and surface every skip
   (a silently skipped surface is a false "no copies here").
2. **Extract candidate secrets** per surface with format-aware heuristics
   (assignment parsing, key-name hints, entropy screening — tuned to
   over-collect; classification happens later).
3. **Fingerprint locally**: `HMAC(pepper, canonicalized_value)`. The pepper
   is machine-local, stored outside the graph. Values are discarded the
   moment the fingerprint is computed. (Why HMAC and not SHA: a bare hash
   of a low-entropy secret is a polite dictionary attack. See THREAT-MODEL
   §2.)
4. **Cluster**: identical fingerprints across surfaces are, by definition,
   copies of the same credential. Each cluster becomes a Credential node;
   each member becomes a copied-at edge. This is what finds the copy you
   forgot — the old path, the second machine, the CI secret set two years
   ago.
5. **Attach provider/kind** by classification (key-name patterns, value
   shape, the consumer's own context — a `CLOUDFLARE_API_TOKEN=` name is
   its own documentation), falling back to `unknown` honestly rather than
   guessing.

Cross-machine: each machine scans and fingerprints with a shared pepper
(distributed once, out of band), shipping only fingerprints + locations to
the graph holder. Values never cross a wire.

## The graph is capture-based evidence, like everything else

A stale graph is the meta-failure: rotation walking last month's consumer
list is exactly the half-completed-rotation hazard. So the graph itself
carries freshness evidence — each surface's last successful scan is
stamped (provenance-stamped, scheduler vs hand-run), and the external
dead-man layer watches graph freshness as a first-class surface. An
unscannable surface degrades to a named blind spot on the graph, never to
silence.

## What the graph enables

**Safe rotation** — the two-phase walk: mint new → canary new → rewrite
every copied-at edge with its format-aware writer → re-verify each
consumer (job-level canary where the job exposes one) → grace window →
revoke old. Any failure at any edge: halt, both keys valid, page with the
exact edge that failed. The walk cannot be safer than the graph is fresh —
which is why freshness is watched.

**Blast-radius-aware escalation** — for the unrotatable majority, the
page isn't "your token is dying," it's "this token feeds these 3 jobs on
these 2 machines; here's the re-auth runbook and everything that breaks
Tuesday if you skip it." Prioritization falls out of the graph for free.

**Estate drift detection** — a new fingerprint appearing in a scan is a
new secret someone (you, an agent, an installer) introduced; a fingerprint
vanishing from a location is a copy removed. Both are ledger events worth
seeing.

## Open problems (named, not hidden)

1. **Invisible values**: OS keychains, compiled binaries, secrets injected
   at runtime by other managers. Coverage boundaries are declared per
   surface class; the graph reports what fraction of known consumers were
   scannable.
2. **Transformed copies**: base64-wrapped, URL-embedded
   (`https://user:TOKEN@host/`), or derived values defeat naive
   canonicalization. Canonicalizers are per-format and grow by casework;
   unmatched transforms are an accepted false-negative class, documented.
3. **Structured secrets** (JSON service-account files): fingerprint both
   the file and the inner key material, else a re-serialized copy looks
   like a different credential.
4. **Scanner privilege**: the scanner reads everything interesting on the
   machine; it must run local-only, unprivileged where possible, with its
   own canary proving it still runs (a dead scanner = a silently staling
   graph).

## Seed heuristic honesty

The scan/parse layer descends from a production scheduled-jobs auditor
(crontab + launchd parsing with dead-path and hygiene findings) that runs
weekly on the author's own estate. The graph extends that parser's job —
"what runs" — with "what secrets what-runs carries." It inherits that
lineage's rules: parse tolerantly, count skips loudly, and treat the
machine actually being scanned as the only source of truth.
