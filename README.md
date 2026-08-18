# lastrites

**your keys die. someone should be there.**

A local-first watchdog for your credential estate: the API keys, OAuth
tokens, and portal secrets scattered across your machines, crontabs,
plists, env files, and SaaS dashboards. lastrites notices them dying —
ideally before they do — and makes sure their death is never silent.

## The thesis

Nearly every credential outage is a **detection failure**, not a rotation
failure. The token that expired three weeks ago and nobody noticed. The
OAuth refresh that died on a Tuesday and took a pipeline with it. The
cron that has been failing auth since the last laptop migration. Vaults
and secret managers rotate what lives inside their walls — but a real
person's estate mostly lives *outside* the walls, and most of it can't be
rotated by any API at all.

lastrites is honest about that. Three verbs, applied per credential by
what its provider actually allows:

| Verb | What it means | Applies to |
|---|---|---|
| **VERIFY** | a canary call proving the credential authenticates *right now*, producing standing evidence | everything |
| **ESCALATE** | expiry ledger + lead-time paging + a guided re-auth runbook | the unrotatable majority: OAuth refresh tokens, portal-only keys |
| **ROTATE** | two-phase overlap rotation (mint → verify → update consumers → verify → grace → revoke), fail-closed at every step | where APIs exist: AWS IAM, GCP SA keys, Cloudflare tokens, self-managed secrets |

## The credential graph

The piece no vault builds: **which consumers hold a copy of which
credential**. lastrites discovers it rather than asking you to declare it —
scanning your config surfaces (crontabs, launchd plists, env files, CI
secrets) and clustering secrets by *local, peppered fingerprint*: identical
fingerprints across locations are the same credential's copies. The graph
is what makes rotation safe (you can't atomically update consumers you
don't know about) and what makes escalation useful (blast radius *before*
you re-auth). Design: [docs/DESIGN-credential-graph.md](docs/DESIGN-credential-graph.md).

## The watcher is watched

A rotator that dies silently is worse than no rotator. lastrites is built
to run under a dead-man triangle: its heartbeats are **capture-based**
(stamped only on verified-working evidence, never on "the process ran")
and **provenance-stamped** (a hand-run check cannot impersonate the
scheduler). It pairs with [deadman](https://github.com/fivedollarfridays/deadman)-style
external watching so the failure of lastrites itself pages you the same
way a dying key does.

## Status

Design phase. Detection and escalation ship first — a read-only canary
daemon cannot hurt the estate it watches. Rotation lands after the
detection layer has survived its author's own credentials for a while.

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md) — read it before trusting
this with anything. Claims in these docs follow an evidence discipline:
if a doc says "verified," it names what was run and when.

## License

MIT.
